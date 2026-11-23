//
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth2lib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"cloud.google.com/go/auth"
)

const (
	// defaultLifetime is the impersonated token lifetime when
	// ImpersonationConfig.Lifetime is 0, as in google-auth
	// (_DEFAULT_TOKEN_LIFETIME_SECS).
	defaultLifetime = time.Hour
	// maxLifetime is the longest lifetime IAM can grant (with the
	// constraints/iam.allowServiceAccountCredentialLifetimeExtension policy).
	maxLifetime = 12 * time.Hour
	// cloudPlatformScope is the scope google-auth gives a service account
	// source of impersonated credentials (iam._IAM_SCOPE).
	cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
)

// ImpersonationConfig describes service account impersonation. The caller
// (for example Go gcloud) resolves every field.
type ImpersonationConfig struct {
	// Source provides the token that calls IAM. Its Token method is called
	// once for every Token call on the impersonated credentials, so it
	// should be uncached (for example from BuildCredentials) when the caller
	// wants a fresh source token each time.
	Source *auth.Credentials
	// Target is the email or unique ID of the service account to
	// impersonate.
	Target string
	// Delegates is the delegation chain: service account emails, unique IDs
	// or projects/-/serviceAccounts/ resource names, sent to IAM with
	// surrounding spaces trimmed. Each delegate needs the Service Account
	// Token Creator role on the next one, and the last one on Target.
	Delegates []string
	// Scopes are the scopes of the impersonated token. Surrounding spaces
	// are trimmed and empty entries dropped, as for Config.Scopes; at least
	// one must remain, and a scope with a space inside it is an error. Go
	// gcloud passes gcloud's default scopes.
	Scopes []string
	// Lifetime is the impersonated token's lifetime, in whole seconds. 0
	// means 1 hour; the maximum is 12 hours.
	Lifetime time.Duration
	// Endpoint is the IAM Credentials API base URL, such as
	// https://iamcredentials.googleapis.com/ or a regional or mTLS
	// endpoint. The request goes to
	// <Endpoint>v1/projects/-/serviceAccounts/<Target>:generateAccessToken.
	// If empty, the host is chosen as in Python gcloud (an explicit
	// api_endpoint_overrides/iamcredentials is what Go gcloud passes here):
	// https://iamcredentials.<UniverseDomain>/ when UniverseDomain is set
	// and not googleapis.com, else https://iamcredentials.<Source's
	// universe>/, else https://iamcredentials.googleapis.com/.
	Endpoint string
	// UniverseDomain is the caller's configured universe (Go gcloud passes
	// core/universe_domain). When Endpoint is empty and UniverseDomain is set
	// to something other than googleapis.com, IAM is called at
	// https://iamcredentials.<UniverseDomain>/, as Python gcloud's
	// GetEffectiveIamEndpoint does. It never changes the credentials'
	// reported universe, which is always Source's, as in google-auth, and a
	// value that differs from Source's is not an error. Leading and trailing
	// spaces are ignored.
	UniverseDomain string
	// Client is used for every IAM call. It must not add its own
	// Authorization header.
	Client *http.Client
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger
}

// String describes c without calling Source.
func (c ImpersonationConfig) String() string {
	return fmt.Sprintf("oauth2lib.ImpersonationConfig{Target:%q Delegates:%q Scopes:%q Lifetime:%v Endpoint:%q UniverseDomain:%q}",
		c.Target, c.Delegates, c.Scopes, c.Lifetime, c.Endpoint, c.UniverseDomain)
}

// GoString makes %#v print the same as String.
func (c ImpersonationConfig) GoString() string { return c.String() }

// LogValue implements slog.LogValuer.
func (c ImpersonationConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("target", c.Target),
		slog.Any("delegates", c.Delegates),
		slog.Any("scopes", c.Scopes),
		slog.Duration("lifetime", c.Lifetime),
		slog.String("endpoint", c.Endpoint),
		slog.String("universe_domain", c.UniverseDomain),
	)
}

// Impersonate returns credentials for cfg.Target.
//
// The returned credentials' TokenProvider is not cached: each Token call gets
// a token from cfg.Source and then sends one IAM generateAccessToken request
// through cfg.Client. An error from cfg.Source is returned unchanged; an IAM
// failure is a *RefreshError whose Code is the google.rpc.Status status (for
// example PERMISSION_DENIED); a done ctx returns its error.
//
// Impersonate reads no files, environment variables or gcloud properties.
// It makes no network calls of its own; it asks cfg.Source for its universe
// domain, which is static for credentials from BuildCredentials. cfg is
// copied, so changing it afterwards does not affect the credentials. As with
// BuildCredentials, no quota project is set.
func Impersonate(ctx context.Context, cfg *ImpersonationConfig) (*auth.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := newImpersonatedTokenProvider(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return p.credentials(ctx, nil, cfg.Logger), nil
}

// impersonatedTokenProvider calls IAM generateAccessToken with a token from
// source. It holds no tokens, so it is safe for concurrent use.
type impersonatedTokenProvider struct {
	source         *auth.Credentials
	client         *http.Client
	url            string // the full generateAccessToken URL
	body           []byte // the JSON request body, the same on every call
	universeDomain string
}

var _ auth.TokenProvider = (*impersonatedTokenProvider)(nil)

// generateAccessTokenRequest is the IAM request body. Its fields are in the
// same order as google-auth's, and an empty Delegates is sent as null, as
// google-auth does when no delegates are given.
type generateAccessTokenRequest struct {
	Delegates []string `json:"delegates"`
	Scope     []string `json:"scope"`
	Lifetime  string   `json:"lifetime"`
}

func newImpersonatedTokenProvider(ctx context.Context, cfg *ImpersonationConfig) (*impersonatedTokenProvider, error) {
	if cfg == nil {
		return nil, errors.New("oauth2lib: ImpersonationConfig is nil")
	}
	if cfg.Client == nil {
		return nil, errors.New("oauth2lib: ImpersonationConfig.Client is nil")
	}
	if cfg.Source == nil {
		return nil, errors.New("oauth2lib: ImpersonationConfig.Source is nil")
	}
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("oauth2lib: ImpersonationConfig.Target is empty")
	}
	if strings.ContainsAny(target, "/:?#") || strings.ContainsFunc(target, unicode.IsSpace) {
		return nil, fmt.Errorf("oauth2lib: ImpersonationConfig.Target %q is not a service account email or unique ID", target)
	}
	// Delegates are trimmed before they are checked, so the request carries
	// exactly what was validated. Resource names (with "/") are allowed,
	// since IAM accepts them.
	var delegates []string
	for _, d := range cfg.Delegates {
		d = strings.TrimSpace(d)
		if d == "" {
			return nil, errors.New("oauth2lib: ImpersonationConfig.Delegates has an empty delegate")
		}
		if strings.ContainsFunc(d, unicode.IsSpace) {
			return nil, fmt.Errorf("oauth2lib: ImpersonationConfig.Delegates has a delegate with spaces in it: %q", d)
		}
		delegates = append(delegates, d)
	}
	// The same rules as Config.Scopes (validateConfig): trim, drop empty
	// entries, and reject inner spaces. cleanScopes returns a new slice.
	scopes := cleanScopes(cfg.Scopes)
	if len(scopes) == 0 {
		return nil, errors.New("oauth2lib: ImpersonationConfig.Scopes is empty")
	}
	for _, s := range scopes {
		if strings.ContainsFunc(s, unicode.IsSpace) {
			return nil, fmt.Errorf("oauth2lib: ImpersonationConfig.Scopes has a scope with spaces in it: %q", s)
		}
	}
	lifetime := cfg.Lifetime
	if lifetime == 0 {
		lifetime = defaultLifetime
	}
	if lifetime < time.Second || lifetime > maxLifetime || lifetime%time.Second != 0 {
		return nil, fmt.Errorf("oauth2lib: ImpersonationConfig.Lifetime is %v; it must be whole seconds between 1s and %v", cfg.Lifetime, maxLifetime)
	}

	universe, err := cfg.Source.UniverseDomain(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: getting the source credentials' universe domain: %w", err)
	}
	// The credentials report Source's universe (trimmed, googleapis.com if
	// empty), as in google-auth. There is no JSON here, so Source's universe
	// takes resolveUniverseDomain's first slot.
	universe = resolveUniverseDomain(universe, "")

	// The IAM host follows Python gcloud: the endpoint override, then a
	// non-default configured universe (GetEffectiveIamEndpoint), then
	// Source's universe (google-auth's _make_iam_token_request), then
	// googleapis.com (already folded into universe above).
	endpoint := cfg.Endpoint
	if endpoint == "" {
		iamUniverse := universe
		if u := strings.TrimSpace(cfg.UniverseDomain); u != "" && u != defaultUniverseDomain {
			iamUniverse = u
		}
		endpoint = "https://iamcredentials." + iamUniverse + "/"
	}
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}

	body, err := json.Marshal(generateAccessTokenRequest{
		Delegates: delegates,
		Scope:     scopes,
		Lifetime:  fmt.Sprintf("%ds", int64(lifetime/time.Second)),
	})
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: encoding the IAM request: %w", err)
	}
	return &impersonatedTokenProvider{
		source:         cfg.Source,
		client:         cfg.Client,
		url:            endpoint + "v1/projects/-/serviceAccounts/" + url.PathEscape(target) + ":generateAccessToken",
		body:           body,
		universeDomain: universe,
	}, nil
}

// validateEndpoint rejects IAM endpoints that could never be sent, so that a
// bad endpoint fails when the credentials are built rather than on the first
// Token call. The URL is not included in the error.
func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("oauth2lib: IAM endpoint must be an absolute http or https URL without a query or fragment")
	}
	return nil
}

// credentials wraps p in auth.Credentials. jsonData is what the credentials'
// JSON method returns.
func (p *impersonatedTokenProvider) credentials(ctx context.Context, jsonData []byte, logger *slog.Logger) *auth.Credentials {
	if logger == nil {
		logger = discardLogger
	}
	logger.DebugContext(ctx, "oauth2lib: built impersonated credentials",
		slog.String("universe_domain", p.universeDomain))
	universe := p.universeDomain
	return auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider: p,
		JSON:          jsonData,
		UniverseDomainProvider: auth.CredentialsPropertyFunc(func(context.Context) (string, error) {
			return universe, nil
		}),
	})
}

// generateAccessTokenResponse is a successful IAM response.
type generateAccessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// Token gets a new source token and exchanges it for an impersonated access
// token. It never returns a cached token.
func (p *impersonatedTokenProvider) Token(ctx context.Context) (*auth.Token, error) {
	src, err := p.source.Token(ctx)
	if err != nil {
		return nil, err
	}
	if src == nil || src.Value == "" {
		return nil, &RefreshError{Kind: KindUnknown, Description: "source credentials returned an empty token"}
	}
	srcType := src.Type
	if srcType == "" {
		srcType = "Bearer"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(p.body))
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: building the IAM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", srcType+" "+src.Value)

	status, body, err := doRequest(ctx, p.client, req)
	if err != nil {
		return nil, err
	}
	var resp generateAccessTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "IAM response is not valid JSON"}
	}
	if resp.AccessToken == "" {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "IAM response has no accessToken"}
	}
	expiry, err := time.Parse(time.RFC3339, resp.ExpireTime)
	if err != nil {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "IAM response has an invalid expireTime"}
	}
	return &auth.Token{
		Value:    resp.AccessToken,
		Type:     "Bearer",
		Expiry:   expiry,
		Metadata: map[string]any{},
	}, nil
}

// impersonatedServiceAccountJSON is the impersonated_service_account
// credential file.
type impersonatedServiceAccountJSON struct {
	Type                           string          `json:"type"`
	ServiceAccountImpersonationURL string          `json:"service_account_impersonation_url"`
	SourceCredentials              json.RawMessage `json:"source_credentials"`
	Delegates                      []string        `json:"delegates"`
	Scopes                         []string        `json:"scopes"`
}

// ParseImpersonatedServiceAccountJSON splits impersonated_service_account
// JSON into its source_credentials JSON and a base ImpersonationConfig with
// Target, Delegates and Scopes set. Like google-auth, it reads only the
// target from service_account_impersonation_url, so Endpoint stays empty.
//
// The source must be authorized_user or service_account JSON; other source
// types, including nested impersonated_service_account, are rejected, as in
// google-auth (external_account_authorized_user sources are not supported
// yet). Callers that cache the source credential can build it from
// sourceJSON, apply their own overrides to base, set Source, Client and the
// other fields, and call Impersonate.
func ParseImpersonatedServiceAccountJSON(b []byte) (sourceJSON []byte, base *ImpersonationConfig, err error) {
	// The JSON holds secrets, so the parse error (which can quote it) is
	// not wrapped. As in validateConfig, parse b itself rather than the
	// trimmed bytes: bytes.TrimSpace also strips Unicode spaces (such as
	// U+00A0) that encoding/json rejects. Requiring '{' also rejects null,
	// arrays and strings.
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil, errors.New("oauth2lib: impersonated_service_account JSON is not a valid JSON object")
	}
	var f impersonatedServiceAccountJSON
	if err := json.Unmarshal(b, &f); err != nil {
		// A field with the wrong JSON type: name the field, never its value.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return nil, nil, fmt.Errorf("oauth2lib: impersonated_service_account JSON field %q has the wrong type", typeErr.Field)
		}
		return nil, nil, errors.New("oauth2lib: impersonated_service_account JSON is not a valid JSON object")
	}
	if f.Type != "impersonated_service_account" {
		return nil, nil, fmt.Errorf("oauth2lib: credential type is %q, want impersonated_service_account", f.Type)
	}
	target, err := targetFromImpersonationURL(f.ServiceAccountImpersonationURL)
	if err != nil {
		return nil, nil, err
	}
	src := bytes.TrimSpace(f.SourceCredentials)
	if len(src) == 0 || bytes.Equal(src, []byte("null")) {
		return nil, nil, errors.New(`oauth2lib: impersonated_service_account JSON has no "source_credentials"`)
	}
	var st credentialType
	if json.Unmarshal(src, &st) != nil {
		return nil, nil, errors.New(`oauth2lib: impersonated_service_account "source_credentials" is not a JSON object`)
	}
	switch st.Type {
	case "authorized_user", "service_account":
	case "":
		return nil, nil, errors.New(`oauth2lib: impersonated_service_account "source_credentials" has no "type"`)
	default:
		return nil, nil, fmt.Errorf("oauth2lib: impersonated_service_account source credentials of type %q are not supported", st.Type)
	}
	return bytes.Clone(src), &ImpersonationConfig{
		Target:    target,
		Delegates: f.Delegates,
		Scopes:    cleanScopes(f.Scopes),
	}, nil
}

// targetFromImpersonationURL returns the service account between the last
// "/" and ":generateAccessToken", as google-auth does.
func targetFromImpersonationURL(u string) (string, error) {
	start := strings.LastIndex(u, "/")
	end := strings.Index(u, ":generateAccessToken")
	if start == -1 || end == -1 || start > end || start+1 == end {
		return "", errors.New(`oauth2lib: cannot read the target service account from "service_account_impersonation_url"`)
	}
	return u[start+1 : end], nil
}

// buildImpersonatedFromJSON builds credentials for impersonated_service_account
// JSON for BuildCredentials. The source keeps its own token_uri and gets
// Config's RAPT, UseSelfSignedJWT, UniverseDomain, Client and Logger. As in
// google-auth, a service_account source gets the cloud-platform scope and an
// authorized_user source keeps its own scopes. The impersonated token gets
// Config.Scopes, or the JSON's scopes if Config.Scopes is empty.
func buildImpersonatedFromJSON(ctx context.Context, c *Config) (*auth.Credentials, string, error) {
	sourceJSON, base, err := ParseImpersonatedServiceAccountJSON(c.JSON)
	if err != nil {
		return nil, "", err
	}
	var st credentialType
	_ = json.Unmarshal(sourceJSON, &st) // checked by ParseImpersonatedServiceAccountJSON
	srcCfg := &Config{
		JSON:             sourceJSON,
		UniverseDomain:   c.UniverseDomain,
		Client:           c.Client,
		RAPT:             c.RAPT,
		UseSelfSignedJWT: c.UseSelfSignedJWT,
		Logger:           c.Logger,
	}
	if st.Type == "service_account" {
		srcCfg.Scopes = []string{cloudPlatformScope}
	}
	source, err := BuildCredentials(ctx, srcCfg)
	if err != nil {
		return nil, "", fmt.Errorf("oauth2lib: impersonated_service_account source credentials: %w", err)
	}
	base.Source = source
	base.UniverseDomain = c.UniverseDomain
	base.Client = c.Client
	base.Logger = c.Logger
	if len(c.Scopes) > 0 {
		base.Scopes = c.Scopes
	}
	if len(base.Scopes) == 0 {
		return nil, "", errors.New("oauth2lib: impersonated_service_account credentials need Config.Scopes or \"scopes\" in the JSON")
	}
	p, err := newImpersonatedTokenProvider(ctx, base)
	if err != nil {
		return nil, "", err
	}
	return p.credentials(ctx, c.JSON, discardLogger), p.universeDomain, nil
}
