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
)

// IAMScope is the scope google-auth gives a service account source of
// impersonated credentials (google/auth/iam.py _IAM_SCOPE), which Python
// gcloud uses for both flag/property and file impersonation. BuildCredentials
// gives it to a service_account source in impersonated_service_account JSON;
// callers that build the source themselves should do the same. go/auth uses
// cloud-platform here instead, and IAM accepts either scope.
const IAMScope = "https://www.googleapis.com/auth/iam"

// ImpersonationConfig describes service account impersonation. The caller
// (for example Go gcloud) resolves every field.
type ImpersonationConfig struct {
	// Source provides the token that calls IAM. Its Token method is called
	// once for every Token call on the impersonated credentials, so it
	// should be uncached (for example from BuildCredentials) when the caller
	// wants a fresh source token each time. Source is used as given: Python
	// gcloud gives a service account source IAMScope for the IAM call, and
	// any scope that allows calling IAM, such as cloud-platform, also works.
	// The credentials report Source's universe domain, as in google-auth.
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
	// If empty, IAM is called at https://iamcredentials.<Source's universe>/,
	// as google-auth does. Go gcloud passes the result of Python gcloud's
	// GetEffectiveIamEndpoint here (api_endpoint_overrides/iamcredentials, or
	// iamcredentials.<core/universe_domain> when that is not googleapis.com).
	Endpoint string
	// Client is used for every IAM call. It must not add its own
	// Authorization header.
	Client *http.Client
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger
}

// String describes c without calling Source.
func (c ImpersonationConfig) String() string {
	return fmt.Sprintf("oauth2lib.ImpersonationConfig{Target:%q Delegates:%q Scopes:%q Lifetime:%v Endpoint:%q}",
		c.Target, c.Delegates, c.Scopes, c.Lifetime, c.Endpoint)
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
// same order as google-auth's. An empty Delegates is sent as null, as
// google-auth does for gcloud's --impersonate-service-account without
// delegates; IAM treats null and [] the same.
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
	if !isServiceAccountID(target) {
		return nil, fmt.Errorf("oauth2lib: ImpersonationConfig.Target %q is not a service account email or unique ID", target)
	}
	delegates, err := cleanDelegates(cfg.Delegates, "ImpersonationConfig.Delegates")
	if err != nil {
		return nil, err
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

	// As in google-auth: the endpoint override, else Source's universe
	// (already googleapis.com when Source reports none).
	endpoint := cfg.Endpoint
	if endpoint == "" {
		// The universe becomes part of a host name; reject anything that
		// would change the host, port or path (for example "x@attacker").
		if strings.ContainsAny(universe, "/:@\\?#") || strings.ContainsFunc(universe, unicode.IsSpace) {
			return nil, errors.New("oauth2lib: universe domain is not a valid domain name for the IAM endpoint")
		}
		endpoint = "https://iamcredentials." + universe + "/"
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
	// Check for '?' and '#' in the string itself: url.Parse leaves RawQuery
	// and Fragment empty for a bare trailing "?" or "#", and the IAM path is
	// appended to the endpoint as a string.
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil ||
		strings.ContainsAny(endpoint, "?#") || strings.ContainsFunc(endpoint, unicode.IsSpace) {
		return errors.New("oauth2lib: IAM endpoint must be an absolute http or https URL with a host name and without user info, spaces, a query or a fragment")
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
		return nil, &RefreshError{Kind: KindUnknown, Err: fmt.Errorf("building the IAM request: %w", err)}
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
	// A zero Expiry means "never expires" to auth.Token.IsValid, so reject
	// it, as serviceaccount.go does for expires_in 0.
	if err != nil || expiry.IsZero() {
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
	UniverseDomain                 string          `json:"universe_domain"`
}

// ImpersonatedServiceAccount is a parsed impersonated_service_account
// credential file.
type ImpersonatedServiceAccount struct {
	// SourceJSON is the source_credentials JSON, an authorized_user or
	// service_account credential file. It holds secrets.
	SourceJSON []byte
	// SourceType is the source's "type": "authorized_user" or
	// "service_account". A service_account source needs IAMScope.
	SourceType string
	// Target is the service account to impersonate, read from
	// service_account_impersonation_url as google-auth does.
	Target string
	// Delegates are the file's delegates, trimmed and checked like
	// ImpersonationConfig.Delegates.
	Delegates []string
	// Scopes are the file's scopes, trimmed with empty entries dropped and
	// checked like ImpersonationConfig.Scopes.
	Scopes []string
	// UniverseDomain is the file's top-level universe_domain, trimmed. Files
	// written by gcloud and google-auth have none.
	UniverseDomain string

	// sourceUniverseDomain is the source's own universe_domain, trimmed.
	sourceUniverseDomain string
}

// String describes a without the contents of SourceJSON, which holds secrets.
func (a ImpersonatedServiceAccount) String() string {
	return fmt.Sprintf("oauth2lib.ImpersonatedServiceAccount{SourceType:%q Target:%q Delegates:%q Scopes:%q UniverseDomain:%q SourceJSON:[REDACTED %d bytes]}",
		a.SourceType, a.Target, a.Delegates, a.Scopes, a.UniverseDomain, len(a.SourceJSON))
}

// GoString makes %#v print the same as String, so it does not dump SourceJSON.
func (a ImpersonatedServiceAccount) GoString() string { return a.String() }

// LogValue implements slog.LogValuer without the contents of SourceJSON.
func (a ImpersonatedServiceAccount) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("source_type", a.SourceType),
		slog.String("target", a.Target),
		slog.Any("delegates", a.Delegates),
		slog.Any("scopes", a.Scopes),
		slog.String("universe_domain", a.UniverseDomain),
		slog.Int("source_json_bytes", len(a.SourceJSON)),
	)
}

// ParseImpersonatedServiceAccountJSON parses impersonated_service_account
// JSON. Like google-auth, it reads only the target from
// service_account_impersonation_url; the IAM host comes from the source's
// universe or ImpersonationConfig.Endpoint.
//
// The source must be authorized_user or service_account JSON; other source
// types, including nested impersonated_service_account, are rejected, as in
// google-auth (external_account_authorized_user sources are not supported
// yet). BuildCredentials uses it for impersonated_service_account JSON.
// Callers that cache the source credential, or need source options that
// BuildCredentials does not apply (such as RAPT or TokenURL), build the
// source from SourceJSON with BuildCredentials and their own Config (adding
// IAMScope for a service_account source), and call Impersonate with Target,
// Delegates, Scopes and their own overrides.
func ParseImpersonatedServiceAccountJSON(b []byte) (*ImpersonatedServiceAccount, error) {
	// The JSON holds secrets, so the parse error (which can quote it) is
	// not wrapped. As in validateConfig, parse b itself rather than the
	// trimmed bytes: bytes.TrimSpace also strips Unicode spaces (such as
	// U+00A0) that encoding/json rejects. Requiring '{' also rejects null,
	// arrays and strings.
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("oauth2lib: impersonated_service_account JSON is not a valid JSON object")
	}
	var f impersonatedServiceAccountJSON
	if err := json.Unmarshal(b, &f); err != nil {
		// A field with the wrong JSON type: name the field, never its value.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return nil, fmt.Errorf("oauth2lib: impersonated_service_account JSON field %q has the wrong type", typeErr.Field)
		}
		return nil, errors.New("oauth2lib: impersonated_service_account JSON is not a valid JSON object")
	}
	if f.Type != "impersonated_service_account" {
		return nil, fmt.Errorf("oauth2lib: credential type is %q, want impersonated_service_account", f.Type)
	}
	target, err := targetFromImpersonationURL(f.ServiceAccountImpersonationURL)
	if err != nil {
		return nil, err
	}
	delegates, err := cleanDelegates(f.Delegates, `impersonated_service_account "delegates"`)
	if err != nil {
		return nil, err
	}
	scopes := cleanScopes(f.Scopes)
	for _, s := range scopes {
		if strings.ContainsFunc(s, unicode.IsSpace) {
			return nil, fmt.Errorf(`oauth2lib: impersonated_service_account "scopes" has a scope with spaces in it: %q`, s)
		}
	}
	src := bytes.TrimSpace(f.SourceCredentials)
	if len(src) == 0 || bytes.Equal(src, []byte("null")) {
		return nil, errors.New(`oauth2lib: impersonated_service_account JSON has no "source_credentials"`)
	}
	if src[0] != '{' {
		return nil, errors.New(`oauth2lib: impersonated_service_account "source_credentials" is not a JSON object`)
	}
	var st credentialType
	if err := json.Unmarshal(src, &st); err != nil {
		// A "type" or "universe_domain" that isn't a string: name the field,
		// never its value.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return nil, fmt.Errorf(`oauth2lib: impersonated_service_account "source_credentials" field %q must be a string`, typeErr.Field)
		}
		return nil, errors.New(`oauth2lib: impersonated_service_account "source_credentials" is not a JSON object`)
	}
	switch st.Type {
	case "authorized_user", "service_account":
	case "":
		return nil, errors.New(`oauth2lib: impersonated_service_account "source_credentials" has no "type"`)
	default:
		return nil, fmt.Errorf("oauth2lib: impersonated_service_account source credentials of type %q are not supported", st.Type)
	}
	return &ImpersonatedServiceAccount{
		SourceJSON:           bytes.Clone(src),
		SourceType:           st.Type,
		Target:               target,
		Delegates:            delegates,
		Scopes:               scopes,
		UniverseDomain:       strings.TrimSpace(f.UniverseDomain),
		sourceUniverseDomain: strings.TrimSpace(st.UniverseDomain),
	}, nil
}

// cleanDelegates trims each delegate and rejects empty ones and ones with
// spaces inside, naming field in the error. Resource names (with "/") are
// allowed, since IAM accepts them. It returns a new slice (nil when there
// are no delegates), so the request carries exactly what was checked.
func cleanDelegates(ds []string, field string) ([]string, error) {
	var out []string
	for _, d := range ds {
		d = strings.TrimSpace(d)
		if d == "" {
			return nil, fmt.Errorf("oauth2lib: %s has an empty delegate", field)
		}
		if strings.ContainsFunc(d, unicode.IsSpace) {
			return nil, fmt.Errorf("oauth2lib: %s has a delegate with spaces in it: %q", field, d)
		}
		out = append(out, d)
	}
	return out, nil
}

// targetFromImpersonationURL returns the service account between the last
// "/" and ":generateAccessToken", as google-auth does, percent-decoded:
// Impersonate escapes it again, so a "%40" in the URL reaches IAM as "%40"
// (google-auth sends the extracted text as is). The decoded target must pass
// the same check as ImpersonationConfig.Target, so an encoded "/" or "?" is
// rejected here and a bad URL is reported as such.
func targetFromImpersonationURL(u string) (string, error) {
	start := strings.LastIndex(u, "/")
	end := strings.Index(u, ":generateAccessToken")
	if start == -1 || end == -1 || start > end {
		return "", errors.New(`oauth2lib: cannot read the target service account from "service_account_impersonation_url"`)
	}
	target, err := url.PathUnescape(u[start+1 : end])
	if err != nil || !isServiceAccountID(target) {
		return "", errors.New(`oauth2lib: cannot read the target service account from "service_account_impersonation_url"`)
	}
	return target, nil
}

// isServiceAccountID reports whether s can be a service account email or
// unique ID in an IAM resource name: non-empty, with no "/", ":", "?", "#"
// or spaces.
func isServiceAccountID(s string) bool {
	return s != "" && !strings.ContainsAny(s, "/:?#") && !strings.ContainsFunc(s, unicode.IsSpace)
}

// buildImpersonatedFromJSON returns the token provider for
// impersonated_service_account JSON, for BuildCredentials. As in google-auth,
// the source is built from its own JSON: it keeps its token_uri and gets only
// Config's Client and Logger (not TokenURL, RAPT or UseSelfSignedJWT, as in
// Python gcloud). A source without universe_domain gets the file's
// top-level universe_domain, else Config.UniverseDomain (the same JSON, then
// Config, then googleapis.com order as the other types). A service_account
// source gets IAMScope and an authorized_user source keeps its own scopes.
// The impersonated token gets Config.Scopes, or the JSON's scopes if
// Config.Scopes is empty, and IAM is called in the source's universe.
func buildImpersonatedFromJSON(ctx context.Context, c *Config) (*impersonatedTokenProvider, error) {
	f, err := ParseImpersonatedServiceAccountJSON(c.JSON)
	if err != nil {
		return nil, err
	}
	srcCfg := &Config{
		JSON:   f.SourceJSON,
		Client: c.Client,
		Logger: c.Logger,
	}
	// Only a source without its own universe_domain gets the fallback, so a
	// source that says googleapis.com keeps it (and doesn't self-sign).
	if f.sourceUniverseDomain == "" {
		srcCfg.UniverseDomain = f.UniverseDomain
		if srcCfg.UniverseDomain == "" {
			srcCfg.UniverseDomain = c.UniverseDomain
		}
	}
	if f.SourceType == "service_account" {
		srcCfg.Scopes = []string{IAMScope}
	}
	source, err := BuildCredentials(ctx, srcCfg)
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: impersonated_service_account source credentials: %w", err)
	}
	base := &ImpersonationConfig{
		Source:    source,
		Target:    f.Target,
		Delegates: f.Delegates,
		Scopes:    f.Scopes,
		Client:    c.Client,
	}
	if len(c.Scopes) > 0 {
		base.Scopes = c.Scopes
	}
	if len(base.Scopes) == 0 {
		return nil, errors.New("oauth2lib: impersonated_service_account credentials need Config.Scopes or \"scopes\" in the JSON")
	}
	p, err := newImpersonatedTokenProvider(ctx, base)
	if err != nil {
		// The fields come from the JSON (or Config.Scopes), not from an
		// ImpersonationConfig the caller set, so say where they came from.
		return nil, fmt.Errorf("oauth2lib: impersonated_service_account JSON: %w", err)
	}
	return p, nil
}
