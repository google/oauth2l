//
// Copyright 2021 Google Inc.
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
package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/auth/oauth2adapt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// defaultAuthState is the 3LO "state" value used when Settings.State is empty.
const defaultAuthState = "state"

const (
	authorizedUserCredentialsType = "authorized_user"
	serviceAccountCredentialsType = "service_account"
)

// credentialsFileHeader holds the fields of a credentials JSON file that are
// needed to configure credentials.DetectOptions.
type credentialsFileHeader struct {
	Type         string `json:"type"`
	TokenURI     string `json:"token_uri"`
	RefreshToken string `json:"refresh_token"`
}

func parseCredentialsFileHeader(b []byte) credentialsFileHeader {
	var h credentialsFileHeader
	if len(b) > 0 {
		// Errors are ignored here; credentials.DetectDefault reports
		// malformed JSON with a descriptive error.
		_ = json.Unmarshal(b, &h)
	}
	return h
}

// newDetectOptions builds credentials.DetectOptions from settings.
//
// An *http.Client stored in ctx under oauth2.HTTPClient is used for token
// requests, as golang.org/x/oauth2/google did.
//
// cloud.google.com/go/auth rejects options that set both Scopes and
// Audience, so Audience is only used for self-signed JWTs (where it takes
// precedence over Scope); OAuth flows only use Scope. This lets callers keep
// setting both fields (e.g. for STS token exchange) as before.
func newDetectOptions(ctx context.Context, settings *Settings, useSelfSignedJWT bool) *credentials.DetectOptions {
	opts := &credentials.DetectOptions{Client: httpClientFromContext(ctx)}
	if settings == nil {
		opts.Scopes = []string{DefaultScope}
		return opts
	}
	opts.Subject = settings.Email
	opts.UseSelfSignedJWT = useSelfSignedJWT
	if useSelfSignedJWT && settings.Audience != "" {
		opts.Audience = settings.Audience
	} else {
		// An empty Scope yields no scopes, which produces the same empty
		// "scope" claim/parameter as the previous strings.Split("", " ").
		opts.Scopes = strings.Fields(settings.Scope)
	}
	if settings.CredentialsJSON != "" {
		opts.CredentialsJSON = []byte(settings.CredentialsJSON)
		// cloud.google.com/go/auth ignores "token_uri" in "authorized_user"
		// files and uses DetectOptions.TokenURL instead. Forward it so that
		// custom token endpoints (e.g. the refresh token JSON built by
		// BuildAuthRefreshTokenJSON) keep working.
		if h := parseCredentialsFileHeader(opts.CredentialsJSON); h.Type == authorizedUserCredentialsType {
			opts.TokenURL = h.TokenURI
		}
	}
	if handler := settings.resolveAuthHandler(); handler != nil {
		state := settings.State
		if state == "" {
			state = defaultAuthState
		}
		opts.AuthHandlerOptions = &auth.AuthorizationHandlerOptions{
			Handler:  handler,
			State:    state,
			PKCEOpts: GeneratePKCEOptions(),
		}
	}
	return opts
}

// httpClientFromContext returns the *http.Client stored in ctx under
// oauth2.HTTPClient, or nil to use the default client.
func httpClientFromContext(ctx context.Context) *http.Client {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(oauth2.HTTPClient).(*http.Client)
	return c
}

// newCredentials returns credentials for the given settings.
// Returns nil for API keys (settings.APIKey set or AuthType "apikey").
func newCredentials(ctx context.Context, settings *Settings) (*auth.Credentials, error) {
	if settings == nil {
		return FindAuthCredentials(ctx, nil)
	}
	if settings.APIKey != "" {
		return nil, nil
	}
	switch settings.GetAuthType() {
	case AuthTypeAPIKey:
		return nil, nil
	case AuthTypeOAuth:
		return FindAuthCredentials(ctx, settings)
	case AuthTypeJWT:
		return findJWTCredentials(ctx, settings, "JWTTokenProvider")
	default:
		return nil, fmt.Errorf("Unsupported authentication method: %s", settings.GetAuthType())
	}
}

// FetchAuthToken returns a cloud.google.com/go/auth token from the given
// settings. If settings is nil, Application Default Credentials with
// DefaultScope are used. Returns nil for API keys.
//
// For 3-legged OAuth flows, the refresh token (if any) is available via
// token.MetadataString("refresh_token").
func FetchAuthToken(ctx context.Context, settings *Settings) (*auth.Token, error) {
	creds, err := newCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, nil
	}
	tok, err := creds.Token(ctx)
	if err != nil {
		return nil, err
	}
	return withRefreshToken(tok, creds.JSON()), nil
}

// withRefreshToken returns tok with its "refresh_token" metadata set from
// "authorized_user" credentials JSON when the token response omitted it,
// matching golang.org/x/oauth2, which keeps the refresh token on refreshed
// tokens. Other tokens are returned unchanged.
func withRefreshToken(tok *auth.Token, credsJSON []byte) *auth.Token {
	if tok == nil || tok.MetadataString("refresh_token") != "" {
		return tok
	}
	h := parseCredentialsFileHeader(credsJSON)
	if h.Type != authorizedUserCredentialsType || h.RefreshToken == "" {
		return tok
	}
	// Copy the token and metadata so the cached token is not mutated.
	metadata := make(map[string]interface{}, len(tok.Metadata)+1)
	for k, v := range tok.Metadata {
		metadata[k] = v
	}
	metadata["refresh_token"] = h.RefreshToken
	tok2 := *tok
	tok2.Metadata = metadata
	return &tok2
}

// OAuthJSONTokenProvider returns a cloud.google.com/go/auth token provider
// for OAuth flows (2LO, 3LO, user and external account credentials).
func OAuthJSONTokenProvider(ctx context.Context, settings *Settings) (auth.TokenProvider, error) {
	creds, err := FindAuthCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

// JWTTokenProvider returns a cloud.google.com/go/auth token provider that
// mints self-signed JWT access tokens from service account credentials.
// settings.Audience takes precedence over settings.Scope.
func JWTTokenProvider(ctx context.Context, settings *Settings) (auth.TokenProvider, error) {
	creds, err := findJWTCredentials(ctx, settings, "JWTTokenProvider")
	if err != nil {
		return nil, err
	}
	return creds, nil
}

// findJWTCredentials returns service account credentials configured for
// self-signed JWTs. caller names the public function in validation errors.
func findJWTCredentials(ctx context.Context, settings *Settings, caller string) (*auth.Credentials, error) {
	if settings == nil || (settings.Audience == "" && settings.Scope == "") {
		// Capitalized to keep the message JWTTokenSource has always returned.
		return nil, fmt.Errorf("Neither audience nor scope is provided for %s", caller)
	}
	creds, err := credentials.DetectDefault(newDetectOptions(ctx, settings, true))
	if err != nil {
		return nil, err
	}
	// cloud.google.com/go/auth silently ignores UseSelfSignedJWT for
	// non-service-account credentials; keep rejecting them as before.
	credsJSON := creds.JSON()
	if len(credsJSON) == 0 {
		return nil, errors.New("self-signed JWT requires a service account key file; no JSON credentials were found")
	}
	if t := parseCredentialsFileHeader(credsJSON).Type; t != serviceAccountCredentialsType {
		return nil, fmt.Errorf("self-signed JWT requires %q credentials, got %q", serviceAccountCredentialsType, t)
	}
	return creds, nil
}

// FindAuthCredentials obtains cloud.google.com/go/auth credentials from
// settings or Application Default Credentials. If settings is nil,
// Application Default Credentials with DefaultScope are used.
//
// ctx is only used to look up an *http.Client stored under
// oauth2.HTTPClient; credentials.DetectDefault does not take a context.
func FindAuthCredentials(ctx context.Context, settings *Settings) (*auth.Credentials, error) {
	return credentials.DetectDefault(newDetectOptions(ctx, settings, false))
}

// Returns a token from the given settings.
// Returns nil for API keys.
//
// Deprecated: Use FetchAuthToken instead.
func FetchToken(ctx context.Context, settings *Settings) (*oauth2.Token, error) {
	tok, err := FetchAuthToken(ctx, settings)
	if err != nil {
		return nil, oauth2Error(err)
	}
	if tok == nil {
		return nil, nil
	}
	return oauth2TokenFromAuthToken(tok), nil
}

// Deprecated: Use OAuthJSONTokenProvider instead.
func OAuthJSONTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := FindAuthCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	return tokenSourceFromCredentials(ctx, creds), nil
}

// Deprecated: Use JWTTokenProvider instead.
func JWTTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := findJWTCredentials(ctx, settings, "JWTTokenSource")
	if err != nil {
		return nil, err
	}
	return tokenSourceFromCredentials(ctx, creds), nil
}

// FindJSONCredentials obtains credentials from settings or Application Default Credentials
//
// Deprecated: Use FindAuthCredentials instead.
func FindJSONCredentials(ctx context.Context, settings *Settings) (*google.Credentials, error) {
	creds, err := FindAuthCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	c := oauth2adapt.Oauth2CredentialsFromAuthCredentials(creds)
	c.TokenSource = tokenSourceFromCredentials(ctx, creds)
	return c, nil
}

// tokenSourceFromCredentials adapts auth.Credentials to an
// oauth2.TokenSource. Unlike oauth2adapt.TokenSourceFromTokenProvider, it
// also populates oauth2.Token.RefreshToken so that 3LO refresh tokens are
// preserved for legacy callers.
//
// Tokens are fetched with ctx, matching golang.org/x/oauth2/google, whose
// token sources were bound to the context they were created with.
func tokenSourceFromCredentials(ctx context.Context, creds *auth.Credentials) oauth2.TokenSource {
	if ctx == nil {
		ctx = context.Background()
	}
	return &oauth2TokenSource{ctx: ctx, creds: creds}
}

type oauth2TokenSource struct {
	ctx   context.Context
	creds *auth.Credentials
}

func (ts *oauth2TokenSource) Token() (*oauth2.Token, error) {
	tok, err := ts.creds.Token(ts.ctx)
	if err != nil {
		return nil, oauth2Error(err)
	}
	return oauth2TokenFromAuthToken(withRefreshToken(tok, ts.creds.JSON())), nil
}

// oauth2TokenFromAuthToken converts an auth.Token to an oauth2.Token,
// preserving the refresh token and the raw token response metadata (exposed
// via oauth2.Token.Extra, e.g. "id_token" and "scope").
func oauth2TokenFromAuthToken(tok *auth.Token) *oauth2.Token {
	t := &oauth2.Token{
		AccessToken:  tok.Value,
		TokenType:    tok.Type,
		RefreshToken: tok.MetadataString("refresh_token"),
		Expiry:       tok.Expiry,
	}
	if len(tok.Metadata) > 0 {
		// Copy the map to avoid sharing it with the cached auth.Token.
		extra := make(map[string]interface{}, len(tok.Metadata))
		for k, v := range tok.Metadata {
			extra[k] = v
		}
		t = t.WithExtra(extra)
	}
	return t
}

// oauth2Error adds an *oauth2.RetrieveError to the chain of *auth.Error
// values so legacy callers can keep using errors.As with
// *oauth2.RetrieveError.
func oauth2Error(err error) error {
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		oauth2adapt.AddRetrieveErrorToAuthError(authErr)
	}
	return err
}
