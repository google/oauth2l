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
	"time"

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
	jwtTokenProviderName          = "JWTTokenProvider"
	jwtTokenSourceName            = "JWTTokenSource"
)

// legacyEarlyTokenRefresh matches golang.org/x/oauth2's expiryDelta: tokens
// are refreshed 10 seconds before they expire. cloud.google.com/go/auth
// defaults to 225 seconds.
const legacyEarlyTokenRefresh = 10 * time.Second

// errNoAuthHandler is returned when a 3-legged OAuth client secret file is
// used without Settings.GoogleAuthHandler or Settings.AuthHandler.
var errNoAuthHandler = errors.New("3-legged OAuth requires Settings.GoogleAuthHandler or Settings.AuthHandler to be set")

// noAuthHandler is used when no authorization handler is configured. With
// golang.org/x/oauth2/google, client secret files could be loaded (e.g. to
// inspect their JSON) without a handler; cloud.google.com/go/auth rejects
// them up front. Passing a handler that fails only when it is called keeps
// loading working and turns the old nil-handler panic into an error.
func noAuthHandler(string) (string, string, error) {
	return "", "", errNoAuthHandler
}

// credentialsOptions configures internal credential lookups shared by the
// cloud.google.com/go/auth API and the deprecated golang.org/x/oauth2
// wrappers.
type credentialsOptions struct {
	// jwtCaller names the public function in JWT validation errors.
	jwtCaller string
	// legacy matches golang.org/x/oauth2 token refresh behavior: refresh
	// 10 seconds before expiry, synchronously in Token().
	legacy bool
}

var (
	authCredentialsOptions   = credentialsOptions{jwtCaller: jwtTokenProviderName}
	legacyCredentialsOptions = credentialsOptions{jwtCaller: jwtTokenSourceName, legacy: true}
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
//
// If no authorization handler is set, a handler that returns an error when
// called is used, so client secret files can still be loaded.
func newDetectOptions(ctx context.Context, settings *Settings, useSelfSignedJWT bool) *credentials.DetectOptions {
	opts := &credentials.DetectOptions{Client: httpClientFromContext(ctx)}
	if settings == nil {
		opts.Scopes = []string{DefaultScope}
		return opts
	}
	if !useSelfSignedJWT {
		opts.Subject = settings.Email
	}
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
	handler := settings.resolveAuthHandler()
	if handler == nil {
		handler = noAuthHandler
	}
	state := settings.State
	if state == "" {
		state = defaultAuthState
	}
	opts.AuthHandlerOptions = &auth.AuthorizationHandlerOptions{
		Handler:  handler,
		State:    state,
		PKCEOpts: GeneratePKCEOptions(),
	}
	return opts
}

// newDetectOptionsFor is newDetectOptions plus the refresh behavior selected
// by o.
func newDetectOptionsFor(ctx context.Context, settings *Settings, useSelfSignedJWT bool, o credentialsOptions) *credentials.DetectOptions {
	opts := newDetectOptions(ctx, settings, useSelfSignedJWT)
	if o.legacy {
		opts.EarlyTokenRefresh = legacyEarlyTokenRefresh
		opts.DisableAsyncRefresh = true
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
func newCredentials(ctx context.Context, settings *Settings, o credentialsOptions) (*auth.Credentials, error) {
	if settings == nil {
		return findAuthCredentials(ctx, nil, o)
	}
	if settings.APIKey != "" {
		return nil, nil
	}
	switch settings.GetAuthType() {
	case AuthTypeAPIKey:
		return nil, nil
	case AuthTypeOAuth:
		return findAuthCredentials(ctx, settings, o)
	case AuthTypeJWT:
		return findJWTCredentials(ctx, settings, o)
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
	creds, err := newCredentials(ctx, settings, authCredentialsOptions)
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
	h := parseCredentialsFileHeader(credsJSON)
	if h.Type != authorizedUserCredentialsType {
		return tok
	}
	return withFallbackRefreshToken(tok, h.RefreshToken)
}

func withFallbackRefreshToken(tok *auth.Token, refreshToken string) *auth.Token {
	if tok == nil || refreshToken == "" || tok.MetadataString("refresh_token") != "" {
		return tok
	}
	// Copy the token and metadata so the cached token is not mutated.
	metadata := make(map[string]interface{}, len(tok.Metadata)+1)
	for k, v := range tok.Metadata {
		metadata[k] = v
	}
	metadata["refresh_token"] = refreshToken
	tok2 := *tok
	tok2.Metadata = metadata
	return &tok2
}

// OAuthJSONTokenProvider returns a cloud.google.com/go/auth token provider
// for OAuth flows (2LO, 3LO, user and external account credentials). The
// returned provider is the *auth.Credentials from FindAuthCredentials.
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
	creds, err := findJWTCredentials(ctx, settings, authCredentialsOptions)
	if err != nil {
		return nil, err
	}
	return creds, nil
}

// findJWTCredentials returns service account credentials configured for
// self-signed JWTs.
func findJWTCredentials(ctx context.Context, settings *Settings, o credentialsOptions) (*auth.Credentials, error) {
	if settings == nil || (settings.Audience == "" && settings.Scope == "") {
		// Capitalized to keep the message JWTTokenSource has always returned.
		return nil, fmt.Errorf("Neither audience nor scope is provided for %s", o.jwtCaller)
	}
	creds, err := credentials.DetectDefault(newDetectOptionsFor(ctx, settings, true, o))
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
	return findAuthCredentials(ctx, settings, authCredentialsOptions)
}

func findAuthCredentials(ctx context.Context, settings *Settings, o credentialsOptions) (*auth.Credentials, error) {
	opts := newDetectOptionsFor(ctx, settings, false, o)
	creds, err := credentials.DetectDefault(opts)
	if err != nil {
		return nil, err
	}
	// When ADC loaded an "authorized_user" file from disk, forward any
	// custom "token_uri" from the JSON that DetectDefault loaded (since
	// cloud.google.com/go/auth ignores "token_uri" in "authorized_user"
	// files unless DetectOptions.TokenURL is set).
	if opts.TokenURL == "" {
		if h := parseCredentialsFileHeader(creds.JSON()); h.Type == authorizedUserCredentialsType && h.TokenURI != "" {
			opts.CredentialsJSON = creds.JSON()
			opts.TokenURL = h.TokenURI
			return credentials.DetectDefault(opts)
		}
	}
	return creds, nil
}

// FetchToken returns a token from the given settings.
// Returns nil for API keys.
//
// Deprecated: Use FetchAuthToken instead.
func FetchToken(ctx context.Context, settings *Settings) (*oauth2.Token, error) {
	creds, err := newCredentials(ctx, settings, legacyCredentialsOptions)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		return nil, nil
	}
	return tokenSourceFromCredentials(ctx, creds).Token()
}

// OAuthJSONTokenSource returns an oauth2.TokenSource for OAuth flows.
//
// Deprecated: Use OAuthJSONTokenProvider instead.
func OAuthJSONTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := findAuthCredentials(ctx, settings, legacyCredentialsOptions)
	if err != nil {
		return nil, err
	}
	return tokenSourceFromCredentials(ctx, creds), nil
}

// JWTTokenSource returns an oauth2.TokenSource that mints self-signed JWT
// access tokens from service account credentials.
//
// Deprecated: Use JWTTokenProvider instead.
func JWTTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := findJWTCredentials(ctx, settings, legacyCredentialsOptions)
	if err != nil {
		return nil, err
	}
	return tokenSourceFromCredentials(ctx, creds), nil
}

// FindJSONCredentials obtains credentials from settings or Application Default Credentials.
//
// Deprecated: Use FindAuthCredentials instead.
func FindJSONCredentials(ctx context.Context, settings *Settings) (*google.Credentials, error) {
	creds, err := findAuthCredentials(ctx, settings, legacyCredentialsOptions)
	if err != nil {
		return nil, err
	}
	c := oauth2adapt.Oauth2CredentialsFromAuthCredentials(creds)
	c.TokenSource = tokenSourceFromCredentials(ctx, creds)
	return c, nil
}

// tokenSourceFromCredentials adapts auth.Credentials to an oauth2.TokenSource
// for the deprecated golang.org/x/oauth2 wrappers, using
// oauth2adapt.TokenSourceFromTokenProvider for the type conversion (which
// also restores the "oauth2.google.*" compute token extras and adds
// *oauth2.RetrieveError to token errors).
//
// oauth2adapt alone would drop two things legacy callers rely on, so it is
// wrapped on both sides:
//   - ctxTokenProvider runs every Token() call with ctx, as
//     golang.org/x/oauth2/google token sources did (oauth2adapt always uses
//     context.Background()). ctx only affects calls that fetch a new token;
//     a cached token that is still valid is returned even if ctx is done.
//   - refreshTokenSource sets oauth2.Token.RefreshToken, which oauth2adapt
//     leaves only in Extra("refresh_token").
func tokenSourceFromCredentials(ctx context.Context, creds *auth.Credentials) oauth2.TokenSource {
	if ctx == nil {
		ctx = context.Background()
	}
	var refreshToken string
	if h := parseCredentialsFileHeader(creds.JSON()); h.Type == authorizedUserCredentialsType {
		refreshToken = h.RefreshToken
	}
	return &refreshTokenSource{
		ts: oauth2adapt.TokenSourceFromTokenProvider(&ctxTokenProvider{
			ctx:          ctx,
			tp:           creds,
			refreshToken: refreshToken,
		}),
	}
}

// ctxTokenProvider is an auth.TokenProvider that ignores the context passed
// to Token and uses ctx instead.
type ctxTokenProvider struct {
	ctx          context.Context
	tp           auth.TokenProvider
	refreshToken string
}

func (p *ctxTokenProvider) Token(context.Context) (*auth.Token, error) {
	tok, err := p.tp.Token(p.ctx)
	if err != nil {
		return nil, err
	}
	return legacyAuthToken(tok, p.refreshToken), nil
}

// legacyAuthToken returns a copy of tok whose metadata matches what
// golang.org/x/oauth2 exposed via oauth2.Token.Extra:
//   - single-valued []string entries (from form-encoded token responses)
//     become plain strings, as url.Values.Get returned them;
//   - "refresh_token" falls back to refreshToken when the token response
//     omitted it, as golang.org/x/oauth2 kept the refresh token on refreshed
//     tokens.
//
// The cached tok is not modified.
func legacyAuthToken(tok *auth.Token, refreshToken string) *auth.Token {
	if tok == nil {
		return nil
	}
	metadata := make(map[string]interface{}, len(tok.Metadata)+1)
	for k, v := range tok.Metadata {
		if vs, ok := v.([]string); ok && len(vs) == 1 {
			v = vs[0]
		}
		metadata[k] = v
	}
	if refreshToken != "" {
		if s, _ := metadata["refresh_token"].(string); s == "" {
			metadata["refresh_token"] = refreshToken
		}
	}
	tok2 := *tok
	tok2.Metadata = metadata
	return &tok2
}

// refreshTokenSource copies Extra("refresh_token") into
// oauth2.Token.RefreshToken.
type refreshTokenSource struct {
	ts oauth2.TokenSource
}

func (s *refreshTokenSource) Token() (*oauth2.Token, error) {
	t, err := s.ts.Token()
	if err != nil {
		return nil, err
	}
	if rt, ok := t.Extra("refresh_token").(string); ok && t.RefreshToken == "" {
		t.RefreshToken = rt
	}
	return t, nil
}
