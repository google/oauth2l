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
package util

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
)

const testRefreshToken = "test-refresh-token"

// newTokenServer returns a fake OAuth 2.0 token endpoint that responds with
// the given status code and JSON body.
func newTokenServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func authorizedUserJSON(tokenURI string) string {
	return fmt.Sprintf(`{
  "type": "authorized_user",
  "client_id": "test-client.apps.googleusercontent.com",
  "client_secret": "test-secret",
  "refresh_token": %q,
  "token_uri": %q
}`, testRefreshToken, tokenURI)
}

func serviceAccountJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() unexpected error: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() unexpected error: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "test-key-id",
		"private_key":    string(pemKey),
		"client_email":   "test-sa@test-project.iam.gserviceaccount.com",
		"client_id":      "123456789",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}
	return string(b)
}

// decodeJWTClaims decodes the (unverified) claims of a JWT. Unlike jwtClaims,
// it does not use *testing.T, so it is safe to call from non-test goroutines
// such as httptest handlers.
func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token %q is not a JWT", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, fmt.Errorf("unmarshaling JWT claims: %w", err)
	}
	return claims, nil
}

// jwtClaims decodes the (unverified) claims of a JWT. It must only be called
// from the test goroutine.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	claims, err := decodeJWTClaims(token)
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestNewDetectOptions(t *testing.T) {
	tests := []struct {
		name             string
		settings         *Settings
		useSelfSignedJWT bool
		wantScopes       []string
		wantAudience     string
		wantTokenURL     string
		wantSubject      string
	}{
		{
			name:       "nil_settings_use_default_scope",
			wantScopes: []string{DefaultScope},
		},
		{
			name:       "oauth_splits_space_delimited_scopes",
			settings:   &Settings{Scope: "scope1 scope2"},
			wantScopes: []string{"scope1", "scope2"},
		},
		{
			name:       "oauth_ignores_audience_when_both_scope_and_audience_set",
			settings:   &Settings{Scope: "scope1", Audience: "https://sts.googleapis.com"},
			wantScopes: []string{"scope1"},
		},
		{
			name:             "jwt_prefers_audience_over_scope",
			settings:         &Settings{Scope: "scope1", Audience: "https://example.googleapis.com/"},
			useSelfSignedJWT: true,
			wantAudience:     "https://example.googleapis.com/",
		},
		{
			name:             "jwt_falls_back_to_scope",
			settings:         &Settings{Scope: "scope1"},
			useSelfSignedJWT: true,
			wantScopes:       []string{"scope1"},
		},
		{
			name:         "authorized_user_token_uri_forwarded_to_token_url",
			settings:     &Settings{Scope: "scope1", CredentialsJSON: authorizedUserJSON("http://localhost:8080/token")},
			wantScopes:   []string{"scope1"},
			wantTokenURL: "http://localhost:8080/token",
		},
		{
			name:       "token_uri_of_other_credential_types_not_forwarded",
			settings:   &Settings{Scope: "scope1", CredentialsJSON: `{"type": "service_account", "token_uri": "http://localhost:8080/token"}`},
			wantScopes: []string{"scope1"},
		},
		{
			name:        "email_used_as_subject_for_oauth",
			settings:    &Settings{Scope: "scope1", Email: "user@example.com"},
			wantScopes:  []string{"scope1"},
			wantSubject: "user@example.com",
		},
		{
			name:             "email_ignored_for_self_signed_jwt",
			settings:         &Settings{Audience: "https://example.googleapis.com/", Email: "user@example.com"},
			useSelfSignedJWT: true,
			wantAudience:     "https://example.googleapis.com/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := newDetectOptions(t.Context(), tc.settings, tc.useSelfSignedJWT)
			if !reflect.DeepEqual(opts.Scopes, tc.wantScopes) {
				t.Errorf("Scopes = %q, want %q", opts.Scopes, tc.wantScopes)
			}
			if opts.Audience != tc.wantAudience {
				t.Errorf("Audience = %q, want %q", opts.Audience, tc.wantAudience)
			}
			if opts.TokenURL != tc.wantTokenURL {
				t.Errorf("TokenURL = %q, want %q", opts.TokenURL, tc.wantTokenURL)
			}
			if opts.Subject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", opts.Subject, tc.wantSubject)
			}
			if opts.UseSelfSignedJWT != (tc.useSelfSignedJWT && tc.settings != nil) {
				t.Errorf("UseSelfSignedJWT = %v, want %v", opts.UseSelfSignedJWT, tc.useSelfSignedJWT)
			}
		})
	}
}

func TestNewDetectOptionsAuthHandlerOptions(t *testing.T) {
	handler := auth.AuthorizationHandler(func(string) (string, string, error) {
		return "code", "state", nil
	})
	legacyHandler := authhandler.AuthorizationHandler(func(string) (string, string, error) {
		return "legacy-code", "state", nil
	})

	tests := []struct {
		name      string
		settings  *Settings
		wantErr   error
		wantCode  string
		wantState string
	}{
		{
			name:      "no_handler_uses_placeholder_handler",
			settings:  &Settings{Scope: "scope1"},
			wantErr:   errNoAuthHandler,
			wantState: defaultAuthState,
		},
		{
			name:      "google_auth_handler_with_default_state",
			settings:  &Settings{Scope: "scope1", GoogleAuthHandler: handler},
			wantCode:  "code",
			wantState: defaultAuthState,
		},
		{
			name:      "deprecated_auth_handler_with_custom_state",
			settings:  &Settings{Scope: "scope1", AuthHandler: legacyHandler, State: "custom-state"},
			wantCode:  "legacy-code",
			wantState: "custom-state",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newDetectOptions(t.Context(), tc.settings, false).AuthHandlerOptions
			if got == nil || got.Handler == nil {
				t.Fatal("AuthHandlerOptions.Handler = nil, want non-nil")
			}
			code, _, err := got.Handler("")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("Handler() error = %v, want %v", err, tc.wantErr)
			}
			if code != tc.wantCode {
				t.Errorf("Handler() code = %q, want %q", code, tc.wantCode)
			}
			if got.State != tc.wantState {
				t.Errorf("State = %q, want %q", got.State, tc.wantState)
			}
			if got.PKCEOpts == nil || got.PKCEOpts.ChallengeMethod != "S256" || got.PKCEOpts.Verifier == "" {
				t.Errorf("PKCEOpts = %+v, want S256 challenge with verifier", got.PKCEOpts)
			}
		})
	}
}

func TestFetchAuthTokenAPIKey(t *testing.T) {
	for _, s := range []*Settings{
		{APIKey: "my-api-key"},
		{AuthType: AuthTypeAPIKey},
	} {
		tok, err := FetchAuthToken(t.Context(), s)
		if err != nil || tok != nil {
			t.Errorf("FetchAuthToken(%+v) = (%v, %v), want (nil, nil)", s, tok, err)
		}
		oauth2Tok, err := FetchToken(t.Context(), s)
		if err != nil || oauth2Tok != nil {
			t.Errorf("FetchToken(%+v) = (%v, %v), want (nil, nil)", s, oauth2Tok, err)
		}
	}
}

func TestFetchAuthTokenUnsupportedAuthType(t *testing.T) {
	_, err := FetchAuthToken(t.Context(), &Settings{AuthType: AuthTypeSSO})
	if err == nil || !strings.Contains(err.Error(), "Unsupported authentication method: sso") {
		t.Errorf("FetchAuthToken() error = %v, want unsupported authentication method", err)
	}
}

func TestFetchAuthTokenAuthorizedUser(t *testing.T) {
	tests := []struct {
		name             string
		response         string
		wantRefreshToken string
	}{
		{
			name:             "refresh_token_kept_from_credentials_when_omitted_in_response",
			response:         `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600, "scope": "scope1", "id_token": "test-id-token"}`,
			wantRefreshToken: testRefreshToken,
		},
		{
			name:             "rotated_refresh_token_from_response_is_used",
			response:         `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600, "scope": "scope1", "id_token": "test-id-token", "refresh_token": "rotated-refresh-token"}`,
			wantRefreshToken: "rotated-refresh-token",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTokenServer(t, http.StatusOK, tc.response)
			settings := &Settings{
				AuthType:        AuthTypeOAuth,
				CredentialsJSON: authorizedUserJSON(srv.URL),
				Scope:           "scope1",
			}

			tok, err := FetchAuthToken(t.Context(), settings)
			if err != nil {
				t.Fatalf("FetchAuthToken() unexpected error: %v", err)
			}
			if tok.Value != "test-access-token" || tok.Type != "Bearer" || tok.Expiry.IsZero() {
				t.Errorf("FetchAuthToken() = %+v, want access token with type and expiry", tok)
			}
			if got := tok.MetadataString("refresh_token"); got != tc.wantRefreshToken {
				t.Errorf("FetchAuthToken() refresh_token = %q, want %q", got, tc.wantRefreshToken)
			}

			// The deprecated wrappers expose the same token via golang.org/x/oauth2.
			oauth2Tok, err := FetchToken(t.Context(), settings)
			if err != nil {
				t.Fatalf("FetchToken() unexpected error: %v", err)
			}
			ts, err := OAuthJSONTokenSource(t.Context(), settings)
			if err != nil {
				t.Fatalf("OAuthJSONTokenSource() unexpected error: %v", err)
			}
			tsTok, err := ts.Token()
			if err != nil {
				t.Fatalf("OAuthJSONTokenSource().Token() unexpected error: %v", err)
			}
			for name, got := range map[string]*oauth2.Token{"FetchToken": oauth2Tok, "OAuthJSONTokenSource": tsTok} {
				if got.AccessToken != "test-access-token" || got.TokenType != "Bearer" || got.Expiry.IsZero() {
					t.Errorf("%s() = %+v, want access token with type and expiry", name, got)
				}
				if got.RefreshToken != tc.wantRefreshToken {
					t.Errorf("%s() RefreshToken = %q, want %q", name, got.RefreshToken, tc.wantRefreshToken)
				}
				if got.Extra("id_token") != "test-id-token" || got.Extra("scope") != "scope1" {
					t.Errorf("%s() Extra(id_token, scope) = (%v, %v), want (test-id-token, scope1)", name, got.Extra("id_token"), got.Extra("scope"))
				}
				data, err := MarshalWithExtras(got, "")
				if err != nil {
					t.Errorf("MarshalWithExtras(%s()) unexpected error: %v", name, err)
					continue
				}
				var m map[string]any
				if err := json.Unmarshal(data, &m); err != nil {
					t.Errorf("json.Unmarshal(MarshalWithExtras(%s())) unexpected error: %v", name, err)
				} else if m["refresh_token"] != tc.wantRefreshToken {
					t.Errorf("MarshalWithExtras(%s()) = %s, want refresh_token %q", name, data, tc.wantRefreshToken)
				}
			}
		})
	}
}

func TestFetchTokenRetrieveError(t *testing.T) {
	srv := newTokenServer(t, http.StatusBadRequest, `{"error": "invalid_grant", "error_description": "Bad Request"}`)
	settings := &Settings{
		AuthType:        AuthTypeOAuth,
		CredentialsJSON: authorizedUserJSON(srv.URL),
		Scope:           "scope1",
	}

	_, err := FetchAuthToken(t.Context(), settings)
	var authErr *auth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("FetchAuthToken() error = %v, want *auth.Error", err)
	}

	_, err = FetchToken(t.Context(), settings)
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		t.Fatalf("FetchToken() error = %v, want *oauth2.RetrieveError in chain", err)
	}
	if retrieveErr.ErrorCode != "invalid_grant" {
		t.Errorf("RetrieveError.ErrorCode = %q, want %q", retrieveErr.ErrorCode, "invalid_grant")
	}

	ts, err := OAuthJSONTokenSource(t.Context(), settings)
	if err != nil {
		t.Fatalf("OAuthJSONTokenSource() unexpected error: %v", err)
	}
	_, err = ts.Token()
	var tsRetrieveErr *oauth2.RetrieveError
	if !errors.As(err, &tsRetrieveErr) || tsRetrieveErr.ErrorCode != "invalid_grant" {
		t.Errorf("OAuthJSONTokenSource().Token() error = %v, want *oauth2.RetrieveError with invalid_grant", err)
	}
}

func TestJWTTokenProvider(t *testing.T) {
	saJSON := serviceAccountJSON(t)
	tests := []struct {
		name         string
		settings     *Settings
		wantAudience string
		wantScope    string
	}{
		{
			name:         "audience_takes_precedence_over_scope",
			settings:     &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON, Audience: "https://pubsub.googleapis.com/", Scope: "scope1"},
			wantAudience: "https://pubsub.googleapis.com/",
		},
		{
			name:      "scope_only_with_email_set_keeps_service_account_as_sub",
			settings:  &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON, Scope: "scope1 scope2", Email: "user@example.com"},
			wantScope: "scope1 scope2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := FetchAuthToken(t.Context(), tc.settings)
			if err != nil {
				t.Fatalf("FetchAuthToken() unexpected error: %v", err)
			}
			if tok.Type != "Bearer" || tok.Expiry.IsZero() {
				t.Errorf("FetchAuthToken() = %+v, want Bearer token with expiry", tok)
			}
			claims := jwtClaims(t, tok.Value)
			if got, _ := claims["aud"].(string); got != tc.wantAudience {
				t.Errorf("JWT aud = %q, want %q", got, tc.wantAudience)
			}
			if got, _ := claims["scope"].(string); got != tc.wantScope {
				t.Errorf("JWT scope = %q, want %q", got, tc.wantScope)
			}
			if got, _ := claims["iss"].(string); got != "test-sa@test-project.iam.gserviceaccount.com" {
				t.Errorf("JWT iss = %q, want service account email", got)
			}
			if got, _ := claims["sub"].(string); got != "test-sa@test-project.iam.gserviceaccount.com" {
				t.Errorf("JWT sub = %q, want service account email", got)
			}

			ts, err := JWTTokenSource(t.Context(), tc.settings)
			if err != nil {
				t.Fatalf("JWTTokenSource() unexpected error: %v", err)
			}
			if _, err := ts.Token(); err != nil {
				t.Errorf("JWTTokenSource().Token() unexpected error: %v", err)
			}
		})
	}
}

func TestJWTTokenProviderErrors(t *testing.T) {
	saJSON := serviceAccountJSON(t)
	t.Run("neither_audience_nor_scope_preserves_caller_name", func(t *testing.T) {
		settings := &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON}
		wantProviderErr := "Neither audience nor scope is provided for JWTTokenProvider"
		for name, fn := range map[string]func() error{
			"JWTTokenProvider": func() error { _, err := JWTTokenProvider(t.Context(), settings); return err },
			"FetchAuthToken":   func() error { _, err := FetchAuthToken(t.Context(), settings); return err },
		} {
			if err := fn(); err == nil || err.Error() != wantProviderErr {
				t.Errorf("%s() error = %v, want %q", name, err, wantProviderErr)
			}
		}
		wantSourceErr := "Neither audience nor scope is provided for JWTTokenSource"
		for name, fn := range map[string]func() error{
			"JWTTokenSource": func() error { _, err := JWTTokenSource(t.Context(), settings); return err },
			"FetchToken":     func() error { _, err := FetchToken(t.Context(), settings); return err },
		} {
			if err := fn(); err == nil || err.Error() != wantSourceErr {
				t.Errorf("%s() error = %v, want %q", name, err, wantSourceErr)
			}
		}
	})

	t.Run("non_service_account_credentials", func(t *testing.T) {
		settings := &Settings{AuthType: AuthTypeJWT, CredentialsJSON: authorizedUserJSON("http://localhost/token"), Audience: "aud"}
		wantErr := `self-signed JWT requires "service_account" credentials, got "authorized_user"`
		if _, err := JWTTokenProvider(t.Context(), settings); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("JWTTokenProvider() error = %v, want error containing %q", err, wantErr)
		}
		if _, err := JWTTokenSource(t.Context(), settings); err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Errorf("JWTTokenSource() error = %v, want error containing %q", err, wantErr)
		}
	})
}

func TestFetchAuthTokenADCAuthorizedUserTokenURI(t *testing.T) {
	srv := newTokenServer(t, http.StatusOK, `{"access_token": "adc-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	credsFile := t.TempDir() + "/adc.json"
	if err := os.WriteFile(credsFile, []byte(authorizedUserJSON(srv.URL)), 0600); err != nil {
		t.Fatalf("os.WriteFile() unexpected error: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile)

	tok, err := FetchAuthToken(t.Context(), &Settings{AuthType: AuthTypeOAuth, Scope: "scope1"})
	if err != nil {
		t.Fatalf("FetchAuthToken(ADC) unexpected error: %v", err)
	}
	if tok.Value != "adc-access-token" || tok.MetadataString("refresh_token") != testRefreshToken {
		t.Errorf("FetchAuthToken(ADC) = (%q, %q), want (adc-access-token, %q)", tok.Value, tok.MetadataString("refresh_token"), testRefreshToken)
	}

	nilTok, err := FetchToken(t.Context(), nil)
	if err != nil {
		t.Fatalf("FetchToken(nil) unexpected error: %v", err)
	}
	if nilTok.AccessToken != "adc-access-token" || nilTok.RefreshToken != testRefreshToken {
		t.Errorf("FetchToken(nil) = (%q, %q), want (adc-access-token, %q)", nilTok.AccessToken, nilTok.RefreshToken, testRefreshToken)
	}

	// Well-known gcloud ADC path when GOOGLE_APPLICATION_CREDENTIALS is unset.
	homeDir := t.TempDir()
	gcloudDir := homeDir + "/.config/gcloud"
	if err := os.MkdirAll(gcloudDir, 0700); err != nil {
		t.Fatalf("os.MkdirAll() unexpected error: %v", err)
	}
	if err := os.WriteFile(gcloudDir+"/application_default_credentials.json", []byte(authorizedUserJSON(srv.URL)), 0600); err != nil {
		t.Fatalf("os.WriteFile() unexpected error: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", homeDir)
	t.Setenv("APPDATA", homeDir)

	wellKnownTok, err := FetchAuthToken(t.Context(), nil)
	if err != nil {
		t.Fatalf("FetchAuthToken(well-known ADC) unexpected error: %v", err)
	}
	if wellKnownTok.Value != "adc-access-token" || wellKnownTok.MetadataString("refresh_token") != testRefreshToken {
		t.Errorf("FetchAuthToken(well-known ADC) = (%q, %q), want (adc-access-token, %q)", wellKnownTok.Value, wellKnownTok.MetadataString("refresh_token"), testRefreshToken)
	}
}

func TestFindJSONCredentialsPreservesJSONAndProjectID(t *testing.T) {
	saJSON := serviceAccountJSON(t)
	settings := &Settings{CredentialsJSON: saJSON, Scope: "scope1"}

	authCreds, err := FindAuthCredentials(t.Context(), settings)
	if err != nil {
		t.Fatalf("FindAuthCredentials() unexpected error: %v", err)
	}
	if string(authCreds.JSON()) != saJSON {
		t.Errorf("FindAuthCredentials().JSON() = %s, want %s", authCreds.JSON(), saJSON)
	}

	creds, err := FindJSONCredentials(t.Context(), settings)
	if err != nil {
		t.Fatalf("FindJSONCredentials() unexpected error: %v", err)
	}
	if string(creds.JSON) != saJSON {
		t.Errorf("FindJSONCredentials().JSON = %s, want %s", creds.JSON, saJSON)
	}
	if creds.ProjectID != "test-project" {
		t.Errorf("FindJSONCredentials().ProjectID = %q, want %q", creds.ProjectID, "test-project")
	}
	if creds.TokenSource == nil {
		t.Error("FindJSONCredentials().TokenSource = nil, want non-nil")
	}
}

func TestNewDetectOptionsScopeFields(t *testing.T) {
	tests := []struct {
		scope      string
		wantScopes []string
	}{
		{scope: ""},
		{scope: "scope1  scope2 ", wantScopes: []string{"scope1", "scope2"}},
	}
	for _, tc := range tests {
		opts := newDetectOptions(t.Context(), &Settings{Scope: tc.scope}, false)
		if len(opts.Scopes) != len(tc.wantScopes) || (len(tc.wantScopes) > 0 && !reflect.DeepEqual(opts.Scopes, tc.wantScopes)) {
			t.Errorf("newDetectOptions(Scope: %q).Scopes = %q, want %q", tc.scope, opts.Scopes, tc.wantScopes)
		}
	}
}

func TestNewDetectOptionsHTTPClientFromContext(t *testing.T) {
	client := &http.Client{}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, client)
	if got := newDetectOptions(ctx, &Settings{Scope: "scope1"}, false).Client; got != client {
		t.Errorf("Client = %p, want client from context %p", got, client)
	}
	if got := newDetectOptions(t.Context(), &Settings{Scope: "scope1"}, false).Client; got != nil {
		t.Errorf("Client = %p, want nil without oauth2.HTTPClient in context", got)
	}
}

// recordingTransport records the requested URLs and forwards to
// http.DefaultTransport.
type recordingTransport struct {
	urls []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.urls = append(rt.urls, r.URL.String())
	return http.DefaultTransport.RoundTrip(r)
}

func TestFetchTokenUsesHTTPClientFromContext(t *testing.T) {
	srv := newTokenServer(t, http.StatusOK, `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	rt := &recordingTransport{}
	ctx := context.WithValue(t.Context(), oauth2.HTTPClient, &http.Client{Transport: rt})
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: authorizedUserJSON(srv.URL), Scope: "scope1"}

	if _, err := FetchToken(ctx, settings); err != nil {
		t.Fatalf("FetchToken() unexpected error: %v", err)
	}
	if len(rt.urls) != 1 || rt.urls[0] != srv.URL {
		t.Errorf("requests through context client = %q, want [%q]", rt.urls, srv.URL)
	}
}

func TestOAuthJSONTokenSourceUsesContext(t *testing.T) {
	srv := newTokenServer(t, http.StatusOK, `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: authorizedUserJSON(srv.URL), Scope: "scope1"}

	ts, err := OAuthJSONTokenSource(ctx, settings)
	if err != nil {
		t.Fatalf("OAuthJSONTokenSource() unexpected error: %v", err)
	}
	if _, err := ts.Token(); !errors.Is(err, context.Canceled) {
		t.Errorf("Token() with canceled context error = %v, want %v", err, context.Canceled)
	}
}

// TestFetchAuthTokenRefreshTokenJSON checks that the refresh token JSON built
// by BuildAuthRefreshTokenJSON is sent to the client secret's token_uri.
func TestFetchAuthTokenRefreshTokenJSON(t *testing.T) {
	var gotForm map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() unexpected error: %v", err)
		}
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "refreshed-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	}))
	t.Cleanup(srv.Close)

	clientSecretJSON := fmt.Sprintf(`{"installed": {
  "client_id": "test-client.apps.googleusercontent.com",
  "client_secret": "test-secret",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": %q,
  "redirect_uris": ["http://localhost"]
}}`, srv.URL)
	creds := auth.NewCredentials(&auth.CredentialsOptions{JSON: []byte(clientSecretJSON)})
	refreshJSON := BuildAuthRefreshTokenJSON(testRefreshToken, creds)
	if refreshJSON == "" {
		t.Fatal("BuildAuthRefreshTokenJSON() = \"\", want refresh token JSON")
	}

	tok, err := FetchAuthToken(t.Context(), &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: refreshJSON, Scope: "scope1"})
	if err != nil {
		t.Fatalf("FetchAuthToken() unexpected error: %v", err)
	}
	if tok.Value != "refreshed-access-token" {
		t.Errorf("FetchAuthToken().Value = %q, want %q", tok.Value, "refreshed-access-token")
	}
	if got := tok.MetadataString("refresh_token"); got != testRefreshToken {
		t.Errorf("FetchAuthToken() refresh_token = %q, want %q", got, testRefreshToken)
	}
	if g := gotForm["grant_type"]; len(g) != 1 || g[0] != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", g)
	}
	if g := gotForm["refresh_token"]; len(g) != 1 || g[0] != testRefreshToken {
		t.Errorf("refresh_token = %q, want %q", g, testRefreshToken)
	}
}

// TestFetchAuthTokenServiceAccountEmptyScope checks that an OAuth fetch with
// service account JSON and no scope still succeeds, sending an empty scope
// claim as golang.org/x/oauth2 did.
func TestFetchAuthTokenServiceAccountEmptyScope(t *testing.T) {
	var gotScope any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This runs on the server goroutine, so report problems with
		// t.Errorf and an HTTP error rather than t.Fatal.
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() unexpected error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		claims, err := decodeJWTClaims(r.PostForm.Get("assertion"))
		if err != nil {
			t.Errorf("decodeJWTClaims(assertion) unexpected error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotScope = claims["scope"]
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "sa-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	}))
	t.Cleanup(srv.Close)

	var sa map[string]string
	if err := json.Unmarshal([]byte(serviceAccountJSON(t)), &sa); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %v", err)
	}
	sa["token_uri"] = srv.URL
	saJSON, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}

	tok, err := FetchAuthToken(t.Context(), &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: string(saJSON)})
	if err != nil {
		t.Fatalf("FetchAuthToken() unexpected error: %v", err)
	}
	if tok.Value != "sa-access-token" {
		t.Errorf("FetchAuthToken().Value = %q, want %q", tok.Value, "sa-access-token")
	}
	if gotScope != nil && gotScope != "" {
		t.Errorf("JWT assertion scope = %v, want empty", gotScope)
	}
}

func TestWithRefreshToken(t *testing.T) {
	userJSON := []byte(authorizedUserJSON("http://localhost/token"))
	installedJSON := []byte(clientSecretJSON("http://localhost/token"))
	tests := []struct {
		name      string
		tok       *auth.Token
		credsJSON []byte
		want      string
	}{
		{name: "nil_token", credsJSON: userJSON},
		{name: "metadata_already_has_refresh_token", tok: &auth.Token{Metadata: map[string]any{"refresh_token": "existing"}}, credsJSON: userJSON, want: "existing"},
		{name: "non_authorized_user_credentials", tok: &auth.Token{}, credsJSON: []byte(`{"type": "service_account", "refresh_token": "x"}`)},
		{name: "empty_credentials_json", tok: &auth.Token{}},
		{name: "authorized_user_fills_refresh_token", tok: &auth.Token{Metadata: map[string]any{"scope": "scope1"}}, credsJSON: userJSON, want: testRefreshToken},
		{name: "form_encoded_refresh_token_on_authorized_user", tok: &auth.Token{Metadata: map[string]any{"refresh_token": []string{"rotated"}}}, credsJSON: userJSON, want: "rotated"},
		{name: "form_encoded_empty_refresh_token_falls_back", tok: &auth.Token{Metadata: map[string]any{"refresh_token": []string{""}}}, credsJSON: userJSON, want: testRefreshToken},
		{name: "form_encoded_refresh_token_on_client_secret", tok: &auth.Token{Metadata: map[string]any{"refresh_token": []string{"3lo-rt"}}}, credsJSON: installedJSON, want: "3lo-rt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var before map[string]any
			if tc.tok != nil && tc.tok.Metadata != nil {
				before = make(map[string]any, len(tc.tok.Metadata))
				for k, v := range tc.tok.Metadata {
					before[k] = v
				}
			}
			got := withRefreshToken(tc.tok, tc.credsJSON)
			if tc.tok == nil {
				if got != nil {
					t.Errorf("withRefreshToken(nil) = %+v, want nil", got)
				}
				return
			}
			if s := got.MetadataString("refresh_token"); s != tc.want {
				t.Errorf("refresh_token = %q, want %q", s, tc.want)
			}
			if before != nil && !reflect.DeepEqual(tc.tok.Metadata, before) {
				t.Errorf("input token metadata mutated: got %v, want %v", tc.tok.Metadata, before)
			}
		})
	}
}

func TestFindJWTCredentialsNoJSON(t *testing.T) {
	// Point ADC at nothing so only a JSON-less source could be found; on
	// machines without GCE metadata this returns a "could not find default
	// credentials" error instead, which is also acceptable here.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	t.Setenv("CLOUDSDK_CONFIG", t.TempDir())
	t.Setenv("GCE_METADATA_HOST", "")
	_, err := JWTTokenProvider(t.Context(), &Settings{AuthType: AuthTypeJWT, Audience: "aud"})
	if err == nil {
		t.Fatal("JWTTokenProvider() without credentials error = nil, want error")
	}
	if strings.Contains(err.Error(), `got ""`) {
		t.Errorf("JWTTokenProvider() error = %v, want a message that does not report an empty type", err)
	}
}

// fakeTokenProvider returns a fixed token.
type fakeTokenProvider struct {
	tok *auth.Token
}

func (p fakeTokenProvider) Token(context.Context) (*auth.Token, error) {
	return p.tok, nil
}

// TestTokenSourceFromCredentialsComputeExtras checks that the deprecated
// wrappers expose the golang.org/x/oauth2/google compute token extras, which
// google.golang.org/api reads (e.g. for DirectPath).
func TestTokenSourceFromCredentialsComputeExtras(t *testing.T) {
	creds := auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider: fakeTokenProvider{tok: &auth.Token{
			Value: "test-access-token",
			Type:  "Bearer",
			Metadata: map[string]interface{}{
				"auth.google.tokenSource":    "compute-metadata",
				"auth.google.serviceAccount": "default",
			},
		}},
	})

	got, err := tokenSourceFromCredentials(t.Context(), creds).Token()
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	for key, want := range map[string]string{
		"oauth2.google.tokenSource":    "compute-metadata",
		"oauth2.google.serviceAccount": "default",
		"auth.google.tokenSource":      "compute-metadata",
	} {
		if v := got.Extra(key); v != want {
			t.Errorf("Token().Extra(%q) = %v, want %q", key, v, want)
		}
	}
}

// TestTokenSourceFromCredentialsFlattensFormValues checks that single-valued
// []string metadata (from form-encoded token responses) is exposed as plain
// strings, as golang.org/x/oauth2 did.
func TestTokenSourceFromCredentialsFlattensFormValues(t *testing.T) {
	cached := &auth.Token{
		Value: "test-access-token",
		Type:  "Bearer",
		Metadata: map[string]interface{}{
			"refresh_token": []string{"form-refresh-token"},
			"id_token":      []string{"form-id-token"},
			"scope":         []string{"scope1 scope2"},
			"multi":         []string{"a", "b"},
		},
	}
	creds := auth.NewCredentials(&auth.CredentialsOptions{TokenProvider: fakeTokenProvider{tok: cached}})

	got, err := tokenSourceFromCredentials(t.Context(), creds).Token()
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if got.RefreshToken != "form-refresh-token" {
		t.Errorf("Token().RefreshToken = %q, want %q", got.RefreshToken, "form-refresh-token")
	}
	if v := got.Extra("id_token"); v != "form-id-token" {
		t.Errorf("Token().Extra(%q) = %#v, want %q", "id_token", v, "form-id-token")
	}
	if v, ok := got.Extra("multi").([]string); !ok || len(v) != 2 {
		t.Errorf("Token().Extra(%q) = %#v, want []string{\"a\", \"b\"}", "multi", got.Extra("multi"))
	}
	if _, err := MarshalWithExtras(got, ""); err != nil {
		t.Errorf("MarshalWithExtras() unexpected error: %v", err)
	}
	if _, ok := cached.Metadata["id_token"].([]string); !ok {
		t.Errorf("cached token metadata was modified: %#v", cached.Metadata)
	}
}

// TestFetchTokenFormEncodedResponse checks a form-encoded token endpoint
// end to end through FetchToken and MarshalWithExtras.
func TestFetchTokenFormEncodedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		fmt.Fprint(w, "access_token=test-access-token&token_type=Bearer&expires_in=3600&refresh_token=new-refresh-token&id_token=form-id-token")
	}))
	t.Cleanup(srv.Close)
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: authorizedUserJSON(srv.URL), Scope: "scope1"}

	tok, err := FetchToken(t.Context(), settings)
	if err != nil {
		t.Fatalf("FetchToken() unexpected error: %v", err)
	}
	if tok.AccessToken != "test-access-token" {
		t.Errorf("FetchToken().AccessToken = %q, want %q", tok.AccessToken, "test-access-token")
	}
	if tok.RefreshToken != "new-refresh-token" {
		t.Errorf("FetchToken().RefreshToken = %q, want %q", tok.RefreshToken, "new-refresh-token")
	}
	b, err := MarshalWithExtras(tok, "")
	if err != nil {
		t.Fatalf("MarshalWithExtras() unexpected error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal(MarshalWithExtras()) unexpected error: %v", err)
	}
	if m["id_token"] != "form-id-token" {
		t.Errorf("MarshalWithExtras() id_token = %#v, want %q", m["id_token"], "form-id-token")
	}
}

func TestNewDetectOptionsForRefreshTiming(t *testing.T) {
	settings := &Settings{Scope: "scope1"}

	legacy := newDetectOptionsFor(t.Context(), settings, false, legacyCredentialsOptions)
	if legacy.EarlyTokenRefresh != legacyEarlyTokenRefresh || !legacy.DisableAsyncRefresh {
		t.Errorf("legacy options: EarlyTokenRefresh = %v, DisableAsyncRefresh = %v, want %v, true",
			legacy.EarlyTokenRefresh, legacy.DisableAsyncRefresh, legacyEarlyTokenRefresh)
	}
	current := newDetectOptionsFor(t.Context(), settings, false, authCredentialsOptions)
	if current.EarlyTokenRefresh != 0 || current.DisableAsyncRefresh {
		t.Errorf("auth options: EarlyTokenRefresh = %v, DisableAsyncRefresh = %v, want library defaults (0, false)",
			current.EarlyTokenRefresh, current.DisableAsyncRefresh)
	}
}

// TestOAuthJSONTokenSourceLegacyRefreshTiming checks that a token that
// expires in 60 seconds is reused, as with golang.org/x/oauth2 (10s early
// refresh), instead of being refreshed (cloud.google.com/go/auth defaults to
// 225s).
func TestOAuthJSONTokenSourceLegacyRefreshTiming(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 60}`)
	}))
	t.Cleanup(srv.Close)
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: authorizedUserJSON(srv.URL), Scope: "scope1"}

	ts, err := OAuthJSONTokenSource(t.Context(), settings)
	if err != nil {
		t.Fatalf("OAuthJSONTokenSource() unexpected error: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ts.Token(); err != nil {
			t.Fatalf("Token() call %d unexpected error: %v", i, err)
		}
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("token requests = %d, want 1", got)
	}
}

func clientSecretJSON(tokenURI string) string {
	return fmt.Sprintf(`{
  "installed": {
    "client_id": "test-client.apps.googleusercontent.com",
    "client_secret": "test-secret",
    "redirect_uris": ["http://localhost"],
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": %q
  }
}`, tokenURI)
}

// TestClientSecretWithoutAuthHandler checks that client secret files can be
// loaded without an authorization handler (as with golang.org/x/oauth2), and
// that fetching a token then fails with errNoAuthHandler instead of panicking.
func TestClientSecretWithoutAuthHandler(t *testing.T) {
	credsJSON := clientSecretJSON("https://oauth2.googleapis.com/token")
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: credsJSON, Scope: "scope1"}

	creds, err := FindJSONCredentials(t.Context(), settings)
	if err != nil {
		t.Fatalf("FindJSONCredentials() unexpected error: %v", err)
	}
	if string(creds.JSON) != credsJSON {
		t.Errorf("FindJSONCredentials().JSON = %s, want %s", creds.JSON, credsJSON)
	}
	if _, err := creds.TokenSource.Token(); !errors.Is(err, errNoAuthHandler) {
		t.Errorf("FindJSONCredentials().TokenSource.Token() error = %v, want %v", err, errNoAuthHandler)
	}

	authCreds, err := FindAuthCredentials(t.Context(), settings)
	if err != nil {
		t.Fatalf("FindAuthCredentials() unexpected error: %v", err)
	}
	if _, err := authCreds.Token(t.Context()); !errors.Is(err, errNoAuthHandler) {
		t.Errorf("FindAuthCredentials().Token() error = %v, want %v", err, errNoAuthHandler)
	}

	if _, err := FetchToken(t.Context(), settings); !errors.Is(err, errNoAuthHandler) {
		t.Errorf("FetchToken() error = %v, want %v", err, errNoAuthHandler)
	}
}

// TestFetchAuthTokenFormEncodedRefreshToken checks that FetchAuthToken
// normalizes form-encoded []string metadata to string so
// tok.MetadataString("refresh_token") returns the refresh token for both
// authorized_user and 3LO client secret flows, while still falling back to the
// refresh token in authorized_user credentials JSON when the response omits it.
func TestFetchAuthTokenFormEncodedRefreshToken(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		useClientSecret bool
		wantRefresh     string
		wantIDToken     string
	}{
		{
			name:        "rotated_refresh_token_is_kept",
			body:        "access_token=test-access-token&token_type=Bearer&expires_in=3600&refresh_token=rotated-refresh-token&id_token=form-id-token",
			wantRefresh: "rotated-refresh-token",
			wantIDToken: "form-id-token",
		},
		{
			name:        "missing_refresh_token_falls_back_to_credentials",
			body:        "access_token=test-access-token&token_type=Bearer&expires_in=3600",
			wantRefresh: testRefreshToken,
		},
		{
			name:            "3lo_client_secret_form_encoded_refresh_token",
			body:            "access_token=test-access-token&token_type=Bearer&expires_in=3600&refresh_token=3lo-form-refresh-token&id_token=3lo-form-id-token",
			useClientSecret: true,
			wantRefresh:     "3lo-form-refresh-token",
			wantIDToken:     "3lo-form-id-token",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
				fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(srv.Close)

			settings := &Settings{
				AuthType:        AuthTypeOAuth,
				CredentialsJSON: authorizedUserJSON(srv.URL),
				Scope:           "scope1",
			}
			if tc.useClientSecret {
				settings.CredentialsJSON = clientSecretJSON(srv.URL)
				settings.State = "state"
				settings.GoogleAuthHandler = func(authCodeURL string) (string, string, error) {
					return "auth-code", "state", nil
				}
			}

			tok, err := FetchAuthToken(t.Context(), settings)
			if err != nil {
				t.Fatalf("FetchAuthToken() unexpected error: %v", err)
			}
			if got := tok.MetadataString("refresh_token"); got != tc.wantRefresh {
				t.Errorf("FetchAuthToken().MetadataString(%q) = %q, want %q", "refresh_token", got, tc.wantRefresh)
			}
			if got := tok.MetadataString("id_token"); got != tc.wantIDToken {
				t.Errorf("FetchAuthToken().MetadataString(%q) = %q, want %q", "id_token", got, tc.wantIDToken)
			}
		})
	}
}
