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
	"reflect"
	"strings"
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

// jwtClaims decodes the (unverified) claims of a JWT.
func jwtClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q is not a JWT", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding JWT claims: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatalf("unmarshaling JWT claims: %v", err)
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
			name:       "nil settings use DefaultScope",
			settings:   nil,
			wantScopes: []string{DefaultScope},
		},
		{
			name:       "OAuth splits space-delimited scopes",
			settings:   &Settings{Scope: "scope1 scope2"},
			wantScopes: []string{"scope1", "scope2"},
		},
		{
			name:       "OAuth ignores audience when both scope and audience set",
			settings:   &Settings{Scope: "scope1", Audience: "https://sts.googleapis.com"},
			wantScopes: []string{"scope1"},
		},
		{
			name:             "JWT prefers audience over scope",
			settings:         &Settings{Scope: "scope1", Audience: "https://example.googleapis.com/"},
			useSelfSignedJWT: true,
			wantAudience:     "https://example.googleapis.com/",
		},
		{
			name:             "JWT falls back to scope",
			settings:         &Settings{Scope: "scope1"},
			useSelfSignedJWT: true,
			wantScopes:       []string{"scope1"},
		},
		{
			name:         "authorized_user token_uri forwarded to TokenURL",
			settings:     &Settings{Scope: "scope1", CredentialsJSON: authorizedUserJSON("http://localhost:8080/token")},
			wantScopes:   []string{"scope1"},
			wantTokenURL: "http://localhost:8080/token",
		},
		{
			name:       "token_uri of other credential types is not forwarded",
			settings:   &Settings{Scope: "scope1", CredentialsJSON: `{"type": "service_account", "token_uri": "http://localhost:8080/token"}`},
			wantScopes: []string{"scope1"},
		},
		{
			name:        "email used as subject",
			settings:    &Settings{Scope: "scope1", Email: "user@example.com"},
			wantScopes:  []string{"scope1"},
			wantSubject: "user@example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := newDetectOptions(tc.settings, tc.useSelfSignedJWT)
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
		wantNil   bool
		wantCode  string
		wantState string
	}{
		{
			name:     "no handler leaves AuthHandlerOptions unset",
			settings: &Settings{Scope: "scope1"},
			wantNil:  true,
		},
		{
			name:      "GoogleAuthHandler with default state",
			settings:  &Settings{Scope: "scope1", GoogleAuthHandler: handler},
			wantCode:  "code",
			wantState: defaultAuthState,
		},
		{
			name:      "deprecated AuthHandler with custom state",
			settings:  &Settings{Scope: "scope1", AuthHandler: legacyHandler, State: "custom-state"},
			wantCode:  "legacy-code",
			wantState: "custom-state",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newDetectOptions(tc.settings, false).AuthHandlerOptions
			if tc.wantNil {
				if got != nil {
					t.Errorf("AuthHandlerOptions = %+v, want nil", got)
				}
				return
			}
			if got == nil || got.Handler == nil {
				t.Fatal("AuthHandlerOptions.Handler = nil, want non-nil")
			}
			if code, _, _ := got.Handler(""); code != tc.wantCode {
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
		tok, err := FetchAuthToken(context.Background(), s)
		if err != nil || tok != nil {
			t.Errorf("FetchAuthToken(%+v) = (%v, %v), want (nil, nil)", s, tok, err)
		}
		oauth2Tok, err := FetchToken(context.Background(), s)
		if err != nil || oauth2Tok != nil {
			t.Errorf("FetchToken(%+v) = (%v, %v), want (nil, nil)", s, oauth2Tok, err)
		}
	}
}

func TestFetchAuthTokenUnsupportedAuthType(t *testing.T) {
	_, err := FetchAuthToken(context.Background(), &Settings{AuthType: AuthTypeSSO})
	if err == nil || !strings.Contains(err.Error(), "Unsupported authentcation method: sso") {
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
			name:             "refresh token kept from credentials when omitted in response",
			response:         `{"access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600, "scope": "scope1", "id_token": "test-id-token"}`,
			wantRefreshToken: testRefreshToken,
		},
		{
			name:             "rotated refresh token from response is used",
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

			tok, err := FetchAuthToken(context.Background(), settings)
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
			oauth2Tok, err := FetchToken(context.Background(), settings)
			if err != nil {
				t.Fatalf("FetchToken() unexpected error: %v", err)
			}
			ts, err := OAuthJSONTokenSource(context.Background(), settings)
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
				var m map[string]interface{}
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

	_, err := FetchAuthToken(context.Background(), settings)
	var authErr *auth.Error
	if !errors.As(err, &authErr) {
		t.Fatalf("FetchAuthToken() error = %v, want *auth.Error", err)
	}

	_, err = FetchToken(context.Background(), settings)
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		t.Fatalf("FetchToken() error = %v, want *oauth2.RetrieveError in chain", err)
	}
	if retrieveErr.ErrorCode != "invalid_grant" {
		t.Errorf("RetrieveError.ErrorCode = %q, want %q", retrieveErr.ErrorCode, "invalid_grant")
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
			name:         "audience takes precedence over scope",
			settings:     &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON, Audience: "https://pubsub.googleapis.com/", Scope: "scope1"},
			wantAudience: "https://pubsub.googleapis.com/",
		},
		{
			name:      "scope only",
			settings:  &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON, Scope: "scope1 scope2"},
			wantScope: "scope1 scope2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := FetchAuthToken(context.Background(), tc.settings)
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

			ts, err := JWTTokenSource(context.Background(), tc.settings)
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
	tests := []struct {
		name     string
		settings *Settings
		wantErr  string
	}{
		{
			name:     "neither audience nor scope",
			settings: &Settings{AuthType: AuthTypeJWT, CredentialsJSON: saJSON},
			wantErr:  "Neither audience nor scope is provided",
		},
		{
			name:     "non service account credentials",
			settings: &Settings{AuthType: AuthTypeJWT, CredentialsJSON: authorizedUserJSON("http://localhost/token"), Audience: "aud"},
			wantErr:  `self-signed JWT requires "service_account" credentials, got "authorized_user"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := JWTTokenProvider(context.Background(), tc.settings); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("JWTTokenProvider() error = %v, want error containing %q", err, tc.wantErr)
			}
			if _, err := JWTTokenSource(context.Background(), tc.settings); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("JWTTokenSource() error = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestFindJSONCredentialsPreservesJSONAndProjectID(t *testing.T) {
	saJSON := serviceAccountJSON(t)
	settings := &Settings{CredentialsJSON: saJSON, Scope: "scope1"}

	authCreds, err := FindAuthCredentials(context.Background(), settings)
	if err != nil {
		t.Fatalf("FindAuthCredentials() unexpected error: %v", err)
	}
	if string(authCreds.JSON()) != saJSON {
		t.Errorf("FindAuthCredentials().JSON() = %s, want %s", authCreds.JSON(), saJSON)
	}

	creds, err := FindJSONCredentials(context.Background(), settings)
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
