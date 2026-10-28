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
	"errors"
	"testing"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2/authhandler"
)

func TestResolveAuthHandler(t *testing.T) {
	googleHandler := auth.AuthorizationHandler(func(string) (string, string, error) {
		return "google-code", "google-state", nil
	})
	legacyHandler := authhandler.AuthorizationHandler(func(string) (string, string, error) {
		return "legacy-code", "legacy-state", nil
	})

	tests := []struct {
		name                string
		settings            Settings
		wantCode, wantState string
	}{
		{
			name:      "prefers GoogleAuthHandler when both set",
			settings:  Settings{GoogleAuthHandler: googleHandler, AuthHandler: legacyHandler},
			wantCode:  "google-code",
			wantState: "google-state",
		},
		{
			name:      "uses GoogleAuthHandler when only GoogleAuthHandler set",
			settings:  Settings{GoogleAuthHandler: googleHandler},
			wantCode:  "google-code",
			wantState: "google-state",
		},
		{
			name:      "falls back to deprecated AuthHandler",
			settings:  Settings{AuthHandler: legacyHandler},
			wantCode:  "legacy-code",
			wantState: "legacy-state",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.settings.resolveAuthHandler()
			if h == nil {
				t.Fatal("resolveAuthHandler() = nil, want non-nil")
			}
			code, state, err := h("https://accounts.google.com/o/oauth2/auth")
			if err != nil {
				t.Fatalf("handler returned unexpected error: %v", err)
			}
			if code != tc.wantCode || state != tc.wantState {
				t.Errorf("handler() = (%q, %q), want (%q, %q)", code, state, tc.wantCode, tc.wantState)
			}
		})
	}
}

func TestResolveAuthHandlerUnset(t *testing.T) {
	var s Settings
	if h := s.resolveAuthHandler(); h != nil {
		t.Errorf("resolveAuthHandler() = %v, want nil", h)
	}
}

func TestFindJSONCredentialsHonorsGoogleAuthHandler(t *testing.T) {
	wantErr := errors.New("stop after handler invoked")
	called := false
	s := &Settings{
		CredentialsJSON: `{
  "installed": {
    "client_id": "test-client.apps.googleusercontent.com",
    "client_secret": "test-secret",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "redirect_uris": ["http://localhost"]
  }
}`,
		Scope: "https://www.googleapis.com/auth/cloud-platform",
		GoogleAuthHandler: func(authCodeURL string) (string, string, error) {
			called = true
			return "", "", wantErr
		},
	}

	creds, err := FindJSONCredentials(context.Background(), s)
	if err != nil {
		t.Fatalf("FindJSONCredentials() unexpected error: %v", err)
	}
	_, err = creds.TokenSource.Token()
	if !called {
		t.Fatal("expected GoogleAuthHandler to be invoked by TokenSource.Token()")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("TokenSource.Token() error = %v, want %v", err, wantErr)
	}
}

func TestGetAuthType(t *testing.T) {
	tests := []struct {
		name     string
		settings Settings
		want     string
	}{
		{
			name:     "explicit AuthType takes precedence",
			settings: Settings{AuthType: AuthTypeSSO, APIKey: "key", Scope: "scope"},
			want:     AuthTypeSSO,
		},
		{
			name:     "APIKey selects apikey auth type",
			settings: Settings{APIKey: "my-api-key"},
			want:     AuthTypeAPIKey,
		},
		{
			name:     "Scope selects oauth auth type",
			settings: Settings{Scope: "https://www.googleapis.com/auth/cloud-platform"},
			want:     AuthTypeOAuth,
		},
		{
			name:     "defaults to jwt auth type",
			settings: Settings{Audience: "https://example.googleapis.com/"},
			want:     AuthTypeJWT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.settings.GetAuthType(); got != tc.want {
				t.Errorf("GetAuthType() = %q, want %q", got, tc.want)
			}
		})
	}
}
