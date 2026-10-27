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
	"testing"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2/authhandler"
)

func TestResolveAuthHandler(t *testing.T) {
	googleHandler := auth.AuthorizationHandler(func(url string) (string, string, error) {
		return "google-code", "google-state", nil
	})
	legacyHandler := authhandler.AuthorizationHandler(func(url string) (string, string, error) {
		return "legacy-code", "legacy-state", nil
	})

	t.Run("prefers GoogleAuthHandler when set", func(t *testing.T) {
		s := Settings{
			GoogleAuthHandler: googleHandler,
			AuthHandler:       legacyHandler,
		}
		h := s.resolveAuthHandler()
		if h == nil {
			t.Fatal("resolveAuthHandler() = nil, want non-nil")
		}
		code, state, err := h("https://accounts.google.com/o/oauth2/auth")
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}
		if code != "google-code" || state != "google-state" {
			t.Errorf("handler() = (%q, %q), want (%q, %q)", code, state, "google-code", "google-state")
		}
	})

	t.Run("falls back to deprecated AuthHandler when GoogleAuthHandler is nil", func(t *testing.T) {
		s := Settings{
			AuthHandler: legacyHandler,
		}
		h := s.resolveAuthHandler()
		if h == nil {
			t.Fatal("resolveAuthHandler() = nil, want non-nil")
		}
		code, state, err := h("https://accounts.google.com/o/oauth2/auth")
		if err != nil {
			t.Fatalf("handler returned unexpected error: %v", err)
		}
		if code != "legacy-code" || state != "legacy-state" {
			t.Errorf("handler() = (%q, %q), want (%q, %q)", code, state, "legacy-code", "legacy-state")
		}
	})

	t.Run("returns nil when neither handler is set", func(t *testing.T) {
		var s Settings
		if h := s.resolveAuthHandler(); h != nil {
			t.Errorf("resolveAuthHandler() = %v, want nil", h)
		}
	})
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
