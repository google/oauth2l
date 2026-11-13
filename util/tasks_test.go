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
	"net/http"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name  string
		token *auth.Token
		want  bool
	}{
		{
			name: "nil_token",
		},
		{
			name:  "zero_expiry",
			token: &auth.Token{Value: "sso-token"},
		},
		{
			name:  "future_expiry",
			token: &auth.Token{Value: "valid-token", Expiry: time.Now().Add(time.Hour)},
		},
		{
			name:  "past_expiry",
			token: &auth.Token{Value: "expired-token", Expiry: time.Now().Add(-time.Hour)},
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTokenExpired(tc.token); got != tc.want {
				t.Errorf("isTokenExpired(%+v) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

func TestGetCredentialTypeNilCredentials(t *testing.T) {
	if got := getCredentialType(nil); got != "" {
		t.Errorf("getCredentialType(nil) = %q, want \"\"", got)
	}
}

// TestFetchTokenUsesContext checks that fetchToken passes its context to the
// token request instead of using context.Background().
func TestFetchTokenUsesContext(t *testing.T) {
	srv := newTokenServer(t, http.StatusOK, `{"access_token": "fake-access-token", "token_type": "Bearer", "expires_in": 3600}`)
	oldCacheLocation := CacheLocation
	CacheLocation = ""
	t.Cleanup(func() { CacheLocation = oldCacheLocation })
	settings := &Settings{AuthType: AuthTypeOAuth, CredentialsJSON: authorizedUserJSON(srv.URL), Scope: DefaultScope}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tok := fetchToken(ctx, settings, &TaskSettings{}); tok != nil {
		t.Errorf("fetchToken() with a canceled context = %+v, want nil", tok)
	}

	tok := fetchToken(context.Background(), settings, &TaskSettings{})
	if tok == nil || tok.Value != "fake-access-token" {
		t.Errorf("fetchToken() = %+v, want token %q", tok, "fake-access-token")
	}
}

