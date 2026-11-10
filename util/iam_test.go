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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGenerateServiceAccountAuthToken(t *testing.T) {
	var gotAuthHeader string
	var gotPath string
	var gotScopes []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() unexpected error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotScopes = r.PostForm["scope"]
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"accessToken":"impersonated-token","expireTime":"2026-11-04T18:00:00Z"}`)
	}))
	t.Cleanup(srv.Close)

	origURL := iamAccessTokenURL
	t.Cleanup(func() {
		iamAccessTokenURL = origURL
	})
	iamAccessTokenURL = srv.URL + "/v1/projects/-/serviceAccounts/%s:generateAccessToken"

	tok, err := GenerateServiceAccountAuthToken(t.Context(), "source-token", "sa@project.iam.gserviceaccount.com", "scope1 scope2")
	if err != nil {
		t.Fatalf("GenerateServiceAccountAuthToken() unexpected error: %v", err)
	}
	if gotAuthHeader != "Bearer source-token" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer source-token")
	}
	wantPath := "/v1/projects/-/serviceAccounts/sa@project.iam.gserviceaccount.com:generateAccessToken"
	if gotPath != wantPath {
		t.Errorf("request path = %q, want %q", gotPath, wantPath)
	}
	if wantScopes := []string{"scope1", "scope2"}; !reflect.DeepEqual(gotScopes, wantScopes) {
		t.Errorf("scopes = %v, want %v", gotScopes, wantScopes)
	}
	if tok.Value != "impersonated-token" {
		t.Errorf("GenerateServiceAccountAuthToken().Value = %q, want %q", tok.Value, "impersonated-token")
	}
	if tok.Type != "Bearer" {
		t.Errorf("GenerateServiceAccountAuthToken().Type = %q, want %q", tok.Type, "Bearer")
	}
	wantExpiry := time.Date(2026, time.November, 4, 18, 0, 0, 0, time.UTC)
	if !tok.Expiry.Equal(wantExpiry) {
		t.Errorf("GenerateServiceAccountAuthToken().Expiry = %v, want %v", tok.Expiry, wantExpiry)
	}

	legacyTok, err := GenerateServiceAccountAccessToken("source-token", "sa@project.iam.gserviceaccount.com", "scope1 scope2")
	if err != nil {
		t.Fatalf("GenerateServiceAccountAccessToken() unexpected error: %v", err)
	}
	if legacyTok.AccessToken != "impersonated-token" || legacyTok.TokenType != "" || !legacyTok.Expiry.Equal(wantExpiry) {
		t.Errorf("GenerateServiceAccountAccessToken() = %+v, want AccessToken=%q TokenType=\"\" Expiry=%v", legacyTok, "impersonated-token", wantExpiry)
	}
}

func TestGenerateServiceAccountAuthTokenErrors(t *testing.T) {
	t.Run("non_2xx_status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":{"message":"permission denied"}}`)
		}))
		t.Cleanup(srv.Close)

		origURL := iamAccessTokenURL
		t.Cleanup(func() { iamAccessTokenURL = origURL })
		iamAccessTokenURL = srv.URL + "/%s"

		_, err := GenerateServiceAccountAuthToken(t.Context(), "source-token", "sa@project.iam.gserviceaccount.com", "scope1")
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("GenerateServiceAccountAuthToken() error = %v, want error containing %q", err, "permission denied")
		}
	})

	t.Run("invalid_json_response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `not-json`)
		}))
		t.Cleanup(srv.Close)

		origURL := iamAccessTokenURL
		t.Cleanup(func() { iamAccessTokenURL = origURL })
		iamAccessTokenURL = srv.URL + "/%s"

		if _, err := GenerateServiceAccountAuthToken(t.Context(), "source-token", "sa@project.iam.gserviceaccount.com", "scope1"); err == nil {
			t.Error("GenerateServiceAccountAuthToken() error = nil, want non-nil JSON error")
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if _, err := GenerateServiceAccountAuthToken(ctx, "source-token", "sa@project.iam.gserviceaccount.com", "scope1"); !errors.Is(err, context.Canceled) {
			t.Errorf("GenerateServiceAccountAuthToken() error = %v, want %v", err, context.Canceled)
		}
	})
}
