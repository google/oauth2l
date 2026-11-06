//
// Copyright 2024 Google Inc.
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

	tok, err := GenerateServiceAccountAuthToken("source-token", "sa@project.iam.gserviceaccount.com", "scope1 scope2")
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
	wantExpiry := time.Date(2026, time.November, 4, 18, 0, 0, 0, time.UTC)
	if !tok.Expiry.Equal(wantExpiry) {
		t.Errorf("GenerateServiceAccountAuthToken().Expiry = %v, want %v", tok.Expiry, wantExpiry)
	}

	legacyTok, err := GenerateServiceAccountAccessToken("source-token", "sa@project.iam.gserviceaccount.com", "scope1 scope2")
	if err != nil {
		t.Fatalf("GenerateServiceAccountAccessToken() unexpected error: %v", err)
	}
	if legacyTok.AccessToken != "impersonated-token" || !legacyTok.Expiry.Equal(wantExpiry) {
		t.Errorf("GenerateServiceAccountAccessToken() = %+v, want AccessToken=%q Expiry=%v", legacyTok, "impersonated-token", wantExpiry)
	}
}
