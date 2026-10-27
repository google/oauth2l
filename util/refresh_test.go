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
package util_test

import (
	"encoding/json"
	"testing"

	"cloud.google.com/go/auth"
	"github.com/google/oauth2l/util"
	"golang.org/x/oauth2/google"
)

type parsedRefreshCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURL     string `json:"token_uri"`
	AuthURL      string `json:"auth_uri"`
	RefreshToken string `json:"refresh_token"`
	Type         string `json:"type"`
}

func assertRefreshTokenJSON(t *testing.T, got string, want *parsedRefreshCredentials) {
	t.Helper()
	if want == nil {
		if got != "" {
			t.Fatalf("got %q, want empty string", got)
		}
		return
	}
	var parsed parsedRefreshCredentials
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("failed to unmarshal refresh token JSON %q: %v", got, err)
	}
	if parsed != *want {
		t.Errorf("unmarshaled refresh token JSON = %+v, want %+v", parsed, *want)
	}
}

func TestBuildAuthRefreshTokenJSON(t *testing.T) {
	installedAuthCreds := auth.NewCredentials(&auth.CredentialsOptions{
		JSON: []byte(testInstalledClientIDJSON),
	})
	webAuthCreds := auth.NewCredentials(&auth.CredentialsOptions{
		JSON: []byte(testWebClientIDJSON),
	})
	invalidAuthCreds := auth.NewCredentials(&auth.CredentialsOptions{
		JSON: []byte(testServiceAccountJSON),
	})

	tests := []struct {
		name         string
		refreshToken string
		creds        *auth.Credentials
		want         *parsedRefreshCredentials
	}{
		{
			name:         "valid installed client credentials",
			refreshToken: "fake-refresh-token",
			creds:        installedAuthCreds,
			want: &parsedRefreshCredentials{
				ClientID:     "144169.apps.googleusercontent.com",
				ClientSecret: "awesomesecret",
				TokenURL:     "http://localhost:8080/token",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				RefreshToken: "fake-refresh-token",
				Type:         "authorized_user",
			},
		},
		{
			name:         "valid web client credentials",
			refreshToken: "fake-refresh-token",
			creds:        webAuthCreds,
			want: &parsedRefreshCredentials{
				ClientID:     "web-client.apps.googleusercontent.com",
				ClientSecret: "websecret",
				TokenURL:     "https://oauth2.googleapis.com/token",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				RefreshToken: "fake-refresh-token",
				Type:         "authorized_user",
			},
		},
		{
			name:         "empty refresh token",
			refreshToken: "",
			creds:        installedAuthCreds,
			want:         nil,
		},
		{
			name:         "nil credentials",
			refreshToken: "fake-refresh-token",
			creds:        nil,
			want:         nil,
		},
		{
			name:         "non-client credentials JSON",
			refreshToken: "fake-refresh-token",
			creds:        invalidAuthCreds,
			want:         nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := util.BuildAuthRefreshTokenJSON(tc.refreshToken, tc.creds)
			assertRefreshTokenJSON(t, got, tc.want)
		})
	}
}

func TestBuildRefreshTokenJSON(t *testing.T) {
	installedOAuth2Creds := &google.Credentials{
		JSON: []byte(testInstalledClientIDJSON),
	}
	webOAuth2Creds := &google.Credentials{
		JSON: []byte(testWebClientIDJSON),
	}
	invalidOAuth2Creds := &google.Credentials{
		JSON: []byte(testServiceAccountJSON),
	}

	tests := []struct {
		name         string
		refreshToken string
		creds        *google.Credentials
		want         *parsedRefreshCredentials
	}{
		{
			name:         "valid installed client credentials",
			refreshToken: "fake-refresh-token",
			creds:        installedOAuth2Creds,
			want: &parsedRefreshCredentials{
				ClientID:     "144169.apps.googleusercontent.com",
				ClientSecret: "awesomesecret",
				TokenURL:     "http://localhost:8080/token",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				RefreshToken: "fake-refresh-token",
				Type:         "authorized_user",
			},
		},
		{
			name:         "valid web client credentials",
			refreshToken: "fake-refresh-token",
			creds:        webOAuth2Creds,
			want: &parsedRefreshCredentials{
				ClientID:     "web-client.apps.googleusercontent.com",
				ClientSecret: "websecret",
				TokenURL:     "https://oauth2.googleapis.com/token",
				AuthURL:      "https://accounts.google.com/o/oauth2/auth",
				RefreshToken: "fake-refresh-token",
				Type:         "authorized_user",
			},
		},
		{
			name:         "empty refresh token",
			refreshToken: "",
			creds:        installedOAuth2Creds,
			want:         nil,
		},
		{
			name:         "nil credentials",
			refreshToken: "fake-refresh-token",
			creds:        nil,
			want:         nil,
		},
		{
			name:         "non-client credentials JSON",
			refreshToken: "fake-refresh-token",
			creds:        invalidOAuth2Creds,
			want:         nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := util.BuildRefreshTokenJSON(tc.refreshToken, tc.creds)
			assertRefreshTokenJSON(t, got, tc.want)
		})
	}
}
