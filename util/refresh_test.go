//
// Copyright 2020 Google Inc.
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
	"golang.org/x/oauth2/google"
)

const wantInstalledRefreshJSON = `{"client_id":"144169.apps.googleusercontent.com","client_secret":"awesomesecret","token_uri":"http://localhost:8080/token","auth_uri":"https://accounts.google.com/o/oauth2/auth","refresh_token":"fake-refresh-token","type":"authorized_user"}`

func TestBuildAuthRefreshTokenJSON(t *testing.T) {
	validAuthCreds := auth.NewCredentials(&auth.CredentialsOptions{
		JSON: []byte(testInstalledClientIDJSON),
	})
	invalidAuthCreds := auth.NewCredentials(&auth.CredentialsOptions{
		JSON: []byte(testServiceAccountJSON),
	})

	tests := []struct {
		name         string
		refreshToken string
		creds        *auth.Credentials
		want         string
	}{
		{
			name:         "valid installed client credentials",
			refreshToken: "fake-refresh-token",
			creds:        validAuthCreds,
			want:         wantInstalledRefreshJSON,
		},
		{
			name:         "empty refresh token",
			refreshToken: "",
			creds:        validAuthCreds,
			want:         "",
		},
		{
			name:         "nil credentials",
			refreshToken: "fake-refresh-token",
			creds:        nil,
			want:         "",
		},
		{
			name:         "non-client credentials JSON",
			refreshToken: "fake-refresh-token",
			creds:        invalidAuthCreds,
			want:         "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildAuthRefreshTokenJSON(tc.refreshToken, tc.creds); got != tc.want {
				t.Errorf("BuildAuthRefreshTokenJSON() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildRefreshTokenJSON(t *testing.T) {
	validOAuth2Creds := &google.Credentials{
		JSON: []byte(testInstalledClientIDJSON),
	}
	invalidOAuth2Creds := &google.Credentials{
		JSON: []byte(testServiceAccountJSON),
	}

	tests := []struct {
		name         string
		refreshToken string
		creds        *google.Credentials
		want         string
	}{
		{
			name:         "valid installed client credentials",
			refreshToken: "fake-refresh-token",
			creds:        validOAuth2Creds,
			want:         wantInstalledRefreshJSON,
		},
		{
			name:         "empty refresh token",
			refreshToken: "",
			creds:        validOAuth2Creds,
			want:         "",
		},
		{
			name:         "nil credentials",
			refreshToken: "fake-refresh-token",
			creds:        nil,
			want:         "",
		},
		{
			name:         "non-client credentials JSON",
			refreshToken: "fake-refresh-token",
			creds:        invalidOAuth2Creds,
			want:         "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildRefreshTokenJSON(tc.refreshToken, tc.creds); got != tc.want {
				t.Errorf("BuildRefreshTokenJSON() = %q, want %q", got, tc.want)
			}
		})
	}
}
