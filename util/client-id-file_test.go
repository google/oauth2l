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
	"testing"

	"github.com/google/oauth2l/util"
)

const (
	testInstalledClientIDJSON = `{
  "installed": {
    "client_id": "144169.apps.googleusercontent.com",
    "project_id": "test-project",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "http://localhost:8080/token",
    "client_secret": "awesomesecret",
    "redirect_uris": [
      "urn:ietf:wg:oauth:2.0:oob",
      "http://localhost"
    ]
  }
}`

	testWebClientIDJSON = `{
  "web": {
    "client_id": "web-client.apps.googleusercontent.com",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_secret": "websecret",
    "redirect_uris": [
      "http://localhost:8080/callback"
    ]
  }
}`

	testBothWebAndInstalledClientIDJSON = `{
  "web": {
    "client_id": "web-client.apps.googleusercontent.com",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_secret": "websecret",
    "redirect_uris": [
      "http://localhost:8080/web-callback"
    ]
  },
  "installed": {
    "client_id": "144169.apps.googleusercontent.com",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "http://localhost:8080/token",
    "client_secret": "awesomesecret",
    "redirect_uris": [
      "urn:ietf:wg:oauth:2.0:oob"
    ]
  }
}`

	testMissingRedirectURIsJSON = `{
  "installed": {
    "client_id": "144169.apps.googleusercontent.com",
    "client_secret": "awesomesecret"
  }
}`

	testEmptyRedirectURIsJSON = `{
  "installed": {
    "client_id": "144169.apps.googleusercontent.com",
    "client_secret": "awesomesecret",
    "redirect_uris": []
  }
}`

	testServiceAccountJSON = `{
  "type": "service_account",
  "project_id": "test-project",
  "client_email": "test@test-project.iam.gserviceaccount.com"
}`
)

func TestIsValidOauthClientIdFile(t *testing.T) {
	tests := []struct {
		name string
		json string
		want bool
	}{
		{
			name: "valid installed client credentials",
			json: testInstalledClientIDJSON,
			want: true,
		},
		{
			name: "valid web client credentials",
			json: testWebClientIDJSON,
			want: true,
		},
		{
			name: "both web and installed present",
			json: testBothWebAndInstalledClientIDJSON,
			want: true,
		},
		{
			name: "empty string",
			json: "",
			want: false,
		},
		{
			name: "invalid JSON",
			json: "{not-json",
			want: false,
		},
		{
			name: "missing redirect_uris",
			json: testMissingRedirectURIsJSON,
			want: false,
		},
		{
			name: "empty redirect_uris slice",
			json: testEmptyRedirectURIsJSON,
			want: false,
		},
		{
			name: "non-client credentials JSON",
			json: testServiceAccountJSON,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := util.IsValidOauthClientIdFile(tc.json); got != tc.want {
				t.Errorf("IsValidOauthClientIdFile() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetFirstRedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantURI string
		wantErr bool
	}{
		{
			name:    "installed client returns first redirect URI",
			json:    testInstalledClientIDJSON,
			wantURI: "urn:ietf:wg:oauth:2.0:oob",
			wantErr: false,
		},
		{
			name:    "web client returns first redirect URI",
			json:    testWebClientIDJSON,
			wantURI: "http://localhost:8080/callback",
			wantErr: false,
		},
		{
			name:    "both web and installed present prefers web",
			json:    testBothWebAndInstalledClientIDJSON,
			wantURI: "http://localhost:8080/web-callback",
			wantErr: false,
		},
		{
			name:    "invalid JSON returns error",
			json:    "{not-json",
			wantURI: "",
			wantErr: true,
		},
		{
			name:    "missing redirect_uris returns error",
			json:    testMissingRedirectURIsJSON,
			wantURI: "",
			wantErr: true,
		},
		{
			name:    "empty redirect_uris slice returns error",
			json:    testEmptyRedirectURIsJSON,
			wantURI: "",
			wantErr: true,
		},
		{
			name:    "non-client credentials returns error",
			json:    testServiceAccountJSON,
			wantURI: "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := util.GetFirstRedirectURI(tc.json)
			if (err != nil) != tc.wantErr {
				t.Fatalf("GetFirstRedirectURI() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.wantURI {
				t.Errorf("GetFirstRedirectURI() = %q, want %q", got, tc.wantURI)
			}
		})
	}
}
