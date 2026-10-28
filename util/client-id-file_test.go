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
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
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
			got := util.IsValidOauthClientIdFile(tc.json)
			if got != tc.want {
				t.Errorf("IsValidOauthClientIdFile() = %v, want %v", got, tc.want)
			}
			if tc.json != "" {
				// Parity check with cloud.google.com/go/auth/credentials.DetectDefault:
				// when AuthHandlerOptions is nil, DetectDefault returns "auth handler must
				// be specified for this credential filetype" iff its internal credsfile
				// parser recognizes the JSON as a 3LO client credentials file.
				_, err := credentials.DetectDefault(&credentials.DetectOptions{
					CredentialsJSON: []byte(tc.json),
					Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
				})
				goAuthRecognized := err != nil && strings.Contains(err.Error(), "auth handler must be specified for this credential filetype")
				if got != goAuthRecognized {
					t.Errorf("IsValidOauthClientIdFile() = %v, out of sync with credentials.DetectDefault (recognized=%v, err=%v)", got, goAuthRecognized, err)
				}
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
			if !tc.wantErr {
				// Parity check: verify credentials.DetectDefault extracts the exact
				// same redirect_uri via its internal credsfile parser.
				var capturedAuthCodeURL string
				errStop := errors.New("stop after capturing authCodeURL")
				creds, err := credentials.DetectDefault(&credentials.DetectOptions{
					CredentialsJSON: []byte(tc.json),
					Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
					AuthHandlerOptions: &auth.AuthorizationHandlerOptions{
						Handler: func(authCodeURL string) (string, string, error) {
							capturedAuthCodeURL = authCodeURL
							return "", "", errStop
						},
						State: "state",
					},
				})
				if err != nil {
					t.Fatalf("credentials.DetectDefault() unexpected error: %v", err)
				}
				_, _ = creds.Token(context.Background())
				parsedURL, err := url.Parse(capturedAuthCodeURL)
				if err != nil {
					t.Fatalf("url.Parse(%q) unexpected error: %v", capturedAuthCodeURL, err)
				}
				if goAuthURI := parsedURL.Query().Get("redirect_uri"); got != goAuthURI {
					t.Errorf("GetFirstRedirectURI() = %q, out of sync with credentials.DetectDefault redirect_uri %q", got, goAuthURI)
				}
			}
		})
	}
}
