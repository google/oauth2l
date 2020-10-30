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
	"context"
	"encoding/json"

	"github.com/google/oauth2l/sgauth"
	"github.com/google/oauth2l/sgauth/credentials"
)

type refreshCredentialsJSON struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	TokenURL     string `json:"token_uri,omitempty"`
	AuthURL      string `json:"auth_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Type         string `json:"type,omitempty"`
}

// BuildRefreshTokenJSON attempts to construct a gcloud refresh token JSON
// using a refreshToken and an OAuth Client ID Credentials object.
// Empty string is returned if this is not possible.
func BuildRefreshTokenJSON(refreshToken string, creds *credentials.Credentials) string {
	if refreshToken == "" {
		return ""
	}
	if creds == nil || creds.Type != credentials.OAuthClientKey {
		return ""
	}

	var credsFile credentials.File
	if err := json.Unmarshal(creds.JSON, &credsFile); err != nil {
		return ""
	}
	var oauth credentials.OAuthClient
	if credsFile.Web.ProjectID != "" {
		oauth = credsFile.Web
	} else {
		oauth = credsFile.Installed
	}
	if oauth.ClientID == "" || oauth.ClientSecret == "" {
		return ""
	}
	var refreshCredentials refreshCredentialsJSON
	refreshCredentials.ClientID = oauth.ClientID
	refreshCredentials.ClientSecret = oauth.ClientSecret
	refreshCredentials.TokenURL = oauth.TokenURL
	refreshCredentials.AuthURL = oauth.AuthURL
	refreshCredentials.RefreshToken = refreshToken
	refreshCredentials.Type = credentials.UserCredentialsKey
	refreshCredentialsJSON, _ := json.Marshal(refreshCredentials)
	return string(refreshCredentialsJSON)
}

// LoadCredentials returns the user specified credentials as a Credentials object.
// If credentials are not specified by the user, attempt to use application default
// credentials instead. Returns nil if no credentials can be loaded.
func LoadCredentials(settings *sgauth.Settings) *credentials.Credentials {
	creds, err := sgauth.FindJSONCredentials(context.Background(), settings)
	if err != nil {
		return nil
	}
	return creds
}
