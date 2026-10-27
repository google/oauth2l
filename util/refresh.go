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
	"encoding/json"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/oauth2adapt"
	"golang.org/x/oauth2/google"
)

type refreshCredentialsJSON struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	TokenURL     string `json:"token_uri,omitempty"`
	AuthURL      string `json:"auth_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Type         string `json:"type,omitempty"`
}

// BuildAuthRefreshTokenJSON attempts to construct a gcloud refresh token JSON
// using a refreshToken and an OAuth Client ID auth.Credentials object.
// Empty string is returned if this is not possible.
func BuildAuthRefreshTokenJSON(refreshToken string, creds *auth.Credentials) string {
	if refreshToken == "" || creds == nil {
		return ""
	}
	clientConfig, err := parseClientCreds(creds.JSON())
	if err != nil {
		return ""
	}
	var refreshCredentials refreshCredentialsJSON
	refreshCredentials.ClientID = clientConfig.ClientID
	refreshCredentials.ClientSecret = clientConfig.ClientSecret
	refreshCredentials.TokenURL = clientConfig.TokenURI
	refreshCredentials.AuthURL = clientConfig.AuthURI
	refreshCredentials.RefreshToken = refreshToken
	refreshCredentials.Type = "authorized_user"
	refreshJSON, _ := json.Marshal(refreshCredentials)
	return string(refreshJSON)
}

// BuildRefreshTokenJSON attempts to construct a gcloud refresh token JSON
// using a refreshToken and an OAuth Client ID Credentials object.
// Empty string is returned if this is not possible.
//
// Deprecated: Use BuildAuthRefreshTokenJSON instead.
func BuildRefreshTokenJSON(refreshToken string, creds *google.Credentials) string {
	return BuildAuthRefreshTokenJSON(refreshToken, oauth2adapt.AuthCredentialsFromOauth2Credentials(creds))
}
