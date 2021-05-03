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

// BuildRefreshTokenJSON attempts to construct a gcloud refresh token JSON
// using a refreshToken and an OAuth Client ID Credentials object.
// Empty string is returned if this is not possible.
func BuildRefreshTokenJSON(refreshToken string, creds *google.Credentials) string {
	if refreshToken == "" {
		return ""
	}
	oauth2Config, err := google.ConfigFromJSON(creds.JSON)
	if err != nil {
		return ""
	}
	var refreshCredentials refreshCredentialsJSON
	refreshCredentials.ClientID = oauth2Config.ClientID
	refreshCredentials.ClientSecret = oauth2Config.ClientSecret
	refreshCredentials.TokenURL = oauth2Config.Endpoint.TokenURL
	refreshCredentials.AuthURL = oauth2Config.Endpoint.AuthURL
	refreshCredentials.RefreshToken = refreshToken
	refreshCredentials.Type = "authorized_user"
	refreshCredentialsJSON, _ := json.Marshal(refreshCredentials)
	return string(refreshCredentialsJSON)
}
