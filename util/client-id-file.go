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
//
// clientIdFile implements several helper functions (wrapping around google package)
// to manipulate the OAuth Client ID file.
package util

import (
	"encoding/json"
	"errors"
)

type clientCredentialsConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthURI      string   `json:"auth_uri"`
	TokenURI     string   `json:"token_uri"`
}

// clientCredentialsFile mirrors cloud.google.com/go/auth/internal/credsfile.ClientCredentialsFile,
// which is internal to cloud.google.com/go/auth and not importable; parity with
// credentials.DetectDefault is verified in client-id-file_test.go.
type clientCredentialsFile struct {
	Web       *clientCredentialsConfig `json:"web"`
	Installed *clientCredentialsConfig `json:"installed"`
}

func parseClientCreds(data []byte) (*clientCredentialsConfig, error) {
	var f clientCredentialsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	var c *clientCredentialsConfig
	switch {
	case f.Web != nil:
		c = f.Web
	case f.Installed != nil:
		c = f.Installed
	default:
		return nil, errors.New("oauth2l: no client credentials found")
	}
	if len(c.RedirectURIs) < 1 {
		return nil, errors.New("oauth2l: missing redirect URL in the client_credentials.json")
	}
	return c, nil
}

// IsValidOauthClientIdFile determines if a valid OAuth Client ID file can be created
// from a credentials json file.
//
// credentialsJSON represents the credentials json file.
//
// Returns isValidCredFile: true if it can be recreated, false otherwise.
func IsValidOauthClientIdFile(credentialsJSON string) (isValidCredFile bool) {
	if credentialsJSON == "" {
		return false
	}

	data := []byte(credentialsJSON)
	_, err := parseClientCreds(data)
	return err == nil
}

// getFirstRedirectURI returns the the first URI in "redirect_uris"
//
// credentialsJSON represents the credentials json file.
//
// Returns firstRedirectURI: is the address of the first URI in "redirect_uris".
// Returns err: if unable to process the credentialsJSON file.
func GetFirstRedirectURI(credentialsJSON string) (firstRedirectURI string, err error) {
	data := []byte(credentialsJSON)
	credentials, err := parseClientCreds(data)
	if err != nil {
		return "", err
	}

	return credentials.RedirectURIs[0], nil
}
