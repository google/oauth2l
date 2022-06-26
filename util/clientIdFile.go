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
	"strings"

	"golang.org/x/oauth2/google"
)

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
	_, err := google.ConfigFromJSON(data)
	return err == nil
}

// getFirstRedirectURI returns the the first URI in "redirect_uris"
//
// credentialsJSON represents the credentials json file.
//
// Returns firstRedirectURI: is the address of the first URI in "redirect_uris".
// Returns err: if nuable to process the credentialsJSON file.
func GetFirstRedirectURI(credentialsJSON string) (firstRedirectURI string, err error) {
	data := []byte(credentialsJSON)
	credentials, err := google.ConfigFromJSON(data)
	if err != nil {
		return "", err
	}

	return credentials.RedirectURL, nil
}

// ReplaceContentAll replaces content in the credentials json file with new content.
// There is no limit on the number of replacements.
//
// credentialsJSON represents the credentials json file.
//
// Returns newCredentialsJSON: represents the modified credentials json file.
func ReplaceContentAll(credentialsJSON string, replaceContent string, replacementContent string) (newCredentialsJSON string) {
	if replaceContent == replacementContent {
		return credentialsJSON
	}
	return strings.Replace(credentialsJSON, replaceContent, replacementContent, -1)
}
