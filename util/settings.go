//
// Copyright 2021 Google Inc.
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
	"golang.org/x/oauth2/authhandler"
)

var MethodOAuth = "oauth"
var MethodJWT = "jwt"
var MethodAPIKey = "apikey"

// An extensible structure that holds the credentials for
// Google API authentication.
type Settings struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// The authentication method should be used.
	AuthMethod string
	// If specified, use OAuth. Otherwise, JWT.
	Scope string
	// The audience field for JWT auth
	Audience string
	// The Google API key
	APIKey string
	// This is only used for domain-wide delegation.
	// DEPRECATED
	User string
	// The email used for SSO and domain-wide delegation.
	Email string
	// A user specified project that is responsible for the request quota and
	// billing charges.
	QuotaProject string
	// AuthHandler is the AuthorizationHandler used for 3-legged OAuth flow.
	AuthHandler authhandler.AuthorizationHandler
	// State is a unique string used with AuthHandler.
	State string
	// Indicates that STS token exchange should be performed.
	Sts bool
	// Used for Service Account Impersonation.
	// Exchange User access token for Service Account access token.
	ServiceAccount string
}

func (s Settings) GetAuthMethod() string {
	if s.AuthMethod != "" {
		return s.AuthMethod
	} else if s.APIKey != "" {
		return MethodAPIKey
	} else if s.Scope != "" {
		return MethodOAuth
	}
	return MethodJWT
}
