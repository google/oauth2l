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
	"cloud.google.com/go/auth"
	// Blank import for go mod tidy and vendor; will be imported directly in util/fetch.go.
	_ "cloud.google.com/go/auth/credentials"
	"golang.org/x/oauth2/authhandler"
)

var AuthTypeOAuth = "oauth"
var AuthTypeJWT = "jwt"
var AuthTypeAPIKey = "apikey"
var AuthTypeSSO = "sso"

// An extensible structure that holds the credentials for
// Google API authentication.
type Settings struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// The authentication type.
	AuthType string
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
	//
	// Deprecated: Use GoogleAuthHandler instead.
	AuthHandler authhandler.AuthorizationHandler
	// GoogleAuthHandler is the cloud.google.com/go/auth AuthorizationHandler
	// used for 3-legged OAuth flow. It takes precedence over AuthHandler when
	// both are set.
	GoogleAuthHandler auth.AuthorizationHandler
	// State is a unique string used with GoogleAuthHandler (or the deprecated AuthHandler).
	State string
	// Indicates that STS token exchange should be performed.
	Sts bool
	// Used for Service Account Impersonation.
	// Exchange User access token for Service Account access token.
	ServiceAccount string
}

func (s Settings) resolveAuthHandler() auth.AuthorizationHandler {
	if s.GoogleAuthHandler != nil {
		return s.GoogleAuthHandler
	}
	if s.AuthHandler != nil {
		return auth.AuthorizationHandler(s.AuthHandler)
	}
	return nil
}

func (s Settings) GetAuthType() string {
	if s.AuthType != "" {
		return s.AuthType
	} else if s.APIKey != "" {
		return AuthTypeAPIKey
	} else if s.Scope != "" {
		return AuthTypeOAuth
	}
	return AuthTypeJWT
}
