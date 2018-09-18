//
// Copyright 2018 Google Inc.
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
package sgauth

var MethodOAuth = "oauth"
var MethodJWT = "jwt"
var MethodAPIKey = "apikey"

// An extensible structure that holds the credentials for
// Google API authentication.
type Settings struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// If specified, use OAuth. Otherwise, JWT.
	Scope string
	// The audience field for JWT auth
	Audience string
	// The Google API key
	APIKey string
	// This is only used for domain-wide delegation.
	// UNIMPLEMENTED
	User string
	// The identifier to the user that the per-user quota will be charged
	// against. If not specified, the identifier to the authenticated account
	// is used. If there is no authenticated account too, the caller's network
	// IP address will be used.
	// UNIMPLEMENTED
	QuotaUser string
	// A user specified project that is responsible for the request quota and
	// billing charges.
	QuotaProject string
	// End-user OAuth Flow handler that redirects the user to the given URL
	// and returns the token.
	OAuthFlowHandler func(url string) (token string, err error)
	// The state string used for 3LO session verification.
	// UNIMPLEMENTED
	State string
}

func (s Settings) AuthMethod() string {
	if s.APIKey != "" {
		return MethodAPIKey
	} else if s.Scope != "" {
		return MethodOAuth
	}
	return MethodJWT
}
