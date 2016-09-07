//
// Copyright 2015 Google Inc.
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

package oauth2util

import (
	"encoding/json"
	"fmt"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// AuthorizeHandler is a handler function that handles user interaction in the
// 3-legged oauth flow.
// This handler is given a URL that points to the authorization page. It should
// then ask the user to authorize on the page, and returns the validation code.
type AuthorizeHandler func(string) (string, error)

// defaultAuthorizeFlowHandler prints the authorization URL on stdout and reads
// the verification code from stdin.
func defaultAuthorizeFlowHandler(authorizeUrl string) (string, error) {
	// Print the url on console, let user authorize and paste the token back.
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authorizeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, nil
}

// NewTokenSource creates a new OAuth 2.0 token source. The underlying http
// requests will use http.RoundTripper provided in ctx.
//
// key is a JSON string that represents either an OAuth client ID or a service account key.
// authorizeHandler handels authorize flow in 3-legged OAuth. If not provided, a default handler is used.
// scope is a list of OAuth scope codes. Read more at https://tools.ietf.org/html/rfc6749.
func NewTokenSource(ctx context.Context, key []byte, authorizeHandler AuthorizeHandler, scope ...string) (oauth2.TokenSource, error) {
	var secret map[string]interface{}
	if err := json.Unmarshal(key, &secret); err != nil {
		return nil, err
	}

	// TODO: support "web" client secret by using a local web server.
	// According to the content in the json, decide whether to run three-legged
	// flow (for client secret) or two-legged flow (for service account).
	if _, ok := secret["installed"]; ok {
		// If authorizeHandler is not given, set it to the default one.
		if authorizeHandler == nil {
			authorizeHandler = defaultAuthorizeFlowHandler
		}

		// When the secret contains "installed" field, it is a client secret. We
		// will run a three-legged flow
		conf, err := google.ConfigFromJSON(key, scope...)
		if err != nil {
			return nil, err
		}

		// In the authorize flow, user will paste a verification code back to console.
		authUrl := conf.AuthCodeURL("", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		code, err := authorizeHandler(authUrl)
		if err != nil {
			return nil, err
		}

		// The verify flow takes in the verification code from authorize flow, sends a
		// POST request containing the code to fetch oauth token.
		token, err := conf.Exchange(ctx, code)
		if err != nil {
			return nil, err
		}

		return conf.TokenSource(ctx, token), nil

	}

	if tokenType, ok := secret["type"]; ok && "service_account" == tokenType {
		// If the token type is "service_account", we will run the two-legged flow
		jwtCfg, err := google.JWTConfigFromJSON(key, scope...)
		if err != nil {
			return nil, err
		}
		return jwtCfg.TokenSource(ctx), nil
	}

	return nil, fmt.Errorf("Unsupported token type.")
}
