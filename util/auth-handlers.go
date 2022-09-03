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
// Contains authorization handler functions.
package util

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/authhandler"
)

// 3LO authorization handler. Determines what algorithm to use
// to get the authorization code.
//
// Note that the "state" parameter is used to prevent CSRF attacks.
func Get3LOAuthorizationHandler(state string, consentSettings ConsentPageSettings,
	authCodeServer *AuthorizationCodeServer) authhandler.AuthorizationHandler {
	return func(authCodeURL string) (string, string, error) {
		decodedValue, _ := url.ParseQuery(authCodeURL)
		redirectURL := decodedValue.Get("redirect_uri")

		if strings.Contains(redirectURL, "localhost") {
			return authorization3LOLoopback(authCodeURL, consentSettings, authCodeServer)
		}

		return authorization3LOOutOfBand(state, authCodeURL)
	}
}

// authorization3LOOutOfBand prints the authorization URL on stdout
// and reads the authorization code from stdin.
//
// Note that the "state" parameter is used to prevent CSRF attacks.
// For convenience, authorization3LOOutOfBand returns a pre-configured state
// instead of requiring the user to copy it from the browser.
func authorization3LOOutOfBand(state string, authCodeURL string) (string, string, error) {
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authCodeURL)
	fmt.Println("Enter authorization code:")
	var code string
	fmt.Scanln(&code)
	return code, state, nil
}

// authorization3LOLoopback prints the authorization URL on stdout
// and redirects the user to the authCodeURL in a new browser's tab.
// if `DisableAutoOpenConsentPage` is set, then the user is instructed
// to manually open the authCodeURL in a new browser's tab.
//
// The code and state output parameters in this function are the same
// as the ones generated after the user grants permission on the consent page.
// When the user interacts with the consent page, an error or a code-state-tuple
// is expected to be returned to the Auth Code Localhost Server endpoint
// (see loopback.go for more info).
func authorization3LOLoopback(authCodeURL string, consentSettings ConsentPageSettings,
	authCodeServer *AuthorizationCodeServer) (string, string, error) {
	const (
		// Max wait time for the server to start listening and serving
		maxWaitForListenAndServe time.Duration = 10 * time.Second
	)

	// (Step 1) Start local Auth Code Server
	if started, _ := (*authCodeServer).WaitForListeningAndServing(maxWaitForListenAndServe); started {
		// (Step 2) Provide access to the consent page
		if consentSettings.DisableAutoOpenConsentPage { // Auto open consent disabled
			fmt.Println("Go to the following link in your browser:")
			fmt.Println("\n", authCodeURL)
		} else { // Auto open consent
			b := Browser{}
			if be := b.OpenURL(authCodeURL); be != nil {
				fmt.Println("Your browser could not be opened to visit:")
				fmt.Println("\n", authCodeURL)
				fmt.Println("\nError:", be)
			} else {
				fmt.Println("Your browser has been opened to visit:")
				fmt.Println("\n", authCodeURL)
			}
		}

		// (Step 3) Wait for user to interact with consent page
		(*authCodeServer).WaitForConsentPageToReturnControl()
	}

	// (Step 4) Attempt to get Authorization code. If one was not received
	// default string values are returned.
	code, err := (*authCodeServer).GetAuthenticationCode()
	return code.Code, code.State, err
}
