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
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"github.com/shinfan/sgauth"
	"github.com/google/oauth2l/go/oauth2l/util"
	"os"
)

var (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"
	cmds = []string{"fetch", "header", "info", "test"}
)

func help() {
	fmt.Println("Usage: oauth2l {fetch|header|info|test} " +
		"[--jwt] [--json] [--sso] [--ssocli] {scope|aud|email}")
}

func readJSON(file string) (string, error) {
	if file != "" {
		secretBytes, err := ioutil.ReadFile(file)
		if err != nil {
			return "", err
		}
		return string(secretBytes), nil
	}
	return "", nil
}

// Default 3LO authorization handler. Prints the authorization URL on stdout
// and reads the verification code from stdin.
func defaultAuthorizeFlowHandler(authorizeUrl string) (string, error) {
	// Print the url on console, let user authorize and paste the token back.
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authorizeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, nil
}

// Append Google OAuth scope prefix if not provided and joins
// the slice into a whitespace-separated string.
func parseScopes(scopes []string) string {
	for i := 0; i < len(scopes); i++ {
		if !strings.Contains(scopes[i], "//") {
			scopes[i] = scopePrefix + scopes[i]
		}
	}
	return strings.Join(scopes, " ")
}

func main() {
	if len(os.Args) < 3 {
		help()
		return
	}

	// Configure the CLI
	flagSet := flag.NewFlagSet("fetch", flag.ExitOnError)
	helpFlag := flagSet.Bool("help", false, "Print help message.")
	flagSet.BoolVar(helpFlag, "h", false, "")
	jsonFile := flagSet.String("json", "", "Path to secret json file.")
	jwtFlag := flagSet.Bool("jwt", false, "Use JWT auth flow")
	ssoFlag := flagSet.Bool("sso", false, "Use SSO auth flow")
	ssocli := flagSet.String("ssocli", "", "Path to SSO CLI")
	flagSet.Parse(os.Args[2:])

	if *helpFlag {
		help()
		return
	}

	// Get the command keyword from the first argument.
	cmd := os.Args[1]

	// Tasks that fetch the access token.
	fetchTasks := map[string]func(*sgauth.Settings){
		"fetch":  util.Fetch,
		"header": util.Header,
	}

	// Tasks that verify the existing token.
	infoTasks := map[string]func(string){
		"info":  util.Info,
		"test": util.Test,
	}

	if task, ok := fetchTasks[cmd]; ok {
		if *jwtFlag {
			// JWT flow
			json, err := readJSON(*jsonFile)
			if err != nil {
				fmt.Println("Failed to open file: " + *jsonFile)
				fmt.Println(err.Error())
				return
			}

			settings := &sgauth.Settings{
				CredentialsJSON: json,
				Audience: flagSet.Args()[len(flagSet.Args()) - 1],
			}
			task(settings)
		} else if *ssoFlag {
			// SSO flow
			util.SSOFetch(flagSet.Args()[0], *ssocli, cmd,
				parseScopes(flagSet.Args()[1:]))
		} else {
			// OAuth flow
			json, err := readJSON(*jsonFile)
			if err != nil {
				fmt.Println("Failed to open file: " + *jsonFile)
				fmt.Println(err.Error())
				return
			}

			// 3LO or 2LO depending on the credential type.
			// For 2LO flow OAuthFlowHandler and State are not needed.
			settings := &sgauth.Settings{
				CredentialsJSON:  json,
				Scope:            parseScopes(flagSet.Args()),
				OAuthFlowHandler: defaultAuthorizeFlowHandler,
				State:            "state",
			}
			task(settings)
		}
	} else if task, ok := infoTasks[cmd]; ok {
		task(flagSet.Args()[len(flagSet.Args()) - 1])
	} else {
		// Unknown command, print usage.
		help()
	}
}
