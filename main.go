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
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"github.com/google/oauth2l/sgauth"
	"github.com/jessevdk/go-flags"
	"./util"
)

const (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"
)

var (
	// Holds the parsed command-line flags
	opts commandOptions
)

// Reads and returns content of JSON file
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

// Overrides default cache location if configured
func setCacheLocation(cache *string) {
	if cache != nil {
		util.CacheLocation = *cache
	}
}

// Top level command-line flags (first argument after program name).
type commandOptions struct {
	Fetch fetchOptions `command:"fetch" description:"Fetch an access token."`
	Header fetchOptions `command:"header" description:"Fetch an access token and return it in header format."`
	Curl fetchOptions `command:"curl" description:"Fetch an access token and use it to make a curl request."`
	Info infoOptions `command:"info" description:"Display info about an OAuth access token."`
	Test infoOptions `command:"test" description:"Tests an OAuth access token. Returns 0 for valid token."`
	Reset resetOptions `command:"reset" description:"Resets the cache."`
}

// Options for "fetch", "header", and "curl" commands.
type fetchOptions struct {
	// Currently there are 3 authentication types that are mutually exclusive:
	//
	// oauth - Executes 2LO flow for Service Account and 3LO flow for OAuth Client ID. Returns OAuth token.
	// jwt - Signs claims (in JWT format) using PK. Returns signature as token. Only works for Service Account.
	// sso - Exchanges LOAS credential to OAuth token.
	AuthType string `short:"t" long:"type" choice:"oauth" choice:"jwt" choice:"sso" description:"The authentication type." default:"oauth"`

	// GUAC parameters
	Credentials string `short:"c" long:"credentials" description:"Credentials file containing OAuth Client Id or Service Account Key. Optional if environment variable GOOGLE_APPLICATION_CREDENTIALS is set."`
	Scope string `short:"s" long:"scope" description:"List of OAuth scopes requested. Required for oauth and sso authentication type. Comma delimited."`
	Audience string `short:"a" long:"audience" description:"Audience used for JWT self-signed token. Required for jwt authentication type."`
	Email string `short:"e" long:"email" description:"Email associated with SSO. Required for sso authentication type."`

	// Client parameters
	Format string `long:"output_format" choice:"bare" choice:"header" choice:"json" choice:"json_compact" choice:"pretty" description:"Token's output format." default:"bare"`
	SsoCli string `long:"ssocli" description:"Path to SSO CLI."`
	CurlCli string `long:"curlcli" description:"Path to Curl CLI."`

	// Cache is declared as a pointer type and can be one of nil, empty (""), or a custom file path.
	Cache *string `long:"cache" description:"Path to the credential cache file. Disables caching if set to empty. Defaults to ~/.oauth2l."`

	// Deprecated flags kept for backwards compatibility. Hidden from help page.
	Json string `long:"json" description:"Deprecated. Same as --credentials." hidden:"true"`
	Jwt bool `long:"jwt" description:"Deprecated. Same as --type jwt." hidden:"true"`
	Sso bool `long:"sso" description:"Deprecated. Same as --type sso." hidden:"true"`
	OldFormat string `long:"credentials_format" choice:"bare" choice:"header" choice:"json" choice:"json_compact" choice:"pretty" description:"Deprecated. Same as --output_format" hidden:"true"`
}

// Options for "info" and "test" commands.
type infoOptions struct {
	Token string `short:"t" long:"token" description:"OAuth access token to analyze."`
}

// Options for "reset" command.
type resetOptions struct {
	// Cache is declared as a pointer type and can be one of nil or a custom file path.
	Cache *string `long:"cache" description:"Path to the credential cache file to remove. Defaults to ~/.oauth2l."`
}

func main() {
	// Parse command-line flags via "go-flags" library
	parser := flags.NewParser(&opts,flags.Default)

	// Arguments that are not recognized by the parser are stored in remainingArgs.
	remainingArgs, err := parser.Parse()
	if err != nil {
		os.Exit(0)
	}

	// Get the name of the selected command
	cmd := parser.Active.Name

	// Tasks that fetch the access token.
	fetchTasks := map[string]func(*sgauth.Settings, ...string){
		"fetch":  util.Fetch,
		"header": util.Header,
		"curl": util.Curl,
	}

	// Tasks that verify the existing token.
	infoTasks := map[string]func(string){
		"info": util.Info,
		"test": util.Test,
	}

	if task, ok := fetchTasks[cmd]; ok {
		// Get the fetch options.
		var fetchOpts fetchOptions
		if cmd == "fetch" {
			fetchOpts = opts.Fetch
		} else if cmd == "header" {
			fetchOpts = opts.Header
		} else if cmd == "curl" {
			fetchOpts = opts.Curl
		}

		// Get the authentication type, with backward compatibility
		authType := fetchOpts.AuthType
		if fetchOpts.Jwt {
			authType = "jwt"
		}
		if fetchOpts.Sso {
			authType = "sso"
		}

		// Get the credentials file, with backward compatibility
		credentials := fetchOpts.Credentials
		if fetchOpts.Json != "" {
			credentials = fetchOpts.Json
		}

		scope := fetchOpts.Scope
		audience := fetchOpts.Audience
		email := fetchOpts.Email

		// Get the output format, with backward compatibility
		format := fetchOpts.Format
		if fetchOpts.OldFormat != "" {
			format = fetchOpts.OldFormat
		}

		ssocli := fetchOpts.SsoCli
		curlcli := fetchOpts.CurlCli

		setCacheLocation (fetchOpts.Cache)

		if authType == "jwt"{
			// JWT flow
			json, err := readJSON(credentials)
			if err != nil {
				fmt.Println("Failed to open file: " + credentials)
				fmt.Println(err.Error())
				return
			}

			// Fallback to reading audience from first remaining arg
			if audience == "" {
				if len(remainingArgs) > 0 {
					audience = remainingArgs [0]
				} else {
					fmt.Println("Missing audience argument for JWT")
					return
				}
			}

			settings := &sgauth.Settings{
				CredentialsJSON: json,
				Audience:		audience,
			}

			var taskArgs []string
			if cmd == "curl" {
				taskArgs = append([]string{curlcli}, remainingArgs...)
			} else if cmd == "fetch" {
				taskArgs = []string{format}
			}
			task(settings, taskArgs...)
		} else if authType == "sso" {
			// Fallback to reading email from first remaining arg
			if email == "" {
				if len(remainingArgs) > 0 {
					email = remainingArgs [0]
				} else {
					fmt.Println("Missing email argument for SSO")
					return
				}
			}

			var scopes []string

			// Fallback to reading scope from other remaining args
			if scope == "" {
				scopes = remainingArgs [1:]
			} else {
				scopes = strings.Split(scope, ",")
			}

			if len(scopes) < 1 {
				fmt.Println("Missing scope argument for SSO")
				return
			}

			// SSO flow
			token := util.SSOFetch(email, ssocli, cmd,
				parseScopes(scopes))
			header := util.BuildHeader("Bearer", token)
			if cmd == "curl" {
				url := remainingArgs[0]
				util.CurlCommand(curlcli, header, url, remainingArgs[1:]...)
			} else if cmd == "header"{
				fmt.Println(header)
			} else {
				fmt.Println(token)
			}
		} else {
			// OAuth flow
			var scopes []string

			// Fallback to reading scope from remaining args
			if scope == "" {
				scopes = remainingArgs
			} else {
				scopes = strings.Split(scope, ",")
			}

			if len(scopes) < 1 {
				fmt.Println("Missing scope argument for OAuth 2.0")
				return
			}

			json, err := readJSON(credentials)
			if err != nil {
				fmt.Println("Failed to open file: " + credentials)
				fmt.Println(err.Error())
				return
			}

			// 3LO or 2LO depending on the credential type.
			// For 2LO flow OAuthFlowHandler and State are not needed.
			settings := &sgauth.Settings{
				CredentialsJSON:  json,
				Scope:			parseScopes(scopes),
				OAuthFlowHandler: defaultAuthorizeFlowHandler,
				State:			"state",
			}
			var taskArgs []string
			if cmd == "curl" {
				taskArgs = append([]string{curlcli}, remainingArgs...)
			} else if cmd == "fetch" {
				taskArgs = []string{format}
			}
			task(settings, taskArgs...)
		}
	} else if task, ok := infoTasks[cmd]; ok {
		// Get the info options.
		var infoOpts infoOptions
		if cmd == "info" {
			infoOpts = opts.Info
		} else if cmd == "test" {
			infoOpts = opts.Test
		}

		token := infoOpts.Token;

		// Fallback to reading token from remaining args.
		if token == "" {
			token = remainingArgs [0]
		}

		task(token)
	} else if cmd == "reset" {
		setCacheLocation (opts.Reset.Cache)
		util.Reset()
	}
}
