//
// Copyright 2019 Google Inc.
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
	"regexp"
	"strings"
	"time"

	"github.com/google/oauth2l/util"
	"github.com/jessevdk/go-flags"
)

const (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"

	// Default state parameter used for 3LO flow
	defaultState = "state"
)

var (
	// Holds the parsed command-line flags
	opts commandOptions

	// Multiple scopes are separate by comma, space, or comma-space.
	scopeDelimiter = regexp.MustCompile("[, ] *")

	// OpenId scopes should not be prefixed with scopePrefix.
	openIdScopes = regexp.MustCompile("^(openid|profile|email)$")
)

// Top level command-line flags (first argument after program name).
type commandOptions struct {
	Fetch  fetchOptions  `command:"fetch" description:"Fetch an access token."`
	Header headerOptions `command:"header" description:"Fetch an access token and return it in header format."`
	Curl   curlOptions   `command:"curl" description:"Fetch an access token and use it to make a curl request."`
	Info   infoOptions   `command:"info" description:"Display info about an OAuth access token."`
	Test   infoOptions   `command:"test" description:"Tests an OAuth access token. Returns 0 for valid token."`
	Reset  resetOptions  `command:"reset" description:"Resets the cache."`
	Web    webOptions    `command:"web"   description:"Launches a local instance of the OAuth2l Playground web app. This feature is experimental."`
}

// Common options for "fetch", "header", and "curl" commands.
type commonFetchOptions struct {
	// Currently there are 3 authentication types that are mutually exclusive:
	//
	// oauth - Executes 2LO flow for Service Account and 3LO flow for OAuth Client ID. Returns OAuth token.
	// jwt - Signs claims (in JWT format) using PK. Returns signature as token. Only works for Service Account.
	// sso - Exchanges LOAS credential to OAuth token.
	AuthType string `long:"type" choice:"oauth" choice:"jwt" choice:"sso" description:"The authentication type." default:"oauth"`

	// GUAC parameters
	Credentials    string `long:"credentials" description:"Credentials file containing OAuth Client Id or Service Account Key. Optional if environment variable GOOGLE_APPLICATION_CREDENTIALS is set."`
	Scope          string `long:"scope" description:"List of OAuth scopes requested. Required for oauth and sso authentication type. Comma delimited."`
	Audience       string `long:"audience" description:"Audience used for JWT self-signed token and STS. Required for jwt authentication type."`
	Email          string `long:"email" description:"Email associated with SSO. Required for sso authentication type."`
	QuotaProject   string `long:"quota_project" description:"Project override for quota and billing. Used for STS."`
	Sts            bool   `long:"sts" description:"Perform STS token exchange."`
	ServiceAccount string `long:"impersonate-service-account" description:"Exchange User acccess token for Service Account access token."`

	// Client parameters
	SsoCli string `long:"ssocli" description:"Path to SSO CLI. Optional."`

	// Cache is declared as a pointer type and can be one of nil, empty (""), or a custom file path.
	Cache *string `long:"cache" description:"Path to the credential cache file. Disables caching if set to empty. Defaults to ~/.oauth2l."`

	// Refresh is used for 3LO flow. When used in conjunction with caching, the user can avoid re-authorizing.
	Refresh bool `long:"refresh" description:"If the cached access token is expired, attempt to refresh it using refreshToken."`

	// Consent page parameters.
	DisableAutoOpenConsentPage         bool   `long:"disableAutoOpenConsentPage" description:"Disables the ability to open the consent page automatically."`
	ConsentPageInteractionTimeout      int    `long:"consentPageInteractionTimeout" description:"Maximum wait time for user to interact with consent page." default:"2"`
	ConsentPageInteractionTimeoutUnits string `long:"consentPageInteractionTimeoutUnits" choice:"seconds" choice:"minutes" description:"Consent page timeout units." default:"minutes"`

	// Deprecated flags kept for backwards compatibility. Hidden from help page.
	Json      string `long:"json" description:"Deprecated. Same as --credentials." hidden:"true"`
	Jwt       bool   `long:"jwt" description:"Deprecated. Same as --type jwt." hidden:"true"`
	Sso       bool   `long:"sso" description:"Deprecated. Same as --type sso." hidden:"true"`
	OldFormat string `long:"credentials_format" choice:"bare" choice:"header" choice:"json" choice:"json_compact" choice:"pretty" description:"Deprecated. Same as --output_format" hidden:"true"`
}

// Additional options for "fetch" command.
type fetchOptions struct {
	commonFetchOptions
	Format string `long:"output_format" choice:"bare" choice:"header" choice:"json" choice:"json_compact" choice:"pretty" choice:"refresh_token" description:"Token's output format." default:"bare"`
}

// Additional options for "header" command.
type headerOptions struct {
	commonFetchOptions
}

// Additional options for "curl" command.
type curlOptions struct {
	commonFetchOptions
	CurlCli string `long:"curlcli" description:"Path to Curl CLI. Optional."`
	Url     string `long:"url" description:"URL endpoint for the curl request." required:"true"`
}

// Options for "info" and "test" commands.
type infoOptions struct {
	Token string `long:"token" description:"OAuth access token to analyze."`
}

// Options for "reset" command.
type resetOptions struct {
	// Cache is declared as a pointer type and can be one of nil or a custom file path.
	Cache *string `long:"cache" description:"Path to the credential cache file to remove. Defaults to ~/.oauth2l."`
}

// Options for "web" command
type webOptions struct {
	Stop      bool   `long:"stop" description:"Stops the OAuth2l Playground where OAuth2l-web should be located."`
	Directory string `long:"directory" description:"Sets the directory of where OAuth2l-web should be located. Defaults to ~/.oauth2l-web." `
}

// Reads and returns content of JSON file.
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

// Append Google OAuth scope prefix if not provided and joins
// the slice into a whitespace-separated string.
func parseScopes(scopes []string) string {
	for i := 0; i < len(scopes); i++ {
		if !strings.Contains(scopes[i], "//") && !openIdScopes.MatchString(scopes[i]) {
			scopes[i] = scopePrefix + scopes[i]
		}
	}
	return strings.Join(scopes, " ")
}

// Overrides default cache location if configured.
func setCacheLocation(cache *string) {
	if cache != nil {
		util.CacheLocation = *cache
	}
}

// Overrides default web directory if configured.
func setWebDirectory(directory string) {
	if directory != "" {
		util.WebDirectory = directory
	}
}

// Extracts the common fetch options based on chosen command.
func getCommonFetchOptions(cmdOpts commandOptions, cmd string) commonFetchOptions {
	var commonOpts commonFetchOptions
	switch cmd {
	case "fetch":
		commonOpts = cmdOpts.Fetch.commonFetchOptions
	case "header":
		commonOpts = cmdOpts.Header.commonFetchOptions
	case "curl":
		commonOpts = cmdOpts.Curl.commonFetchOptions
	}
	return commonOpts
}

// Generates a time duration
func getTimeDuration(quantity int, units string) (time.Duration, error) {
	switch units {
	case "seconds":
		return time.Duration(quantity) * time.Second, nil
	case "minutes":
		return time.Duration(quantity) * time.Minute, nil
	default:
		return time.Duration(0), fmt.Errorf("Invalid units: %s", units)
	}
}

// Get the authentication type, with backward compatibility.
func getAuthTypeWithFallback(commonOpts commonFetchOptions) string {
	authType := commonOpts.AuthType
	if commonOpts.Jwt {
		authType = "jwt"
	} else if commonOpts.Sso {
		authType = "sso"
	}
	return authType
}

// Get the credentials file, with backward compatibility.
func getCredentialsWithFallback(commonOpts commonFetchOptions) string {
	credentials := commonOpts.Credentials
	if commonOpts.Json != "" {
		credentials = commonOpts.Json
	}
	return credentials
}

// Get the fetch output format, with backward compatibility.
func getOutputFormatWithFallback(fetchOpts fetchOptions) string {
	format := fetchOpts.Format
	if fetchOpts.OldFormat != "" {
		format = fetchOpts.OldFormat
	}
	return format
}

// Converts scope argument to string slice, with backward compatibility.
func getScopesWithFallback(scope string, remainingArgs ...string) []string {
	var scopes []string
	// Fallback to reading scope from remaining args
	if scope == "" {
		scopes = remainingArgs
	} else {
		scopes = scopeDelimiter.Split(scope, -1)
	}
	return scopes
}

// Extracts the info options based on chosen command.
func getInfoOptions(cmdOpts commandOptions, cmd string) infoOptions {
	var infoOpts infoOptions
	switch cmd {
	case "info":
		infoOpts = cmdOpts.Info
	case "test":
		infoOpts = cmdOpts.Test
	}
	return infoOpts
}

func main() {
	// Parse command-line flags via "go-flags" library
	parser := flags.NewParser(&opts, flags.Default)

	// Arguments that are not recognized by the parser are stored in remainingArgs.
	remainingArgs, err := parser.Parse()
	if err != nil {
		os.Exit(0)
	}

	// Get the name of the selected command
	cmd := parser.Active.Name

	// Tasks that fetch the access token.
	fetchTasks := map[string]func(*util.Settings, *util.TaskSettings){
		"fetch":  util.Fetch,
		"header": util.Header,
		"curl":   util.Curl,
	}

	// Tasks that verify the existing token.
	infoTasks := map[string](func(string) int){
		"info": util.Info,
		"test": util.Test,
	}

	if task, ok := fetchTasks[cmd]; ok {
		commonOpts := getCommonFetchOptions(opts, cmd)
		authType := getAuthTypeWithFallback(commonOpts)
		credentials := getCredentialsWithFallback(commonOpts)
		scope := commonOpts.Scope
		audience := commonOpts.Audience
		quotaProject := commonOpts.QuotaProject
		sts := commonOpts.Sts
		serviceAccount := commonOpts.ServiceAccount
		email := commonOpts.Email
		ssocli := commonOpts.SsoCli
		setCacheLocation(commonOpts.Cache)
		refresh := commonOpts.Refresh
		format := getOutputFormatWithFallback(opts.Fetch)
		curlcli := opts.Curl.CurlCli
		url := opts.Curl.Url

		taskSettings := &util.TaskSettings{
			AuthType:  authType,
			Format:    format,
			CurlCli:   curlcli,
			Url:       url,
			ExtraArgs: remainingArgs,
			SsoCli:    ssocli,
			Refresh:   refresh,
		}

		// Configure GUAC settings based on authType.
		var settings *util.Settings
		if authType == util.AuthTypeJWT {
			json, err := readJSON(credentials)
			if err != nil {
				fmt.Println("Failed to open file: " + credentials)
				fmt.Println(err.Error())
				return
			}

			// Fallback to reading audience from first remaining arg
			if audience == "" {
				if len(remainingArgs) > 0 {
					audience = remainingArgs[0]
				}
			}

			scopes := getScopesWithFallback(scope, remainingArgs...)
			if audience == "" && len(scopes) < 1 {
				fmt.Println("Neither audience nor scope argument is provided for JWT")
				return
			}

			settings = &util.Settings{
				AuthType:        util.AuthTypeJWT,
				CredentialsJSON: json,
				Audience:        audience,
				Scope:           parseScopes(scopes),
			}
		} else if authType == util.AuthTypeSSO {
			// Fallback to reading email from first remaining arg
			argProcessedIndex := 0
			if email == "" {
				if len(remainingArgs) > 0 {
					email = remainingArgs[argProcessedIndex]
					argProcessedIndex++
				} else {
					fmt.Println("Missing email argument for SSO")
					return
				}
			}

			scopes := getScopesWithFallback(scope, remainingArgs[argProcessedIndex:]...)
			if len(scopes) < 1 {
				fmt.Println("Missing scope argument for SSO")
				return
			}

			// SSO flow does not use CredentialsJSON
			settings = &util.Settings{
				Email:          email,
				Scope:          parseScopes(scopes),
				Audience:       audience,
				QuotaProject:   quotaProject,
				Sts:            sts,
				ServiceAccount: serviceAccount,
			}
		} else {
			// OAuth flow
			scopes := getScopesWithFallback(scope, remainingArgs...)
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

			var authCodeServer util.AuthorizationCodeServer = nil
			var consentPageSettings util.ConsentPageSettings
			redirectUri, err := util.GetFirstRedirectURI(json)
			// 3LO Loopback case
			if err == nil && strings.Contains(redirectUri, "localhost") {
				interactionTimeout, err := getTimeDuration(commonOpts.ConsentPageInteractionTimeout, commonOpts.ConsentPageInteractionTimeoutUnits)
				if err != nil {
					fmt.Println("Failed to create time.Duration: " + err.Error())
					return
				}
				consentPageSettings = util.ConsentPageSettings{
					DisableAutoOpenConsentPage: commonOpts.DisableAutoOpenConsentPage,
					InteractionTimeout:         interactionTimeout,
				}
				authCodeServer = &util.AuthorizationCodeLocalhost{
					ConsentPageSettings: consentPageSettings,
					AuthCodeReqStatus: util.AuthorizationCodeStatus{
						Status: util.WAITING, Details: "Authorization code not yet set."},
				}

				// Start localhost server
				adr, err := authCodeServer.ListenAndServe(redirectUri)
				if err != nil {
					fmt.Println(err)
					return
				}
				// Close localhost server's port on exit
				defer authCodeServer.Close()

				// If a different dynamic redirect uri was created, replace the redirect uri in file.
				// this happens if the original redirect does not have a port for the localhost.
				redirectUri = fmt.Sprintf("\"%s\"", redirectUri)
				adr = fmt.Sprintf("\"%s\"", adr)
				json = strings.Replace(json, redirectUri, adr, -1)
			}

			// 3LO or 2LO depending on the credential type.
			// For 2LO flow AuthHandler, State and ConsentPageSettings are not needed.
			settings = &util.Settings{
				CredentialsJSON: json,
				Scope:           parseScopes(scopes),
				AuthHandler:     util.Get3LOAuthorizationHandler(defaultState, consentPageSettings, &authCodeServer),
				State:           defaultState,
				Audience:        audience,
				QuotaProject:    quotaProject,
				Sts:             sts,
				ServiceAccount:  serviceAccount,
				Email:           email,
				AuthType:        util.AuthTypeOAuth,
			}
		}

		task(settings, taskSettings)
	} else if task, ok := infoTasks[cmd]; ok {
		infoOpts := getInfoOptions(opts, cmd)
		token := infoOpts.Token

		// Fallback to reading token from remaining args.
		if token == "" {
			if len(remainingArgs) > 0 {
				token = remainingArgs[0]
			} else {
				fmt.Println("Missing token to analyze")
				return
			}
		}

		os.Exit(task(token))
	} else if cmd == "web" {
		setWebDirectory(opts.Web.Directory)
		if opts.Web.Stop {
			util.WebStop()
		} else {
			util.Web()
		}

	} else if cmd == "reset" {
		setCacheLocation(opts.Reset.Cache)
		util.Reset()
	}
}
