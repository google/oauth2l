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
package util

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// Base URL to fetch the token info
	googleTokenInfoURLPrefix = "https://www.googleapis.com/oauth2/v3/tokeninfo/?access_token="
)

// Supported output formats
const (
	formatJson         = "json"
	formatJsonCompact  = "json_compact"
	formatPretty       = "pretty"
	formatHeader       = "header"
	formatBare         = "bare"
	formatRefreshToken = "refresh_token"
)

// Credentials file types.
// If type is not one of the below, it means the file is a
// Google Client ID JSON.
const (
	serviceAccountKey  = "service_account"
	userCredentialsKey = "authorized_user"
	externalAccountKey = "external_account"
)

// An extensible structure that holds the settings
// used by different oauth2l tasks.
// These settings are used by oauth2l only
// and are not part of GUAC settings.
type TaskSettings struct {
	// AuthType determines which auth tool to use (sso vs sgauth)
	AuthType string
	// Output format for Fetch task
	Format string
	// CurlCli override for Curl task
	CurlCli string
	// Url endpoint for Curl task
	Url string
	// Extra args for Curl task
	ExtraArgs []string
	// SsoCli override for Sso task
	SsoCli string
	// Refresh expired access token in cache
	Refresh bool
}

// Fetches and prints the token in plain text with the given settings
// using Google Authenticator.
func Fetch(settings *Settings, taskSettings *TaskSettings) {
	token := fetchToken(settings, taskSettings)
	printToken(token, taskSettings.Format, settings)
}

// Fetches and prints the token in header format with the given settings
// using Google Authenticator.
func Header(settings *Settings, taskSettings *TaskSettings) {
	taskSettings.Format = formatHeader
	Fetch(settings, taskSettings)
}

// Fetches token with the given settings using Google Authenticator
// and use the token as header to make curl request.
func Curl(settings *Settings, taskSettings *TaskSettings) {
	token := fetchToken(settings, taskSettings)
	if token != nil {
		header := BuildHeader(token.TokenType, token.AccessToken)
		curlcli := taskSettings.CurlCli
		url := taskSettings.Url
		extraArgs := taskSettings.ExtraArgs
		CurlCommand(curlcli, header, url, extraArgs...)
	}
}

// Fetches the information of the given token.
func Info(token string) int {
	info, err := getTokenInfo(token)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Println(info)
	}
	return 0
}

// Tests the given token. Returns 0 for valid tokens.
// Otherwise returns 1.
func Test(token string) int {
	_, err := getTokenInfo(token)
	if err != nil {
		fmt.Println(1)
		return 1
	} else {
		fmt.Println(0)
		return 0
	}
}

// Resets the cache.
func Reset() {
	err := ClearCache()
	if err != nil {
		fmt.Print(err)
	}
}

// Returns the given token in standard header format.
func BuildHeader(tokenType string, token string) string {
	return fmt.Sprintf("Authorization: %s %s", tokenType, token)
}

func getTokenInfo(token string) (string, error) {
	c := http.DefaultClient
	resp, err := c.Get(googleTokenInfoURLPrefix + token)
	if err != nil {
		return "", err
	}
	data, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", errors.New(string(data))
	}
	return string(data), err
}

// fetchToken attempts to fetch and cache an access token.
//
// If SSO is specified, obtain token via SSOFetch instead of FetchToken.
//
// If cached token is expired and refresh is requested,
// attempt to obtain new token via RefreshToken instead
// of default OAuth flow.
//
// If STS is requested, we will perform an STS exchange
// after the original access token has been fetched.
func fetchToken(settings *Settings, taskSettings *TaskSettings) *oauth2.Token {
	token, err := LookupCache(settings)
	tokenExpired := isTokenExpired(token)
	if token == nil || tokenExpired {
		if taskSettings.AuthType == "sso" {
			token, err = SSOFetch(taskSettings.SsoCli, settings.Email, settings.Scope)
			if err != nil {
				fmt.Println(err)
				return nil
			}
		} else {
			fetchSettings := settings
			if tokenExpired && taskSettings.Refresh {
				// If creds cannot be retrieved here, which is unexpected, we will ignore
				// the error and let FetchToken return a standardized error message
				// in the subsequent step.
				creds, _ := FindJSONCredentials(context.Background(), settings)
				refreshTokenJSON := BuildRefreshTokenJSON(token.RefreshToken, creds)
				if refreshTokenJSON != "" {
					refreshSettings := *settings // Make a shallow copy
					refreshSettings.CredentialsJSON = refreshTokenJSON
					fetchSettings = &refreshSettings
				}
			}
			token, err = FetchToken(context.Background(), fetchSettings)
			if err != nil {
				fmt.Println(err)
				return nil
			}
		}
		if settings.ServiceAccount != "" {
			token, err = GenerateServiceAccountAccessToken(token.AccessToken, settings.ServiceAccount, settings.Scope)
			if err != nil {
				fmt.Println(err)
				return nil
			}
		}
		if settings.Sts {
			token, err = StsExchange(token.AccessToken, EncodeClaims(settings))
			if err != nil {
				fmt.Println(err)
				return nil
			}
		}
		err = InsertCache(settings, token)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}
	return token
}

func isTokenExpired(token *oauth2.Token) bool {
	// SSO and STS tokens currently do not have expiration, as indicated by empty Expiry.
	return token != nil && !token.Expiry.IsZero() && time.Now().After(token.Expiry)
}

func getCredentialType(creds *google.Credentials) string {
	var m map[string]string
	err := json.Unmarshal(creds.JSON, &m)
	if err != nil && m["type"] != "" {
		return m["type"]
	}
	return ""
}

// Prints the token with the specified format.
func printToken(token *oauth2.Token, format string, settings *Settings) {
	if token != nil {
		switch format {
		case formatBare:
			fmt.Println(token.AccessToken)
		case formatHeader:
			printHeader(token.TokenType, token.AccessToken)
		case formatJson:
			printJson(token, "  ")
		case formatJsonCompact:
			printJson(token, "")
		case formatPretty:
			creds, err := FindJSONCredentials(context.Background(), settings)
			if err != nil {
				log.Fatal(err.Error())
			}
			fmt.Printf("Fetched credentials of type:\n  %s\n"+
				"Access Token:\n  %s\n",
				getCredentialType(creds), token.AccessToken)
		case formatRefreshToken:
			creds, err := FindJSONCredentials(context.Background(), settings)
			if err != nil {
				log.Fatal(err.Error())
			}
			credsType := getCredentialType(creds)
			if credsType == serviceAccountKey {
				log.Fatalf("Refresh token output format is not supported for Service Account credentials type")
			}
			if credsType == externalAccountKey {
				log.Fatalf("Refresh token output format is not supported for External Account credentials type")
			}
			if credsType == userCredentialsKey {
				fmt.Print(string(creds.JSON)) // The input credential is already in refresh token format.
			}
			fmt.Println(BuildRefreshTokenJSON(token.RefreshToken, creds))
		default:
			log.Fatalf("Invalid output_format: '%s'", format)
		}
	}
}

func printHeader(tokenType string, token string) {
	fmt.Println(BuildHeader(tokenType, token))
}

func printJson(token *oauth2.Token, indent string) {
	data, err := MarshalWithExtras(token, indent)
	if err != nil {
		log.Fatal(err.Error())
		return
	}
	fmt.Println(string(data))
}
