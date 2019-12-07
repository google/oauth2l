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
	"github.com/google/oauth2l/sgauth"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	// Base URL to fetch the token info
	googleTokenInfoURLPrefix = "https://www.googleapis.com/oauth2/v3/tokeninfo/?access_token="
)

// Supported output formats
const (
	formatJson        = "json"
	formatJsonCompact = "json_compact"
	formatPretty      = "pretty"
	formatHeader      = "header"
	formatBare        = "bare"
)

// Fetches and prints the token in plain text with the given settings
// using Google Authenticator.
func Fetch(settings *sgauth.Settings, args ...string) {
	format := args[0]
	printToken(fetchToken(settings), format, getCredentialType(settings))
}

// Fetches and prints the token in header format with the given settings
// using Google Authenticator.
func Header(settings *sgauth.Settings, args ...string) {
	Fetch(settings, formatHeader)
}

// Fetches token with the given settings using Google Authenticator
// and use the token as header to make curl request.
func Curl(settings *sgauth.Settings, args ...string) {
	token := fetchToken(settings)
	if token != nil {
		header := BuildHeader(token.TokenType, token.AccessToken)
		curlcli := args[0]
		url := args[1]
		CurlCommand(curlcli, header, url, args[2:]...)
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

func fetchToken(settings *sgauth.Settings) *sgauth.Token {
	token, _ := LookupCache(settings)
	if token != nil {
		return token
	}
	token, err := sgauth.FetchToken(context.Background(), settings)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	err = InsertCache(settings, token)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return token
}

func getCredentialType(settings *sgauth.Settings) string {
	cred, err := sgauth.FindJSONCredentials(context.Background(), settings)
	if err != nil {
		return ""
	}
	return cred.Type
}

// Prints the token with the specified format
func printToken(token *sgauth.Token, format string, credType string) {
	if token != nil {
		switch format {
		case formatBare:
			fmt.Println(token.AccessToken)
		case formatHeader:
			printHeader(token.TokenType, token.AccessToken)
		case formatJson:
			json, err := json.MarshalIndent(token.Raw, "", "  ")
			if err != nil {
				log.Fatal(err.Error())
				return
			}
			fmt.Println(string(json))
		case formatJsonCompact:
			json, err := json.Marshal(token.Raw)
			if err != nil {
				log.Fatal(err.Error())
				return
			}
			fmt.Println(string(json))
		case formatPretty:
			fmt.Printf("Fetched credentials of type:\n  %s\n"+
				"Access Token:\n  %s\n",
				credType, token.AccessToken)
		default:
			log.Fatalf("Invalid choice: '%s' "+
				"(choose from 'bare', 'header', 'json', 'json_compact', 'pretty')",
				format)
		}
	}
}

func printHeader(tokenType string, token string) {
	fmt.Println(BuildHeader(tokenType, token))
}
