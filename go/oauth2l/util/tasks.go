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
	"fmt"
	"net/http"
	"io/ioutil"
	"errors"
	"github.com/google/oauth2l/go/sgauth"
	"context"
)

const (
	// Base URL to fetch the token info
	googleTokenInfoURLPrefix =
		"https://www.googleapis.com/oauth2/v3/tokeninfo/?access_token="
)

// Prints the token in either plain or header format
func PrintToken(tokenType string, token string, headerFormat bool) {
	if headerFormat {
		fmt.Printf("Authorization: %s %s\n", tokenType, token)
	} else {
		fmt.Println(token)
	}
}

// Fetches and prints the token in plain text with the given settings
// using Google Authenticator.
func Fetch(settings *sgauth.Settings) {
	token, err := sgauth.FetchToken(context.Background(), settings)
	if err != nil {
		fmt.Println(err)
	}
	PrintToken(token.TokenType, token.AccessToken, false)
}

// Fetches and prints the token in header format with the given settings
// using Google Authenticator.
func Header(settings *sgauth.Settings) {
	token, err := sgauth.FetchToken(context.Background(), settings)
	if err != nil {
		fmt.Println(err)
	}
	PrintToken(token.TokenType, token.AccessToken, true)
}

// Fetch the information of the given token.
func Info(token string) {
	info, err := getTokenInfo(token)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Println(info)
	}
}

// Test the given token. Returns 0 for valid tokens.
// Otherwise returns 1.
func Test(token string) {
	_, err := getTokenInfo(token)
	if err != nil {
		fmt.Println(1)
	} else {
		fmt.Println(0)
	}
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
