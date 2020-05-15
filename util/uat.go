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
package util

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/oauth2l/sgauth"
)

// StsURL is Google's Secure Token Service endpoint used for obtaining identity
// tokens such as UAT.
// TODO (andyzhao): Replace with https://sts.googleapis.com/v1/token when ready.
const StsURL = "https://securetoken.googleapis.com/v1alpha2/identitybindingtoken"

// tokenJSON is the struct representing the HTTP response from STS
type tokenJSON struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Exchanges an OAuth Access Token to an UAT token with base64 encoded claims
func UatExchange(accessToken string, encodedClaims string) (*sgauth.Token, error) {
	v := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"subject_token":        {accessToken},
	}

	req, err := http.NewRequest("POST", StsURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Goog-Auth-Claims", encodedClaims)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2l: UAT exchange failed: %v", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, errors.New(string(body))
	}

	var tj tokenJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		return nil, err
	}
	token := sgauth.Token{}
	token.AccessToken = tj.AccessToken
	token.TokenType = tj.TokenType
	json.Unmarshal(body, &token.Raw)
	return &token, nil
}

// claimsJSON is the struct representing supported UAT claims
type claimsJSON struct {
	Audience    string `json:"audience,omitempty"`
	UserProject string `json:"user_project,omitempty"`
}

// EncodeClaims base64 encodes supported UAT claims in settings
func EncodeClaims(settings *sgauth.Settings) string {
	cj := claimsJSON{Audience: settings.Audience, UserProject: settings.UserProject}
	claims, _ := json.Marshal(cj)
	return base64.StdEncoding.EncodeToString(claims)
}
