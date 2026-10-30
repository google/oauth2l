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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

// IamServiceAccountAccessTokenURL is used for generating accesss token for a Service Account.
const IamServiceAccountAccessTokenURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"

// IamServiceAccountIdTokenURL is used for generating ID token for a Service Account.
// It is a variable so tests can point it at a fake server.
var IamServiceAccountIdTokenURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"

// iamTokenJSON is the struct representing the HTTP response from IAM
type iamTokenJSON struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// GenerateServiceAccountAccessToken generates a Service Account access token using a User access
// token approved for at least one of the following scopes:
// * https://www.googleapis.com/auth/iam
// * https://www.googleapis.com/auth/cloud-platform
func GenerateServiceAccountAccessToken(accessToken string, serviceAccount string, scope string) (*oauth2.Token, error) {
	form := url.Values{}
	for _, s := range strings.Split(scope, " ") {
		form.Add("scope", s)
	}
	req, err := http.NewRequest("POST", fmt.Sprintf(IamServiceAccountAccessTokenURL, serviceAccount), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2l: GenerateServiceAccountAccessToken failed: %v", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, errors.New(string(body))
	}

	var itj iamTokenJSON
	if err = json.Unmarshal(body, &itj); err != nil {
		return nil, err
	}
	token := oauth2.Token{}
	token.AccessToken = itj.AccessToken
	token.Expiry, _ = time.Parse(time.RFC3339, itj.ExpireTime)
	var raw map[string]interface{}
	json.Unmarshal(body, &raw)
	return token.WithExtra(raw), nil
}

// GenerateServiceAccountIdToken generates a Google-signed ID token for a Service Account
// with the given audience, using a User access token approved for at least one of the
// following scopes:
// * https://www.googleapis.com/auth/iam
// * https://www.googleapis.com/auth/cloud-platform
// The ID token is returned as the AccessToken, and also as the id_token extra field.
func GenerateServiceAccountIdToken(accessToken string, serviceAccount string, audience string) (*oauth2.Token, error) {
	reqBody, err := json.Marshal(map[string]interface{}{"audience": audience, "includeEmail": true})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf(IamServiceAccountIdTokenURL, serviceAccount), strings.NewReader(string(reqBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2l: GenerateServiceAccountIdToken failed: %v", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, errors.New(string(body))
	}

	var res struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	claims, err := jws.Decode(res.Token)
	if err != nil {
		return nil, fmt.Errorf("oauth2l: failed to decode ID token: %v", err)
	}
	token := oauth2.Token{AccessToken: res.Token, TokenType: "Bearer", Expiry: time.Unix(claims.Exp, 0)}
	return token.WithExtra(map[string]interface{}{"id_token": res.Token}), nil
}
