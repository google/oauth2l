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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2"
)

// IamServiceAccountAccessTokenURL is used for generating accesss token for a Service Account.
const IamServiceAccountAccessTokenURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"

var iamAccessTokenURL = IamServiceAccountAccessTokenURL

// iamTokenJSON is the struct representing the HTTP response from IAM
type iamTokenJSON struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

// GenerateServiceAccountAuthToken generates a Service Account access token using a User access
// token approved for at least one of the following scopes:
// * https://www.googleapis.com/auth/iam
// * https://www.googleapis.com/auth/cloud-platform
func GenerateServiceAccountAuthToken(ctx context.Context, accessToken string, serviceAccount string, scope string) (*auth.Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	form := url.Values{}
	for _, s := range strings.Split(scope, " ") {
		form.Add("scope", s)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf(iamAccessTokenURL, serviceAccount), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && c != nil {
		client = c
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2l: IAM token generation failed: %v", err)
	}
	if code := resp.StatusCode; code < 200 || code > 299 {
		return nil, errors.New(string(body))
	}

	var itj iamTokenJSON
	if err = json.Unmarshal(body, &itj); err != nil {
		return nil, err
	}
	expiry, _ := time.Parse(time.RFC3339, itj.ExpireTime)
	var raw map[string]any
	json.Unmarshal(body, &raw)
	return &auth.Token{
		Value:    itj.AccessToken,
		Type:     "Bearer",
		Expiry:   expiry,
		Metadata: raw,
	}, nil
}

// GenerateServiceAccountAccessToken generates a Service Account access token using a User access
// token approved for at least one of the following scopes:
// * https://www.googleapis.com/auth/iam
// * https://www.googleapis.com/auth/cloud-platform
//
// Deprecated: Use GenerateServiceAccountAuthToken instead.
func GenerateServiceAccountAccessToken(accessToken string, serviceAccount string, scope string) (*oauth2.Token, error) {
	token, err := GenerateServiceAccountAuthToken(context.Background(), accessToken, serviceAccount, scope)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{
		AccessToken: token.Value,
		Expiry:      token.Expiry,
	}
	return t.WithExtra(token.Metadata), nil
}
