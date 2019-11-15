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
package sgauth

import (
	"cloud.google.com/go/compute/metadata"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/oauth2l/sgauth/internal"
	"strings"
	"time"
)

// ComputeTokenSource returns a token source that fetches access tokens
// from Google Compute Engine (GCE)'s metadata server. It's only valid to use
// this token source if your program is running on a GCE instance.
// If no account is specified, "default" is used.
// Further information about retrieving access tokens from the GCE metadata
// server can be found at https://cloud.google.com/compute/docs/authentication.
func ComputeTokenSource(account string) internal.TokenSource {
	return internal.ReuseTokenSource(nil, computeSource{account: account})
}

type computeSource struct {
	account string
}

func (cs computeSource) Token() (*internal.Token, error) {
	if !metadata.OnGCE() {
		return nil, errors.New("oauth2/google: can't get a token from the metadata service; not running on GCE")
	}
	acct := cs.account
	if acct == "" {
		acct = "default"
	}
	tokenJSON, err := metadata.Get("instance/service-accounts/" + acct + "/token")
	if err != nil {
		return nil, err
	}
	var res struct {
		AccessToken  string `json:"access_token"`
		ExpiresInSec int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	err = json.NewDecoder(strings.NewReader(tokenJSON)).Decode(&res)
	if err != nil {
		return nil, fmt.Errorf("oauth2/google: invalid token JSON from metadata: %v", err)
	}
	if res.ExpiresInSec == 0 || res.AccessToken == "" {
		return nil, fmt.Errorf("oauth2/google: incomplete token received from metadata")
	}
	return &internal.Token{
		AccessToken: res.AccessToken,
		TokenType:   res.TokenType,
		Expiry:      time.Now().Add(time.Duration(res.ExpiresInSec) * time.Second),
	}, nil
}
