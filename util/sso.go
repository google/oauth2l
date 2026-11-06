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
	"bytes"
	"os/exec"
	"strings"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2"
)

const (
	defaultCli = "/google/data/ro/teams/oneplatform/sso"
)

// SSOAuthFetch fetches and returns an OAuth access token using SSO CLI.
func SSOAuthFetch(cli string, email string, scope string) (*auth.Token, error) {
	if cli == "" {
		cli = defaultCli
	}
	cmdArgs := append([]string{email}, strings.Split(scope, " ")...)
	cmd := exec.Command(cli, cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return &auth.Token{
		Value: out.String(),
		Type:  "Bearer",
	}, nil
}

// Fetches and returns OAuth access token using SSO CLI.
//
// Deprecated: Use SSOAuthFetch instead.
func SSOFetch(cli string, email string, scope string) (*oauth2.Token, error) {
	token, err := SSOAuthFetch(cli, email, scope)
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{
		AccessToken: token.Value,
		TokenType:   token.Type,
	}, nil
}
