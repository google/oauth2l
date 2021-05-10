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

	"golang.org/x/oauth2"
)

const (
	defaultCli = "/google/data/ro/teams/oneplatform/sso"
)

// Fetches and returns OAuth access token using SSO CLI.
func SSOFetch(cli string, email string, scope string) (*oauth2.Token, error) {
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
	accessToken := out.String()
	token := oauth2.Token{}
	token.AccessToken = accessToken
	token.TokenType = "Bearer"
	return &token, nil
}
