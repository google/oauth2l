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
	"fmt"
	"os/exec"
	"strings"
)

const (
	defaultCli = "/google/data/ro/teams/oneplatform/sso"
)

// Fetches and returns OAuth access token using SSO CLI.
func SSOFetch(email string, cli string, task string, scope string) (string, error) {
	if cli == "" {
		cli = defaultCli
	}
	cmdArgs := append([]string{email}, strings.Split(scope, " ")...)
	cmd := exec.Command(cli, cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
		return "", err
	} else {
		return out.String(), nil
	}
}
