//
// Copyright 2019 Google Inc.
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
)

const (
	defaultCurlCli = "/usr/bin/curl"
)

// Executes curl command with provided header and params.
func CurlCommand(cli string, header string, url string, extraArgs ...string) {
	if cli == "" {
		cli = defaultCurlCli
	}
	requiredArgs := []string{"-H", header, url}
	cmdArgs := append(requiredArgs, extraArgs...)

	cmd := exec.Command(cli, cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
	}
	print(out.String())
}
