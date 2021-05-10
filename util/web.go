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
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	defaultServer         = "http://localhost:3000/"
	defaultWebPackageName = ".oauth2l-web"
)

var WebDirectory string = filepath.Join(GuessUnixHomeDir(), defaultWebPackageName)

// Runs the frontend/backend for OAuth2l Playground
func Web() {
	_, err := os.Stat(WebDirectory)
	if os.IsNotExist(err) {
		fmt.Println("Installing...")
		cmd := exec.Command("git", "clone", "https://github.com/googleinterns/oauth2l-web.git", WebDirectory)
		cmdErr := cmd.Run()
		if cmdErr != nil {
			fmt.Println("Failed to install web feature.")
			log.Fatal(cmdErr.Error())
		} else {
			fmt.Println("Web feature installed")
		}
	}
	cmd := exec.Command("docker-compose", "up", "-d", "--build")
	cmd.Dir = WebDirectory

	// Capture actual error message from docker command, if there is any
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	cmdErr := cmd.Run()
	if cmdErr != nil {
		fmt.Println(stderr.String())
		log.Fatal(cmdErr.Error())
	} else {
		openWeb()
	}
}

// Opens the website on the default browser
func openWeb() error {
	var cmd string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	case "windows":
		cmd = "start"
	default:
		cmd = "Not currently supported"
	}

	return exec.Command(cmd, defaultServer).Start()
}

// Closes the containers and removes stopped containers
func WebStop() {
	cmd := exec.Command("docker-compose", "stop")
	cmd.Dir = WebDirectory
	err := cmd.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	remContainer := exec.Command("docker-compose", "rm", "-f")
	remContainer.Dir = WebDirectory
	remErr := remContainer.Run()
	if remErr != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("OAuth2l Playground was stopped.")
}
