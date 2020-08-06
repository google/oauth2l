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
	"log"
	"os"
	"os/exec"
	"runtime"
)

const (
	defaultServer = "http://localhost:3000/"
)

// Runs the frontend/backend for OAuth2l Playground
func Web(directory string) {
	_, err := os.Stat(directory)
	if os.IsNotExist(err) {
		fmt.Println("Installing...")
		cmd := exec.Command("git", "clone", "https://github.com/googleinterns/oauth2l-web.git", directory)
		clonErr := cmd.Run()
		if clonErr != nil {
			log.Fatal(clonErr.Error())
		} else {
			fmt.Println("Web feature installed")
		}
	}
	cmd := exec.Command("docker-compose", "up", "-d", "--build")
	cmd.Dir = directory
	fmt.Println("barely running command")
	dockErr := cmd.Run()
	fmt.Println("ran command")
	if dockErr != nil {
		fmt.Println("Please ensure that Docker is installed.")
		log.Fatal(dockErr.Error())

	} else {
		openWeb()
	}
}

// opens the website on the default browser
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

// closes the containers and removes stopped containers
func WebStop(directory string) {
	cmd := exec.Command("docker-compose", "stop")
	cmd.Dir = directory
	err := cmd.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	remContainer := exec.Command("docker-compose", "rm", "-f")
	remContainer.Dir = directory
	remErr := remContainer.Run()
	if remErr != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("OAuth2l Playground was stopped.")
}
