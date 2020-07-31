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
	"strings"
)

const (
	defaultServer = "http://localhost:3000/"
)

var location string = "~/.oauth2l-web"

// Runs the frontend/backend for OAuth2l Playground
func Web() {
	_, err := os.Stat("~/.oauth2l-web")
	if os.IsNotExist(err) {
		var decision string
		fmt.Println("The Web feature will be installed in ~/.oauth2l-web. Would you like to change the directory? (y/n)")
		fmt.Scanln(&decision)
		decision = strings.ToLower(decision)
		if decision == "y" || decision == "yes" {
			fmt.Println("Enter new directory location")
			fmt.Scanln(&location)
		}
		fmt.Println("Installing...")
		cmd := exec.Command("git", "clone", "https://github.com/googleinterns/oauth2l-web.git", location)
		clonErr := cmd.Run()
		if clonErr != nil {
			log.Fatal(clonErr.Error())
		} else {
			fmt.Println("Web feature installed")
		}
	}
	cmd := exec.Command("docker-compose", "up", "-d", "--build")
	cmd.Dir = location

	dockErr := cmd.Run()

	if dockErr != nil {
		fmt.Println("Check to see if Docker is running!")
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
func WebStop() {
	cmd := exec.Command("docker-compose", "stop")
	cmd.Dir = location
	err := cmd.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	remContainer := exec.Command("docker-compose", "rm", "-f")
	remContainer.Dir = location
	remErr := remContainer.Run()
	if remErr != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("OAuth2l Playground was stopped.")
}
