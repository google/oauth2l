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
package main

import (
	"errors"
	"fmt"
	"os"
)

var (
	kScope   = "scope"
	kAud     = "aud"
	kHost    = "host"
	kApiName = "api_name"
	kApiKey  = "api_key"
)

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}

func getFlagValue(flag string) string {
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == flag {
			if len(os.Args) < i+2 {
				printUsage()
				return ""
			}
			return os.Args[i+1]
		}
	}
	printUsage()
	return ""
}

func printUsage() {
	fmt.Println("Usage: cmd [grpc|protorpc] --[aud|scope] [--host] [--api_name]")
}

func parseArguments() (map[string]string, error) {
	args := make(map[string]string)
	args[kScope] = ""
	args[kAud] = ""
	args[kHost] = ""
	args[kApiName] = ""
	args[kApiKey] = ""

	if contains(os.Args, "--host") {
		args[kHost] = getFlagValue("--host")
	} else {
		return nil, errors.New("Invalid argument: --host is required")
	}

	if contains(os.Args, "--aud") {
		args[kAud] = getFlagValue("--aud")
	}

	if contains(os.Args, "--scope") {
		args[kScope] = getFlagValue("--scope")
	}

	if contains(os.Args, "--api_key") {
		args[kApiKey] = getFlagValue("--api_key")
	}

	if contains(os.Args, "--api_name") {
		args[kApiName] = getFlagValue("--api_name")
	} else if os.Args[1] == "protorpc" {
		return nil, errors.New("Invalid argument: --api_name is required for ProtoRPC mode")
	}

	if args[kApiKey] == "" && args[kScope] == "" && args[kAud] == "" {
		if args[kApiName] != "" {
			args[kAud] = fmt.Sprintf("https://%s/%s", args[kHost], args[kApiName])
		} else {
			return nil, errors.New("Invalid argument: scope and aud cannot be both empty.")
		}
	}

	return args, nil
}
