//
// Copyright 2015 Google Inc.
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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/google/oauth2l/go/oauth2util"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"
)

func help() {
	log.Fatal("Usage: oauth2l --json <secret.json> {fetch|header|token} scope1 scope2 ...")
}

func fetch(token *oauth2.Token) {
	fmt.Println(token.AccessToken)
}

func header(token *oauth2.Token) {
	fmt.Printf("Authorization: %v %v\n", token.TokenType, token.AccessToken)
}

func token(token *oauth2.Token) {
	jsonBytes, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		log.Fatal("Failed to covert token to json.")
	}
	fmt.Println(string(jsonBytes))
}

func main() {
	jsonFile := flag.String("json", "", "Path to secret json file.")
	helpFlag := flag.Bool("help", false, "Print help message.")
	flag.BoolVar(helpFlag, "h", false, "")

	flag.Parse()

	if *helpFlag || len(flag.Args()) < 2 {
		help()
	}

	commands := map[string]func(*oauth2.Token){
		"fetch":  fetch,
		"header": header,
		"token":  token,
	}
	secretBytes, err := ioutil.ReadFile(*jsonFile)
	if err != nil {
		log.Fatalf("Failed to read file %v.\n", *jsonFile)
	}

	cmdFunc, ok := commands[flag.Args()[0]]
	if !ok {
		help()
	}

	scopes := flag.Args()[1:]
	// Append Google OAuth scope prefix if not provided.
	for i := 0; i < len(scopes); i++ {
		if !strings.Contains(scopes[i], "//") {
			scopes[i] = scopePrefix + scopes[i]
		}
	}
	client, err := oauth2util.NewTokenSource(context.Background(), secretBytes, nil, scopes...)
	if err != nil {
		log.Fatalf("Failed to create OAuth2 client: %v\n", err)
	}
	token, err := client.Token()
	if err != nil {
		log.Fatalf("Error getting token: %v\n", err)
	}

	cmdFunc(token)
}
