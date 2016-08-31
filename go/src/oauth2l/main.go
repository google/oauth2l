package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"oauth2client"
	"strings"
)

const (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"
)

func help() {
	fmt.Println("Usage: oauth2l --json <secret.json> " +
		"{fetch|header|token} scope1 scope2 ...")
}

func fetch(token *oauth2client.Token) {
	fmt.Println(token.AccessToken)
}

func header(token *oauth2client.Token) {
	fmt.Printf("Authorization: %s %s\n", token.TokenType, token.AccessToken)
}

func token(token *oauth2client.Token) {
	jsonStr, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		panic("Failed to covert token to json.")
	}
	fmt.Println(string(jsonStr))
}

func main() {
	jsonFile := flag.String("json", "", "Path to secret json file.")
	helpFlag := flag.Bool("help", false, "Print help message.")
	flag.BoolVar(helpFlag, "h", false, "")

	flag.Parse()

	if *helpFlag || len(flag.Args()) < 2 {
		help()
		return
	}

	commands := map[string]func(*oauth2client.Token){
		"fetch":  fetch,
		"header": header,
		"token":  token,
	}
	secretBytes, err := ioutil.ReadFile(*jsonFile)
	if err != nil {
		fmt.Printf("Failed to read file %s.\n", *jsonFile)
		return
	}

	cmdFunc, ok := commands[flag.Args()[0]]
	if !ok {
		help()
		return
	}

	scopes := flag.Args()[1:]
	// Append Google OAuth scope prefix if not provided.
	for i := 0; i < len(scopes); i++ {
		if !strings.Contains(scopes[i], "//") {
			scopes[i] = scopePrefix + scopes[i]
		}
	}
	client, err := oauth2client.NewClient(secretBytes, nil)
	if err != nil {
		fmt.Printf("Failed to create OAuth2 client: %s\n", err)
		return
	}
	token, err := client.GetToken(strings.Join(scopes, " "))
	if err != nil {
		fmt.Printf("Error getting token: %s\n", err)
		return
	}

	cmdFunc(token)
}
