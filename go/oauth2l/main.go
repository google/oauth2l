package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"github.com/shinfan/sgauth"
	"context"
)

const (
	// Common prefix for google oauth scope
	scopePrefix = "https://www.googleapis.com/auth/"
)

func help() {
	fmt.Println("Usage: oauth2l --json <secret.json> " +
		"{fetch|header|token} scope1 scope2 ...")
}

func fetch(token *sgauth.Token) {
	fmt.Println(token.AccessToken)
}

func header(token *sgauth.Token) {
	fmt.Printf("Authorization: %s %s\n", token.TokenType, token.AccessToken)
}

func token(token *sgauth.Token) {
	jsonStr, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		panic("Failed to covert token to json.")
	}
	fmt.Println(string(jsonStr))
}

// Default 3LO authorization handler. Prints the authorization URL on stdout
// and reads the verification code from stdin.
func defaultAuthorizeFlowHandler(authorizeUrl string) (string, error) {
	// Print the url on console, let user authorize and paste the token back.
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authorizeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, nil
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

	commands := map[string]func(*sgauth.Token){
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
	for i := 0; i < len(scopes); i++ {
		// Append Google OAuth scope prefix if not provided.
		if !strings.Contains(scopes[i], "//") {
			scopes[i] = scopePrefix + scopes[i]
		}
	}

	settings := &sgauth.Settings{
		CredentialsJSON: string(secretBytes),
		Scope: strings.Join(scopes, " "),
		OAuthFlowHandler: defaultAuthorizeFlowHandler,
		State: "state",
	}

	token, err := sgauth.FetchToken(context.Background(), settings)
	if err != nil {
		fmt.Printf("Error getting token: %s\n", err)
		return
	}
	cmdFunc(token)
}
