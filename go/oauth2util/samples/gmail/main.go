package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/google/oauth2l/go/oauth2util"
	"golang.org/x/net/context"
	"google.golang.org/api/gmail/v1"
)

func main() {
	ctx := context.Background()

	// [START auth]

	// Read client secret json from local file.
	b, err := ioutil.ReadFile("client_secret.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// Create new http.Client from client secret json.
	//
	// Here we pass authorizeHandler as nil, the function will use a default
	// authorize handler, which prints a URL to console and let you paste the
	// verification code back to console. You can also provide your own authorize
	// handler.
	c, err := oauth2util.NewClient(ctx, b, nil /* authorizeHandler */, gmail.GmailReadonlyScope)
	if err != nil {
		log.Fatalf("Failed to get OAuth2 token.")
	}

	// Create a gmail.Service from http.Client.
	srv, err := gmail.New(c)
	if err != nil {
		log.Fatalf("Unable to retrieve gmail Client %v", err)
	}
	// [END auth]

	r, err := srv.Users.Labels.List("me").Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels. %v", err)
	}
	fmt.Print("Labels:\n")
	for _, l := range r.Labels {
		fmt.Printf("- %s\n", l.Name)
	}

}
