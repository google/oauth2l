package main

import (
	"fmt"
	"io/ioutil"
	"log"

	// [START imports]
	"cloud.google.com/go/pubsub"
	"github.com/google/oauth2l/go/oauth2util"
	"golang.org/x/net/context"
	"google.golang.org/api/option"
	// [END imports]
)

func main() {
	ctx := context.Background()

	// Read a service account key json from a local file. WARNING: you
	// should never embed the service account key as a string literal
	// in the source code.
	key, err := ioutil.ReadFile("service_account_key.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// Create new http.Client from service account key and pubsub OAuth scope.
	// For the service account auth, authorizeHandler is not used. If you want
	// to use authentication based on runtime context, you can simply pass
	// nil instead of key.
	c, err := oauth2util.NewClient(ctx, key, nil /* authorizeHandler */, pubsub.ScopePubSub)
	if err != nil {
		log.Fatalf("Failed to get OAuth token: %v", err)
	}

	// Create pubsub.Client from http.Client.
	// TODO: Change "project-id" to your project id.
	client, err := pubsub.NewClient(ctx, "project-id", option.WithHTTPClient(c))
	if err != nil {
		log.Fatalf("Could not create pubsub Client: %v", err)
	}

	// Print all the topics in the project.
	fmt.Println("Listing all topics from the project:")
	it := client.Topics(ctx)
	for {
		topic, err := it.Next()
		if err != nil {
			break
		}
		fmt.Println(topic.String())
	}
}
