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

	// [START auth]

	// Read service account key from local file.
	b, err := ioutil.ReadFile("service_account_key.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// Create new http.Client from service account key and pubsub OAuth scope.
	// For service account auth, authorizeHandler is not used.
	c, err := oauth2util.NewClient(ctx, b, nil /* authorizeHandler */, pubsub.ScopePubSub)
	if err != nil {
		log.Fatalf("Failed to get OAuth token: %v", err)
	}

	// Create pubsub.Client from http.Client.
	// TODO: Change "project-id" to your project id.
	client, err := pubsub.NewClient(ctx, "project-id", option.WithHTTPClient(c))
	if err != nil {
		log.Fatalf("Could not create pubsub Client: %v", err)
	}
	// [END auth]

	// Print all the subscriptions in the project.
	fmt.Println("Listing all subscriptions from the project:")
	subs, err := list(client)
	if err != nil {
		log.Fatal(err)
	}
	for _, sub := range subs {
		fmt.Println(sub)
	}
}

func list(client *pubsub.Client) ([]*pubsub.Subscription, error) {
	ctx := context.Background()
	// [START get_all_subscriptions]
	var subs []*pubsub.Subscription
	it := client.Subscriptions(ctx)
	for {
		s, err := it.Next()
		if err == pubsub.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		subs = append(subs, s)
	}
	// [END get_all_subscriptions]
	return subs, nil
}
