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
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/google/oauth2l/sgauth"
	"github.com/wora/protorpc/client"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/example/library/v1"
)

func createSettings(args map[string]string) *sgauth.Settings {
	if args[kApiKey] != "" {
		return &sgauth.Settings{
			APIKey: args[kApiKey],
		}
	} else if args[kAud] != "" {
		return &sgauth.Settings{
			Audience: args[kAud],
		}
	} else {
		return &sgauth.Settings{
			Scope: args[kScope],
		}
	}
}

func newHTTPClient(ctx context.Context, args map[string]string) (
	*client.Client, error) {
	baseUrl := fmt.Sprintf("https://%s/$rpc/%s/", args[kHost], args[kApiName])

	http, err := sgauth.NewHTTPClient(ctx, createSettings(args))
	if err != nil {
		return nil, err
	}
	return &client.Client{
		HTTP:      http,
		BaseURL:   baseUrl,
		UserAgent: "protorpc/0.1",
	}, nil
}

func newGrpcClient(ctx context.Context, args map[string]string) (library.LibraryServiceClient, error) {
	conn, err := sgauth.NewGrpcConn(ctx, createSettings(args), args[kHost], "443")
	if err != nil {
		return nil, err
	}
	return library.NewLibraryServiceClient(conn), nil
}

func protoRPCExample(client *client.Client) {
	request := &library.ListShelvesRequest{}
	response := &library.ListShelvesResponse{}
	err := client.Call(context.Background(), "ListShelves", request, response)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(proto.MarshalTextString(response))
	}
}

func gRPCExample(client library.LibraryServiceClient) {
	request := &library.ListShelvesRequest{}
	response, err := client.ListShelves(context.Background(), request)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(proto.MarshalTextString(response))
	}
}
