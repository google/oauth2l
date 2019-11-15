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
	"context"
	"fmt"
	"os"
)

func main() {
	args, err := parseArguments()
	if err != nil {
		printUsage()
		println(err.Error())
		return
	}

	if os.Args[1] == "protorpc" {
		if len(os.Args) < 3 {
			printUsage()
			return
		}
		c, err := newHTTPClient(context.Background(), args)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		protoRPCExample(c)
	} else if os.Args[1] == "grpc" {
		c, err := newGrpcClient(context.Background(), args)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		gRPCExample(c)
	} else {
		printUsage()
	}
}
