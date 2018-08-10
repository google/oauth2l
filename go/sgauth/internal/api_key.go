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
package internal

import "golang.org/x/net/context"

// TokenSource supplies PerRPCCredentials from an oauth2.TokenSource.
type GrpcApiKey struct {
	Value string
}

// GetRequestMetadata gets the request metadata as a map from a TokenSource.
func (key GrpcApiKey) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"x-goog-api-key": key.Value,
	}, nil
}

// RequireTransportSecurity indicates whether the credentials requires transport security.
func (key GrpcApiKey) RequireTransportSecurity() bool {
	return true
}
