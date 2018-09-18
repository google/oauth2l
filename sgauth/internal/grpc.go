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

import "context"

// TokenSource supplies PerRPCCredentials from an oauth2.TokenSource.
type GrpcTokenSource struct {
	Source TokenSource
	ApiKey string

	// Additional metadata attached as headers
	QuotaUser    string
	QuotaProject string
}

// GetRequestMetadata gets the request metadata as a map from a TokenSource.
func (ts GrpcTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (
	map[string]string, error) {
	metadata := map[string]string{}
	if ts.ApiKey != "" {
		metadata[headerApiKey] = ts.ApiKey
	} else {
		token, err := ts.Source.Token()
		if err != nil {
			return nil, err
		}
		metadata[headerAuth] = token.Type() + " " + token.AccessToken
	}
	attachAdditionalMetadata(metadata, ts)
	return metadata, nil
}

// RequireTransportSecurity indicates whether the credentials requires transport security.
func (ts GrpcTokenSource) RequireTransportSecurity() bool {
	return true
}

func attachAdditionalMetadata(metadata map[string]string, ts GrpcTokenSource) {
	if ts.QuotaUser != "" {
		metadata[headerQuotaUser] = ts.QuotaUser
	}
	if ts.QuotaProject != "" {
		metadata[headerQuotaProject] = ts.QuotaProject
	}
}
