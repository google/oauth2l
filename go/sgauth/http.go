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
package sgauth

import (
	"github.com/shinfan/sgauth/internal"
	"net/http"
	"golang.org/x/net/context"
)

// createClient creates an *http.Client from a TokenSource.
// The returned client is not valid beyond the lifetime of the context.
func createAuthTokenClient(src internal.TokenSource) *http.Client {
	if src == nil {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &Transport{
			Base:   http.DefaultClient.Transport,
			Source: internal.ReuseTokenSource(nil, src),
		},
	}
}

// createClient creates an *http.Client from a TokenSource.
// The returned client is not valid beyond the lifetime of the context.
func createAPIKeyClient(key string) *http.Client {
	if key == "" {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &Transport{
			Base:   http.DefaultClient.Transport,
			APIKey: key,
		},
	}
}

var DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// DefaultClient returns an HTTP Client that uses the
// DefaultTokenSource to obtain authentication credentials.
func NewHTTPClient(ctx context.Context, settings *Settings) (*http.Client, error) {
	if settings.APIKey != "" {
		return createAPIKeyClient(settings.APIKey), nil
	} else {
		ts, err := newTokenSource(ctx, settings)
		if err != nil {
			return nil, err
		}
		return createAuthTokenClient(*ts), nil
	}
}
