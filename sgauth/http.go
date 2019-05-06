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
	"github.com/google/oauth2l/sgauth/internal"
	"golang.org/x/net/context"
	"net/http"
)

var DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// Returns the HTTP client using the given settings.
func NewHTTPClient(ctx context.Context, settings *Settings) (*http.Client, error) {
	if settings == nil {
		settings = &Settings{
			Scope: DefaultScope,
		}
	}
	transport := &internal.Transport{
		Base:         http.DefaultClient.Transport,
		QuotaUser:    settings.QuotaUser,
		QuotaProject: settings.QuotaProject,
	}

	if settings.APIKey != "" {
		// API key
		transport.APIKey = settings.APIKey
	} else {
		// OAuth or JWT token
		ts, err := newTokenSource(ctx, settings)
		if err != nil {
			return nil, err
		}
		transport.Source = *ts
	}
	return &http.Client{
		Transport: transport,
	}, nil
}
