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
)

// Wrapper of internal.Token that is visible from public.
// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
type Token struct {
	internal.Token
}

// Default method to return a token source from a given settings.
// Returns nil for API keys.
func newTokenSource(ctx context.Context, settings *Settings) (*internal.TokenSource, error) {
	var ts internal.TokenSource
	var err error
	if settings == nil {
		ts, err = DefaultTokenSource(ctx, DefaultScope)
	} else if settings.APIKey != "" {
		return nil, nil
	} else if settings.Scope != "" {
		ts, err = OAuthJSONTokenSource(ctx, settings)
	} else {
		ts, err = JWTTokenSource(ctx, settings)
	}
	if err != nil {
		return nil, err
	}
	return &ts, err
}

// Returns a token from the given settings.
// Returns nil for API keys.
func FetchToken(ctx context.Context, settings *Settings) (*Token, error) {
	if settings.APIKey != "" {
		return nil, nil
	}
	src, err := newTokenSource(ctx, settings)
	if err != nil {
		return nil, err
	}
	ts := internal.ReuseTokenSource(nil, *src)
	t, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return &Token{*t}, nil
}
