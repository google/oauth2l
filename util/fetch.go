//
// Copyright 2021 Google Inc.
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
package util

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var DefaultScope = "https://www.googleapis.com/auth/cloud-platform"

// Default method to return a token source from a given settings.
// Returns nil for API keys.
func newTokenSource(ctx context.Context, settings *Settings) (*oauth2.TokenSource, error) {
	var ts oauth2.TokenSource
	var err error
	if settings == nil {
		ts, err = google.DefaultTokenSource(ctx, DefaultScope)
	} else if settings.GetAuthType() == AuthTypeAPIKey {
		return nil, nil
	} else if settings.GetAuthType() == AuthTypeOAuth {
		ts, err = OAuthJSONTokenSource(ctx, settings)
	} else if settings.GetAuthType() == AuthTypeJWT {
		ts, err = JWTTokenSource(ctx, settings)
	} else {
		return nil, fmt.Errorf("Unsupported authentcation method: %s", settings.GetAuthType())
	}
	if err != nil {
		return nil, err
	}
	return &ts, err
}

// Returns a token from the given settings.
// Returns nil for API keys.
func FetchToken(ctx context.Context, settings *Settings) (*oauth2.Token, error) {
	if settings.APIKey != "" {
		return nil, nil
	}
	src, err := newTokenSource(ctx, settings)
	if err != nil {
		return nil, err
	}
	ts := oauth2.ReuseTokenSource(nil, *src)
	t, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return t, nil
}

func OAuthJSONTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := FindJSONCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	return creds.TokenSource, nil

}

func JWTTokenSource(ctx context.Context, settings *Settings) (oauth2.TokenSource, error) {
	creds, err := FindJSONCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	if settings.Audience != "" {
		return google.JWTAccessTokenSourceFromJSON(creds.JSON, settings.Audience)
	} else if settings.Scope != "" {
		return google.JWTAccessTokenSourceWithScope(creds.JSON, settings.Scope)
	} else {
		return nil, errors.New("Neither audience nor scope is provided for JWTTokenSource")
	}
}

// FindJSONCredentials obtains credentials from settings or Application Default Credentials
func FindJSONCredentials(ctx context.Context, settings *Settings) (*google.Credentials, error) {
	var params google.CredentialsParams
	params.Scopes = strings.Split(settings.Scope, " ")
	params.State = "state"
	params.AuthHandler = settings.AuthHandler
	params.Subject = settings.Email
	params.PKCE = GeneratePKCEParams()
	if settings.CredentialsJSON != "" {
		return google.CredentialsFromJSONWithParams(ctx, []byte(settings.CredentialsJSON),
			params)

	} else {
		return google.FindDefaultCredentialsWithParams(ctx, params)

	}
}
