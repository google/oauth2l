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
package credentials

import (
	"errors"
	"fmt"
	"github.com/google/oauth2l/sgauth/internal"
	"golang.org/x/net/context"
)

// DefaultTokenURL is Google's OAuth 2.0 token URL to use with the service
// account flow.
const DefaultTokenURL = "https://oauth2.googleapis.com/token"

// DefaultAuthURL is Google's OAuth 2.0 Auth URL to use with the end-user
// authentication flow.
const DefaultAuthURL = "https://accounts.google.com/o/oauth2/auth"

// JSON key file types.
const (
	ServiceAccountKey  = "service_account"
	UserCredentialsKey = "authorized_user"
	OAuthClientKey     = "oauth_client"
)

// Contains data for OAuthClient key.
type OAuthClient struct {
	ProjectID    string   `json:"project_id"`
	ClientSecret string   `json:"client_secret"`
	ClientID     string   `json:"client_id"`
	TokenURL     string   `json:"token_uri"`
	AuthURL      string   `json:"auth_uri"`
	RedirectURL  []string `json:"redirect_uris"`
}

// File is the unmarshalled representation of a credentials file.
type File struct {
	// serviceAccountKey or userCredentialsKey
	// Otherwise empty.
	Type string `json:"type"`

	// Service Account fields
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURL     string `json:"token_uri"`
	AuthURL      string `json:"auth_uri"`
	ProjectID    string `json:"project_id"`

	// User Credential fields
	// (These typically come from gcloud auth.)
	ClientSecret string `json:"client_secret"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`

	// Web application credential
	Web OAuthClient `json:"web"`

	// Other application credential
	Installed OAuthClient `json:"installed"`
}

// Returns the credential type of the file.
func (f *File) CredentialsType() string {
	if f.Type != "" {
		return f.Type
	} else if f.Web.ProjectID != "" || f.Installed.ProjectID != "" {
		return OAuthClientKey
	}
	return ""
}

// Construct the corresponding token source based on the type of the file.
func (f *File) TokenSource(ctx context.Context, scopes []string,
	handler func(string) (string, error), state string) (internal.TokenSource, error) {
	switch f.CredentialsType() {
	case ServiceAccountKey:
		cfg := JWTConfigFromFile(f, scopes)
		return cfg.TokenSource(ctx), nil
	case UserCredentialsKey:
		authURL := f.AuthURL
		tokenURL := f.TokenURL
		// Falling back to default URLs only if file URLs are empty
		if authURL == "" {
			authURL = DefaultAuthURL
		}
		if tokenURL == "" {
			tokenURL = DefaultTokenURL
		}
		cfg := &internal.Config{
			ClientID:     f.ClientID,
			ClientSecret: f.ClientSecret,
			Scopes:       scopes,
			Endpoint: internal.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
		}
		tok := &internal.Token{RefreshToken: f.RefreshToken}
		return cfg.TokenSource(ctx, tok), nil
	case OAuthClientKey:
		var oauth OAuthClient
		if f.Web.ProjectID != "" {
			oauth = f.Web
		} else {
			oauth = f.Installed
		}

		if len(oauth.RedirectURL) == 0 {
			// Redirect URL is a required field for end-user oauth flow.
			return nil, errors.New("incomplete client key: redirect url is missing")
		}

		if handler == nil {
			handler = defaultAuthorizeFlowHandler
		}

		cfg := &internal.Config{
			ClientID:     oauth.ClientID,
			ClientSecret: oauth.ClientSecret,
			Scopes:       scopes,
			Endpoint: internal.Endpoint{
				AuthURL:  oauth.AuthURL,
				TokenURL: oauth.TokenURL,
			},
			FlowHandler: handler,
			State:       state,
			RedirectURL: oauth.RedirectURL[0],
		}
		return cfg.TokenSource(ctx, nil), nil
	default:
		return nil, fmt.Errorf("unknown credential type: %q", f.Type)
	}
}

// Default 3LO authorization handler. Prints the authorization URL on stdout
// and reads the verification code from stdin.
func defaultAuthorizeFlowHandler(authorizeUrl string) (string, error) {
	// Print the url on console, let user authorize and paste the token back.
	fmt.Printf("Go to the following link in your browser:\n\n   %s\n\n", authorizeUrl)
	fmt.Println("Enter verification code: ")
	var code string
	fmt.Scanln(&code)
	return code, nil
}
