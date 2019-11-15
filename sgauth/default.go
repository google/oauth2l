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
	"cloud.google.com/go/compute/metadata"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/oauth2l/sgauth/credentials"
	"github.com/google/oauth2l/sgauth/internal"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultTokenSource returns the token source for
// "Application Default Credentials".
// It is a shortcut for FindDefaultCredentials(ctx, scope).TokenSource.
func DefaultTokenSource(ctx context.Context, scope string) (internal.TokenSource, error) {
	creds, err := applicationDefaultCredentials(ctx, &Settings{Scope: scope})
	if err != nil {
		return nil, err
	}
	return creds.TokenSource, nil
}

func OAuthJSONTokenSource(ctx context.Context, settings *Settings) (internal.TokenSource, error) {
	creds, err := FindJSONCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	return creds.TokenSource, nil

}

func JWTTokenSource(ctx context.Context, settings *Settings) (internal.TokenSource, error) {
	creds, err := FindJSONCredentials(ctx, settings)
	if err != nil {
		return nil, err
	}
	ts, err := credentials.JWTAccessTokenSourceFromJSON(creds.JSON, settings.Audience)
	return ts, err
}

func FindJSONCredentials(ctx context.Context, settings *Settings) (*credentials.Credentials, error) {
	if settings.CredentialsJSON != "" {
		return credentialsFromJSON(ctx, []byte(settings.CredentialsJSON),
			strings.Split(settings.Scope, " "), settings.OAuthFlowHandler, settings.State)

	} else {
		return applicationDefaultCredentials(ctx, settings)

	}
}

func applicationDefaultCredentials(ctx context.Context, settings *Settings) (*credentials.Credentials, error) {
	const envVar = "GOOGLE_APPLICATION_CREDENTIALS"
	if filename := os.Getenv(envVar); filename != "" {
		creds, err := readCredentialsFile(ctx, filename, settings)
		if err != nil {
			return nil, fmt.Errorf("google: error getting credentials using %v environment variable: %v", envVar, err)
		}
		return creds, nil
	}
	// Second, try a well-known file.
	filename := wellKnownFile()
	if creds, err := readCredentialsFile(ctx, filename, settings); err == nil {
		return creds, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("google: error getting credentials using well-known file (%v): %v", filename, err)
	}

	// Third, if we're on Google App Engine use those credentials.
	if appengineTokenFunc != nil && !appengineFlex {
		return &credentials.Credentials{
			ProjectID:   appengineAppIDFunc(ctx),
			TokenSource: AppEngineTokenSource(ctx, settings.Scope),
		}, nil
	}

	// Fourth, if we're on Google Compute Engine use the metadata server.
	if metadata.OnGCE() {
		id, _ := metadata.ProjectID()
		return &credentials.Credentials{
			ProjectID:   id,
			TokenSource: ComputeTokenSource(""),
		}, nil
	}

	// None are found; return helpful error.
	const url = "https://developers.google.com/accounts/docs/application-default-credentials"
	return nil, fmt.Errorf("google: could not find default credentials. See %v for more information.", url)
}

func readCredentialsFile(ctx context.Context, filename string, settings *Settings) (*credentials.Credentials, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return credentialsFromJSON(ctx, b, strings.Split(settings.Scope, " "),
		settings.OAuthFlowHandler, settings.State)
}

func credentialsFromJSON(ctx context.Context, jsonData []byte, scopes []string,
	handler func(string) (string, error), state string) (*credentials.Credentials, error) {
	var f credentials.File
	if err := json.Unmarshal(jsonData, &f); err != nil {
		return nil, err
	}
	ts, err := f.TokenSource(ctx, scopes, handler, state)
	if err != nil {
		return nil, err
	}
	return &credentials.Credentials{
		ProjectID:   f.ProjectID,
		TokenSource: ts,
		JSON:        jsonData,
		Type:        f.CredentialsType(),
	}, nil
}

func wellKnownFile() string {
	const f = "application_default_credentials.json"
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gcloud", f)
	}
	return filepath.Join(GuessUnixHomeDir(), ".config", "gcloud", f)
}

func GuessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}
