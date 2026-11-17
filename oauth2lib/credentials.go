//
// Copyright 2026 Google LLC
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

package oauth2lib

import (
	"context"
	"log/slog"
	"net/http"
)

// Config describes one credential. The caller (for example Go gcloud)
// resolves every field; oauth2lib reads no configuration of its own.
type Config struct {
	// JSON is the credential file: authorized_user, service_account or
	// impersonated_service_account.
	JSON []byte
	// Scopes are sent with every token request. If nil, the JSON's "scopes"
	// field is used, if any.
	Scopes []string
	// TokenURL overrides the JSON's token_uri for authorized_user and
	// service_account credentials. If empty, the JSON's token_uri is used,
	// and https://oauth2.googleapis.com/token if the JSON has none.
	TokenURL string
	// UniverseDomain is the universe domain of the credential.
	UniverseDomain string
	// Client is used for every network call. It must not add its own
	// Authorization header.
	Client *http.Client
	// RAPT returns the latest reauth proof token before each user refresh.
	// ("", nil) omits rapt, (t, nil) sends rapt=t, and an error stops Token
	// before any request is made. Nil for non-user credentials, or to never
	// send a RAPT.
	RAPT func(ctx context.Context) (string, error)
	// UseSelfSignedJWT makes service account credentials sign a JWT locally
	// instead of calling the token endpoint.
	UseSelfSignedJWT bool
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger
}
