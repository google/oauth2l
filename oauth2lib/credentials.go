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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"unicode"

	"cloud.google.com/go/auth"
)

// Config describes one credential. The caller (for example Go gcloud)
// resolves every field; oauth2lib reads no configuration of its own.
type Config struct {
	// JSON is the credential file: authorized_user, service_account or
	// impersonated_service_account.
	JSON []byte
	// Scopes are sent with every token request. Surrounding spaces are
	// trimmed and empty entries dropped; a scope with a space inside it is an
	// error, since scopes are sent space-separated. If no scopes remain, the
	// JSON's "scopes" field is used, if any.
	Scopes []string
	// TokenURL overrides the JSON's token_uri for authorized_user and
	// service_account credentials. If empty, the JSON's token_uri is used,
	// and https://oauth2.googleapis.com/token if the JSON has none.
	TokenURL string
	// UniverseDomain is used when the credential JSON has no universe_domain.
	// The JSON's own universe_domain always wins, since a key belongs to the
	// universe that issued it. A key file without universe_domain was issued
	// in googleapis.com, so for a key file pass that file's universe
	// (googleapis.com when absent), not core/universe_domain; otherwise the
	// credentials can't reveal a mismatch with core/universe_domain. Go
	// gcloud's file-override path already resolves it this way. For service
	// accounts, a non-default value also turns on self-signed JWTs, as in
	// Python gcloud. Leading and trailing spaces are ignored.
	UniverseDomain string
	// Client is used for every network call. It must not add its own
	// Authorization header.
	Client *http.Client
	// RAPT returns the latest reauth proof token before each user refresh.
	// ("", nil) omits rapt, (t, nil) sends rapt=t, and an error stops Token
	// before any request is made. Nil to never send a RAPT. Ignored for
	// credentials other than authorized_user, as in Python gcloud.
	RAPT func(ctx context.Context) (string, error)
	// UseSelfSignedJWT makes service account credentials sign a JWT locally
	// instead of calling the token endpoint. Ignored for credentials other
	// than service_account, as in Python gcloud (creds.UseSelfSignedJwt).
	UseSelfSignedJWT bool
	// Logger receives debug logs. Nil discards them.
	Logger *slog.Logger
}

// String describes c without the contents of JSON, which holds secrets
// (refresh tokens, client secrets or private keys).
func (c Config) String() string {
	return fmt.Sprintf("oauth2lib.Config{TokenURL:%q UniverseDomain:%q Scopes:%q JSON:[REDACTED %d bytes]}",
		c.TokenURL, c.UniverseDomain, c.Scopes, len(c.JSON))
}

// GoString makes %#v print the same as String, so it does not dump JSON.
func (c Config) GoString() string { return c.String() }

// LogValue implements slog.LogValuer without the contents of JSON.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("token_url", c.TokenURL),
		slog.String("universe_domain", c.UniverseDomain),
		slog.Any("scopes", c.Scopes),
		slog.Int("json_bytes", len(c.JSON)),
	)
}

// credentialType reads only the "type" and "universe_domain" fields of a
// credential file.
type credentialType struct {
	Type           string `json:"type"`
	UniverseDomain string `json:"universe_domain"`
}

// BuildCredentials returns credentials for cfg.JSON, which must be an
// authorized_user or service_account credential file.
//
// The returned credentials' TokenProvider is not cached: each Token call
// blocks on a new token request (or, for a self-signed JWT, signs a new JWT
// locally) and returns a *RefreshError when the token endpoint fails, or
// the context's error when ctx is done. JSON returns a copy of cfg.JSON, and
// UniverseDomain returns the JSON's universe_domain, else
// cfg.UniverseDomain, else googleapis.com (surrounding spaces ignored).
//
// BuildCredentials reads no files, environment variables or gcloud
// properties, and makes no network calls. cfg is copied, so changing it
// afterwards does not affect the credentials.
//
// oauth2lib sets no quota project or project ID. go/auth's QuotaProjectID
// and ProjectID still fall back to environment variables and to the JSON's
// quota_project_id and project_id, so callers should decide the quota project
// themselves and should not pass the credentials to go/auth's httptransport
// or grpctransport.
func BuildCredentials(ctx context.Context, cfg *Config) (*auth.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, ct, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}
	logger := c.Logger
	if logger == nil {
		logger = discardLogger
	}

	var (
		tp       auth.TokenProvider
		universe string
	)
	switch ct.Type {
	case "authorized_user":
		p, err := newUserTokenProvider(c)
		if err != nil {
			return nil, err
		}
		tp = p
		universe = resolveUniverseDomain(ct.UniverseDomain, c.UniverseDomain)
	case "service_account":
		p, err := newServiceAccountTokenProvider(c)
		if err != nil {
			return nil, err
		}
		tp = p
		universe = p.universeDomain
	case "impersonated_service_account":
		return nil, errors.New("oauth2lib: impersonated_service_account credentials are not supported yet")
	case "external_account", "external_account_authorized_user":
		return nil, fmt.Errorf("oauth2lib: %s credentials are not supported", ct.Type)
	case "":
		return nil, errors.New(`oauth2lib: credential JSON has no "type"`)
	default:
		return nil, fmt.Errorf("oauth2lib: unsupported credential type %q", ct.Type)
	}

	logger.DebugContext(ctx, "oauth2lib: built credentials",
		slog.String("type", ct.Type),
		slog.String("universe_domain", universe))
	return auth.NewCredentials(&auth.CredentialsOptions{
		TokenProvider: tp,
		JSON:          c.JSON,
		UniverseDomainProvider: auth.CredentialsPropertyFunc(func(context.Context) (string, error) {
			return universe, nil
		}),
	}), nil
}

// resolveUniverseDomain returns a credential's universe domain: the JSON's
// universe_domain, else the caller's Config.UniverseDomain, else
// googleapis.com, ignoring surrounding spaces. A key belongs to the universe
// that issued it, so the JSON wins. It only reports the universe: whether a
// service account self-signs is decided separately (serviceaccount.go), since
// a non-default Config.UniverseDomain turns that on even when the JSON says
// googleapis.com.
func resolveUniverseDomain(jsonUniverse, cfgUniverse string) string {
	if u := strings.TrimSpace(jsonUniverse); u != "" {
		return u
	}
	if u := strings.TrimSpace(cfgUniverse); u != "" {
		return u
	}
	return defaultUniverseDomain
}

// validateConfig checks the fields every credential type needs and returns
// a copy of cfg, with its own copies of JSON and Scopes, and the JSON's type.
func validateConfig(cfg *Config) (*Config, credentialType, error) {
	var ct credentialType
	if cfg == nil {
		return nil, ct, errors.New("oauth2lib: Config is nil")
	}
	if cfg.Client == nil {
		return nil, ct, errors.New("oauth2lib: Config.Client is nil")
	}
	trimmed := bytes.TrimSpace(cfg.JSON)
	if len(trimmed) == 0 {
		return nil, ct, errors.New("oauth2lib: Config.JSON is empty")
	}
	// The JSON holds secrets, so the parse error (which can quote it) is not
	// wrapped. Parse cfg.JSON itself, the same bytes the providers parse:
	// bytes.TrimSpace also strips Unicode spaces (such as U+00A0) that
	// encoding/json rejects. Requiring '{' also rejects null, which
	// json.Unmarshal accepts without error, arrays and strings.
	if trimmed[0] != '{' {
		return nil, ct, errors.New("oauth2lib: Config.JSON is not a JSON object")
	}
	if err := json.Unmarshal(cfg.JSON, &ct); err != nil {
		// An object whose "type" or "universe_domain" isn't a string: name
		// the field, never its value.
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) && typeErr.Field != "" {
			return nil, ct, fmt.Errorf("oauth2lib: Config.JSON field %q must be a string", typeErr.Field)
		}
		return nil, ct, errors.New("oauth2lib: Config.JSON is not a JSON object")
	}
	// Trim each scope and drop empty ones, as the providers do (cleanScopes),
	// so []string{""} means no scopes. cleanScopes returns a new slice.
	scopes := cleanScopes(cfg.Scopes)
	for _, s := range scopes {
		// Scopes are sent space-separated, so one with a space inside would
		// silently become several.
		if strings.ContainsFunc(s, unicode.IsSpace) {
			return nil, ct, fmt.Errorf("oauth2lib: Config.Scopes has a scope with spaces in it: %q", s)
		}
	}
	c := *cfg
	c.JSON = bytes.Clone(cfg.JSON)
	c.Scopes = scopes
	return &c, ct, nil
}
