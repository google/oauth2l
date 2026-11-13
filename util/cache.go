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
package util

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2"
)

const CacheFileName = ".oauth2l"

var CacheLocation string = filepath.Join(GuessUnixHomeDir(), CacheFileName)

// The key struct that used to identify an auth token fetch operation.
type CacheKey struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// If specified, use OAuth. Otherwise, JWT.
	Scope string
	// The audience field for JWT auth and UAT
	Audience string
	// The email used for SSO and domain-wide delegation.
	Email string
	// The Google API key
	APIKey string
	// The QuotaProject field for STS
	QuotaProject string
	// If specified, performs STS exchange on top of base OAuth
	Sts bool
	// Exchange User access token for Service Account access token.
	ServiceAccount string
}

// cachedTokenJSON is the JSON wire format for unmarshaling cached tokens,
// matching golang.org/x/oauth2.Token so existing ~/.oauth2l cache files and
// JSON CLI outputs remain compatible.
type cachedTokenJSON struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

// LookupAuthCache looks up a cached auth.Token for the given settings.
// It returns (nil, nil) when caching is disabled or the key is not present.
func LookupAuthCache(settings *Settings) (*auth.Token, error) {
	if CacheLocation == "" {
		return nil, nil
	}
	var cache, err = loadCache()
	if err != nil {
		return nil, err
	}
	key, err := json.Marshal(createKey(settings))
	if err != nil {
		return nil, err
	}
	val, ok := cache[string(key)]
	if !ok || len(val) == 0 {
		return nil, nil
	}
	return UnmarshalAuthTokenWithExtras(val)
}

// LookupCache looks up a cached oauth2.Token for the given settings.
//
// Deprecated: Use LookupAuthCache instead.
func LookupCache(settings *Settings) (*oauth2.Token, error) {
	if CacheLocation == "" {
		return nil, nil
	}
	token, err := LookupAuthCache(settings)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return UnmarshalWithExtras(nil)
	}
	return oauth2TokenFromAuthToken(token), nil
}

// InsertAuthCache inserts the given auth.Token into the cache for settings.
func InsertAuthCache(settings *Settings, token *auth.Token) error {
	if CacheLocation == "" || token == nil {
		return nil
	}
	var cache, err = loadCache()
	if err != nil {
		return err
	}
	val, err := MarshalAuthTokenWithExtras(token, "")
	if err != nil {
		return err
	}
	key, err := json.Marshal(createKey(settings))
	if err != nil {
		return err
	}
	cache[string(key)] = val
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	// The cache contains OAuth tokens and embeds the credentials JSON (including
	// service account private keys) in its keys, so it must be owner-only.
	return os.WriteFile(CacheLocation, data, 0600)
}

// InsertCache inserts the given oauth2.Token into the cache for settings.
//
// Deprecated: Use InsertAuthCache instead.
func InsertCache(settings *Settings, token *oauth2.Token) error {
	return InsertAuthCache(settings, authTokenFromOAuth2Token(token))
}

func ClearCache() error {
	if CacheLocation == "" {
		return nil
	}
	if _, err := os.Stat(CacheLocation); os.IsNotExist(err) {
		// Noop if file does not exist.
		return nil
	}
	return os.Remove(CacheLocation)
}

func loadCache() (map[string][]byte, error) {
	if _, err := os.Stat(CacheLocation); os.IsNotExist(err) {
		// Create the cache file if not existing.
		f, err := os.OpenFile(CacheLocation, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		f.Close()
	}
	data, err := ioutil.ReadFile(CacheLocation)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	m := make(map[string][]byte)
	if len(data) > 0 {
		err = json.Unmarshal(data, &m)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	}
	return m, nil
}

func createKey(settings *Settings) CacheKey {
	if settings == nil {
		return CacheKey{}
	}
	// Removing redirect_uri from credentials file. This allows for dynamic
	// localhost ports created during 3LO loopback.
	var credentialsJSON string = settings.CredentialsJSON
	re := regexp.MustCompile("\"redirect_uris\":([[:graph:]\\s]*?)\\]")
	match := re.FindString(credentialsJSON)
	credentialsJSON = strings.Replace(credentialsJSON, match, "\"redirect_uris\":[]", 1)

	return CacheKey{
		CredentialsJSON: credentialsJSON,
		Scope:           settings.Scope,
		Audience:        settings.Audience,
		Email:           settings.Email,
		APIKey:          settings.APIKey,
		QuotaProject:    settings.QuotaProject,
		Sts:             settings.Sts,
		ServiceAccount:  settings.ServiceAccount,
	}
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

// MarshalAuthTokenWithExtras marshals the given auth.Token into a JSON
// bytearray using the oauth2.Token wire format and includes extra metadata
// fields that normally would be omitted with default marshalling.
func MarshalAuthTokenWithExtras(token *auth.Token, indent string) ([]byte, error) {
	if token == nil {
		return json.MarshalIndent(nil, "", indent)
	}
	// Note: "expiry" is always set (even when zero) to match encoding/json's
	// behavior on golang.org/x/oauth2.Token's non-pointer Expiry time.Time field.
	m := map[string]any{
		"access_token": token.Value,
		"expiry":       token.Expiry,
	}
	if token.Type != "" {
		m["token_type"] = token.Type
	}
	if rt := tokenMetadataString(token, "refresh_token"); rt != "" {
		m["refresh_token"] = rt
	}
	for _, k := range []string{"issued_token_type", "id_token", "scope"} {
		if v, ok := tokenMetadataExtraString(token, k); ok {
			m[k] = v
		}
	}
	return json.MarshalIndent(m, "", indent)
}

// Marshals the given oauth2.Token into a JSON bytearray and include Extra
// fields that normally would be omitted with default marshalling.
//
// Deprecated: Use MarshalAuthTokenWithExtras instead.
func MarshalWithExtras(token *oauth2.Token, indent string) ([]byte, error) {
	return MarshalAuthTokenWithExtras(authTokenFromOAuth2Token(token), indent)
}

// UnmarshalAuthTokenWithExtras unmarshals the given JSON bytearray into an
// auth.Token and includes extra fields in Metadata.
func UnmarshalAuthTokenWithExtras(data []byte) (*auth.Token, error) {
	var extra map[string]any
	err := json.Unmarshal(data, &extra)
	if err != nil {
		return nil, err
	}
	var wire cachedTokenJSON
	err = json.Unmarshal(data, &wire)
	if err != nil {
		return nil, err
	}
	return &auth.Token{
		Value:    wire.AccessToken,
		Type:     wire.TokenType,
		Expiry:   wire.Expiry,
		Metadata: extra,
	}, nil
}

// Unmarshals the given JSON bytearray into oauth2.Token and include Extra
// fields that normally would be omitted with default unmarshalling.
//
// Deprecated: Use UnmarshalAuthTokenWithExtras instead.
func UnmarshalWithExtras(data []byte) (*oauth2.Token, error) {
	token, err := UnmarshalAuthTokenWithExtras(data)
	if err != nil {
		return nil, err
	}
	return oauth2TokenFromAuthToken(token), nil
}

// tokenMetadataString returns the string value for key in tok.Metadata,
// supporting string values (from JSON token responses), single-element
// []string values (from form-encoded token responses), and []any values
// (from unmarshaled JSON arrays).
func tokenMetadataString(tok *auth.Token, key string) string {
	v, _ := tokenMetadataExtraString(tok, key)
	return v
}

func tokenMetadataExtraString(tok *auth.Token, key string) (string, bool) {
	if tok == nil || tok.Metadata == nil {
		return "", false
	}
	switch v := tok.Metadata[key].(type) {
	case string:
		return v, true
	case []string:
		if len(v) > 0 {
			return v[0], true
		}
	case []any:
		if len(v) > 0 {
			if str, ok := v[0].(string); ok {
				return str, true
			}
		}
	}
	return "", false
}

// oauth2TokenFromAuthToken converts an auth.Token into an oauth2.Token for the
// deprecated golang.org/x/oauth2 wrappers.
func oauth2TokenFromAuthToken(token *auth.Token) *oauth2.Token {
	if token == nil {
		return nil
	}
	t := &oauth2.Token{
		AccessToken:  token.Value,
		TokenType:    token.Type,
		RefreshToken: tokenMetadataString(token, "refresh_token"),
		Expiry:       token.Expiry,
	}
	if token.Metadata != nil {
		extra := make(map[string]any, len(token.Metadata))
		for k, v := range token.Metadata {
			switch vs := v.(type) {
			case []string:
				if len(vs) == 1 {
					v = vs[0]
				}
			case []any:
				if len(vs) == 1 {
					if s, ok := vs[0].(string); ok {
						v = s
					}
				}
			}
			extra[k] = v
		}
		t = t.WithExtra(extra)
	}
	return t
}

// authTokenFromOAuth2Token converts an oauth2.Token into an auth.Token for the
// deprecated golang.org/x/oauth2 wrappers.
func authTokenFromOAuth2Token(token *oauth2.Token) *auth.Token {
	if token == nil {
		return nil
	}
	metadata := make(map[string]any)
	for _, k := range []string{"issued_token_type", "id_token", "scope"} {
		if v, ok := token.Extra(k).(string); ok {
			metadata[k] = v
		}
	}
	if token.RefreshToken != "" {
		metadata["refresh_token"] = token.RefreshToken
	}
	var metadataOrNil map[string]any
	if len(metadata) > 0 {
		metadataOrNil = metadata
	}
	return &auth.Token{
		Value:    token.AccessToken,
		Type:     token.TokenType,
		Expiry:   token.Expiry,
		Metadata: metadataOrNil,
	}
}
