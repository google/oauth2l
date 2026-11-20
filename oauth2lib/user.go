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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
)

// Token metadata keys set on returned tokens.
const (
	// MetadataIDToken holds the ID token, when the token endpoint returns one.
	MetadataIDToken = "id_token"
	// MetadataRAPT holds the RAPT that was sent with the refresh, if any.
	MetadataRAPT = "rapt_token"
	// MetadataRefreshToken holds a new refresh token, when the token endpoint
	// returns one. The credentials use it for their next refresh; callers
	// that store credentials should save it.
	MetadataRefreshToken = "refresh_token"
)

// defaultTokenURL is used when neither Config.TokenURL nor the JSON's
// token_uri is set.
const defaultTokenURL = "https://oauth2.googleapis.com/token"

// userCredentialsJSON is the authorized_user credential file.
type userCredentialsJSON struct {
	Type         string          `json:"type"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	RefreshToken string          `json:"refresh_token"`
	TokenURI     string          `json:"token_uri"`
	Scopes       json.RawMessage `json:"scopes"`
}

// userTokenProvider refreshes authorized_user credentials. Each Token call
// sends one refresh_token grant through the caller's client, the same request
// Python gcloud sends (google_auth_credentials._RefreshGrant).
type userTokenProvider struct {
	client       *http.Client
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	rapt         func(context.Context) (string, error)

	mu           sync.Mutex
	refreshToken string // replaced when the token endpoint returns a new one
}

var _ auth.TokenProvider = (*userTokenProvider)(nil)

// newUserTokenProvider parses cfg.JSON as an authorized_user credential.
func newUserTokenProvider(cfg *Config) (*userTokenProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("oauth2lib: Config.Client is nil")
	}
	var f userCredentialsJSON
	if err := json.Unmarshal(cfg.JSON, &f); err != nil {
		return nil, fmt.Errorf("oauth2lib: parsing authorized_user JSON: %w", err)
	}
	if f.Type != "authorized_user" {
		return nil, fmt.Errorf("oauth2lib: credential type is %q, want authorized_user", f.Type)
	}
	var missing []string
	for _, field := range []struct{ name, value string }{
		{"client_id", f.ClientID},
		{"client_secret", f.ClientSecret},
		{"refresh_token", f.RefreshToken},
	} {
		if field.value == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("oauth2lib: authorized_user JSON is missing %s", strings.Join(missing, ", "))
	}
	scopes := cleanScopes(cfg.Scopes)
	if len(scopes) == 0 {
		s, err := parseJSONScopes(f.Scopes)
		if err != nil {
			return nil, err
		}
		scopes = s
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = f.TokenURI
	}
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	if err := validateTokenURL(tokenURL); err != nil {
		return nil, err
	}
	return &userTokenProvider{
		client:       cfg.Client,
		tokenURL:     tokenURL,
		clientID:     f.ClientID,
		clientSecret: f.ClientSecret,
		scopes:       scopes,
		rapt:         cfg.RAPT,
		refreshToken: f.RefreshToken,
	}, nil
}

// parseJSONScopes reads the "scopes" field, which google-auth writes as a
// list and also accepts as a space-separated string.
func parseJSONScopes(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return cleanScopes(list), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.Fields(s), nil
	}
	return nil, errors.New(`oauth2lib: authorized_user JSON "scopes" must be a list or a space-separated string`)
}

// cleanScopes returns scopes in a new slice, with surrounding spaces trimmed
// and empty entries dropped, so that []string{""} means no scopes.
func cleanScopes(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// validateTokenURL rejects token URLs that could never be sent, so that a
// bad Config.TokenURL or token_uri fails when the credentials are built
// rather than on the first Token call. The URL is not included in the error.
func validateTokenURL(tokenURL string) error {
	u, err := url.Parse(tokenURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("oauth2lib: token URL must be an absolute http or https URL")
	}
	return nil
}

// Token sends a refresh_token grant and returns the new access token.
func (p *userTokenProvider) Token(ctx context.Context) (*auth.Token, error) {
	var rapt string
	if p.rapt != nil {
		r, err := p.rapt(ctx)
		if err != nil {
			return nil, fmt.Errorf("oauth2lib: getting the RAPT: %w", err)
		}
		rapt = r
	}

	p.mu.Lock()
	refreshToken := p.refreshToken
	p.mu.Unlock()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"refresh_token": {refreshToken},
	}
	if len(p.scopes) > 0 {
		form.Set("scope", strings.Join(p.scopes, " "))
	}
	if rapt != "" {
		form.Set("rapt", rapt)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: building the refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	status, body, err := doRequest(ctx, p.client, req)
	if err != nil {
		return nil, err
	}
	return p.parseResponse(status, body, refreshToken, rapt)
}

// userTokenResponse is a successful refresh_token grant response.
type userTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	Scope        *string         `json:"scope"`
}

func (p *userTokenProvider) parseResponse(status int, body []byte, sentRefreshToken, rapt string) (*auth.Token, error) {
	var resp userTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "token response is not valid JSON"}
	}
	if resp.AccessToken == "" {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "token response has no access_token"}
	}
	expiresIn, ok := parseExpiresIn(resp.ExpiresIn)
	if !ok {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "token response has an invalid expires_in"}
	}

	metadata := map[string]interface{}{}
	if resp.RefreshToken != "" && resp.RefreshToken != sentRefreshToken {
		// Like Python gcloud, keep the new refresh token even if the scope
		// check below fails. An echoed, unchanged token is not reported, so
		// callers only save the credentials when the token really changed.
		p.mu.Lock()
		if p.refreshToken == sentRefreshToken {
			p.refreshToken = resp.RefreshToken
		}
		p.mu.Unlock()
		metadata[MetadataRefreshToken] = resp.RefreshToken
	}
	if resp.IDToken != "" {
		metadata[MetadataIDToken] = resp.IDToken
	}
	if rapt != "" {
		metadata[MetadataRAPT] = rapt
	}

	if len(p.scopes) > 0 && resp.Scope != nil {
		if missing := missingScopes(p.scopes, *resp.Scope); len(missing) > 0 {
			return nil, &RefreshError{
				Kind:       KindInvalidGrant,
				StatusCode: status,
				Description: "Not all requested scopes were granted by the authorization server, missing scopes " +
					strings.Join(missing, ", ") + ".",
			}
		}
	}

	tok := &auth.Token{
		Value:    resp.AccessToken,
		Type:     resp.TokenType,
		Metadata: metadata,
	}
	if tok.Type == "" {
		tok.Type = "Bearer"
	}
	if expiresIn != nil {
		tok.Expiry = time.Now().Add(time.Duration(*expiresIn) * time.Second)
	}
	return tok, nil
}

// maxExpiresIn is the largest expires_in, in seconds, that fits in a
// time.Duration.
const maxExpiresIn = math.MaxInt64 / int64(time.Second)

// parseExpiresIn reads expires_in, which some servers send as a string. It
// returns nil, true if the field is missing, and false if the value is not
// an integer in [0, maxExpiresIn].
func parseExpiresIn(raw json.RawMessage) (*int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, false
		}
		if n, err = strconv.ParseInt(s, 10, 64); err != nil {
			return nil, false
		}
	}
	if n < 0 || n > maxExpiresIn {
		return nil, false
	}
	return &n, true
}

// missingScopes returns the requested scopes that granted (a space-separated
// list) does not contain, in the order they were requested.
func missingScopes(requested []string, granted string) []string {
	have := map[string]bool{}
	for _, s := range strings.Fields(granted) {
		have[s] = true
	}
	var missing []string
	for _, s := range requested {
		if !have[s] {
			missing = append(missing, s)
		}
	}
	return missing
}
