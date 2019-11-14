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
package internal

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"errors"
	"golang.org/x/net/context"
)

// Token represents the credentials used to authorize
// the requests to access protected resources on the OAuth 2.0
// provider's backend.
//
// This type is a mirror of oauth2.Token and exists to break
// an otherwise-circular dependency. Other internal packages
// should convert this Token into an oauth2.Token before use.
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time

	// Raw optionally contains extra metadata from the server
	// when updating a token.
	Raw interface{}
}

// expiryDelta determines how earlier a token should be considered
// expired than its actual expiration time. It is used to avoid late
// expirations due to client-server time mismatches.
const expiryDelta = 10 * time.Second

// Type returns t.TokenType if non-empty, else "Bearer".
func (t *Token) Type() string {
	if strings.EqualFold(t.TokenType, "bearer") {
		return "Bearer"
	}
	if strings.EqualFold(t.TokenType, "mac") {
		return "MAC"
	}
	if strings.EqualFold(t.TokenType, "basic") {
		return "Basic"
	}
	if t.TokenType != "" {
		return t.TokenType
	}
	return "Bearer"
}

// SetAuthHeader sets the Authorization header to r using the access
// token in t.
//
// This method is unnecessary when using Transport or an HTTP Client
// returned by this package.
func (t *Token) SetAuthHeader(r *http.Request) {
	r.Header.Set("Authorization", t.Type()+" "+t.AccessToken)
}

// WithExtra returns a new Token that's a clone of t, but using the
// provided raw extra map. This is only intended for use by packages
// implementing derivative OAuth2 flows.
func (t *Token) WithExtra(extra interface{}) *Token {
	t2 := new(Token)
	*t2 = *t
	t2.Raw = extra
	return t2
}

// Extra returns an extra field.
// Extra fields are key-value pairs returned by the server as a
// part of the token retrieval response.
func (t *Token) Extra(key string) interface{} {
	if raw, ok := t.Raw.(map[string]interface{}); ok {
		return raw[key]
	}

	vals, ok := t.Raw.(url.Values)
	if !ok {
		return nil
	}

	v := vals.Get(key)
	switch s := strings.TrimSpace(v); strings.Count(s, ".") {
	case 0: // Contains no "."; try to parse as int
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	case 1: // Contains a single "."; try to parse as float
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}

	return v
}

// expired reports whether the token is expired.
// t must be non-nil.
func (t *Token) expired() bool {
	if t.Expiry.IsZero() {
		return false
	}
	return t.Expiry.Round(0).Add(-expiryDelta).Before(time.Now())
}

// Valid reports whether t is non-nil, has an AccessToken, and is not expired.
func (t *Token) Valid() bool {
	return t != nil && t.AccessToken != "" && !t.expired()
}

// retrieveToken takes a *Config and uses that to retrieve an *internal.Token.
// This token is then mapped from *internal.Token into an *oauth2.Token which is returned along
// with an error..
func RetrieveToken(ctx context.Context, c *Config, v url.Values) (*Token, error) {
	if c.getOAuthType() == k2LO {
		tk, err := retrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
		if err != nil {
			if rErr, ok := err.(*RetrieveError); ok {
				return nil, (*RetrieveError)(rErr)
			}
			return nil, err
		}
		return tk, nil
	} else {
		url := c.AuthCodeURL()
		code, err := c.FlowHandler(url)
		if err != nil {
			return nil, err
		}
		return c.Exchange(ctx, code)
	}
}

// tokenRefresher is a TokenSource that makes "grant_type"=="refresh_token"
// HTTP requests to renew a token using a RefreshToken.
type tokenRefresher struct {
	ctx          context.Context // used to get HTTP requests
	conf         *Config
	refreshToken string
}

// WARNING: Token is not safe for concurrent access, as it
// updates the tokenRefresher's refreshToken field.
// Within this package, it is used by reuseTokenSource which
// synchronizes calls to this method with its own mutex.
func (tf *tokenRefresher) Token() (*Token, error) {
	if tf.conf.getOAuthType() == k2LO && tf.refreshToken == "" {
		return nil, errors.New("oauth2: token expired and refresh token is not set")
	}

	tk, err := RetrieveToken(tf.ctx, tf.conf, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tf.refreshToken},
	})

	if err != nil {
		return nil, err
	}
	if tf.refreshToken != tk.RefreshToken {
		tf.refreshToken = tk.RefreshToken
	}
	return tk, err
}
