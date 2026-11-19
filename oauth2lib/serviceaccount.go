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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
)

// defaultUniverseDomain is the Google Cloud universe domain.
const defaultUniverseDomain = "googleapis.com"

// discardLogger is passed to every cloud.google.com/go/auth call. At debug
// level, go/auth logs full request and response bodies (signed assertions,
// access tokens), so oauth2lib never gives it the caller's logger.
var discardLogger = slog.New(slog.DiscardHandler)

// serviceAccountJSON is the service_account credential file.
type serviceAccountJSON struct {
	Type           string `json:"type"`
	ClientEmail    string `json:"client_email"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyID   string `json:"private_key_id"`
	TokenURI       string `json:"token_uri"`
	UniverseDomain string `json:"universe_domain"`
}

// serviceAccountTokenProvider returns tokens for service_account
// credentials. In the Google universe it uses the OAuth 2.0 JWT bearer grant
// (2LO): each Token call signs a new assertion and sends one request to the
// token endpoint through the caller's client. With UseSelfSignedJWT, or in
// any other universe, each Token call signs a new self-signed JWT locally
// and makes no network call. The signing happens inside
// cloud.google.com/go/auth, so oauth2lib needs no crypto code of its own.
type serviceAccountTokenProvider struct {
	// universeDomain is the credential's universe domain, for BuildCredentials.
	universeDomain string
	// tokenURL is the token endpoint, used only for 2LO.
	tokenURL string
	// selfSignedJWT reports whether tokens are self-signed JWTs.
	selfSignedJWT bool

	twoLO    auth.TokenProvider         // 2LO
	jsonData []byte                     // self-signed JWT
	jsonOpts *credentials.DetectOptions // self-signed JWT
}

var _ auth.TokenProvider = (*serviceAccountTokenProvider)(nil)

// newServiceAccountTokenProvider parses cfg.JSON as a service_account
// credential.
func newServiceAccountTokenProvider(cfg *Config) (*serviceAccountTokenProvider, error) {
	if cfg.Client == nil {
		return nil, errors.New("oauth2lib: Config.Client is nil")
	}
	var f serviceAccountJSON
	if err := json.Unmarshal(cfg.JSON, &f); err != nil {
		return nil, fmt.Errorf("oauth2lib: parsing service_account JSON: %w", err)
	}
	if f.Type != "service_account" {
		return nil, fmt.Errorf("oauth2lib: credential type is %q, want service_account", f.Type)
	}
	var missing []string
	if f.ClientEmail == "" {
		missing = append(missing, "client_email")
	}
	if f.PrivateKey == "" {
		missing = append(missing, "private_key")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("oauth2lib: service_account JSON is missing %s", strings.Join(missing, ", "))
	}
	if err := checkPrivateKey(f.PrivateKey); err != nil {
		return nil, err
	}

	p := &serviceAccountTokenProvider{universeDomain: cfg.UniverseDomain}
	if p.universeDomain == "" {
		p.universeDomain = f.UniverseDomain
	}
	if p.universeDomain == "" {
		p.universeDomain = defaultUniverseDomain
	}

	// Outside the Google universe there is no token endpoint for the JWT
	// bearer grant, so tokens must be self-signed, as in Python gcloud.
	p.selfSignedJWT = cfg.UseSelfSignedJWT || p.universeDomain != defaultUniverseDomain
	if p.selfSignedJWT {
		if len(cfg.Scopes) == 0 {
			return nil, errors.New("oauth2lib: a self-signed JWT needs Config.Scopes")
		}
		p.jsonData = cfg.JSON
		p.jsonOpts = &credentials.DetectOptions{
			Scopes:           cfg.Scopes,
			UseSelfSignedJWT: true,
			UniverseDomain:   p.universeDomain,
			Client:           cfg.Client,
			Logger:           discardLogger,
		}
		return p, nil
	}

	p.tokenURL = cfg.TokenURL
	if p.tokenURL == "" {
		p.tokenURL = f.TokenURI
	}
	if p.tokenURL == "" {
		p.tokenURL = defaultTokenURL
	}
	if err := validateTokenURL(p.tokenURL); err != nil {
		return nil, err
	}
	tp, err := auth.New2LOTokenProvider(&auth.Options2LO{
		Email:        f.ClientEmail,
		PrivateKey:   []byte(f.PrivateKey),
		PrivateKeyID: f.PrivateKeyID,
		Scopes:       cfg.Scopes,
		TokenURL:     p.tokenURL,
		Client:       cfg.Client,
		Logger:       discardLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: service account: %w", err)
	}
	p.twoLO = tp
	return p, nil
}

// checkPrivateKey reports whether key is a PEM or DER private key in a form
// cloud.google.com/go/auth can sign with (PKCS #8, PKCS #1 or EC), so a bad
// key fails when the credentials are built rather than on every Token call.
func checkPrivateKey(key string) error {
	der := []byte(key)
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return nil
	}
	return errors.New("oauth2lib: service_account private_key is not a PKCS #8, PKCS #1 or EC private key")
}

// Token returns a new access token or self-signed JWT. It never returns a
// cached token.
func (p *serviceAccountTokenProvider) Token(ctx context.Context) (*auth.Token, error) {
	if p.selfSignedJWT {
		return p.selfSignedToken(ctx)
	}
	tok, err := p.twoLO.Token(ctx)
	if err != nil {
		return nil, classify2LOError(ctx, err)
	}
	if tok.Value == "" {
		return nil, &RefreshError{Kind: KindUnknown, Description: "token response has no access_token"}
	}
	return newServiceAccountToken(tok), nil
}

// selfSignedToken signs a new self-signed JWT. go/auth only exposes
// self-signed JWTs through NewCredentialsFromJSON, whose credentials cache
// tokens, so the credentials are built on each call: their cache starts
// empty, the first Token call signs synchronously, and nothing is reused or
// refreshed in the background.
func (p *serviceAccountTokenProvider) selfSignedToken(ctx context.Context) (*auth.Token, error) {
	creds, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, p.jsonData, p.jsonOpts)
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: self-signed JWT: %w", err)
	}
	tok, err := creds.Token(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("oauth2lib: self-signed JWT: %w", err)
	}
	return newServiceAccountToken(tok), nil
}

// newServiceAccountToken copies the fields oauth2lib returns. go/auth puts
// the whole token response, including the access token, in Metadata, so only
// the ID token is carried over.
func newServiceAccountToken(tok *auth.Token) *auth.Token {
	out := &auth.Token{
		Value:    tok.Value,
		Type:     tok.Type,
		Expiry:   tok.Expiry,
		Metadata: map[string]interface{}{},
	}
	if out.Type == "" {
		out.Type = "Bearer"
	}
	if id, ok := tok.Metadata[MetadataIDToken].(string); ok && id != "" {
		out.Metadata[MetadataIDToken] = id
	}
	return out
}

// classify2LOError turns an error from go/auth's 2LO token provider into the
// error Token returns, as doRequest does for oauth2lib's own requests.
func classify2LOError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var authErr *auth.Error
	if errors.As(err, &authErr) && authErr.Response != nil {
		body := authErr.Body
		if len(body) > maxResponseBody {
			body = body[:maxResponseBody]
		}
		return classifyResponse(authErr.Response.StatusCode, body)
	}
	// http.Client.Do always returns a *url.Error. A failure while reading the
	// body is a network error or an unexpected EOF.
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		return classifyTransportError(ctx, err)
	}
	// Anything else, such as a 2xx body that is not valid JSON.
	return &RefreshError{Kind: KindUnknown, Err: err}
}
