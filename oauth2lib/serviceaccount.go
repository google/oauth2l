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
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

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

	// A key belongs to the universe that issued it, so the JSON's
	// universe_domain wins, and Config.UniverseDomain is used only when the
	// JSON has none. That way UniverseDomain always reports the key's real
	// universe, and the caller can check it against its own configuration.
	// Surrounding spaces are ignored, so a blank value counts as missing (as
	// in Go gcloud's normalizeUniverseDomain).
	fileUniverse := strings.TrimSpace(f.UniverseDomain)
	cfgUniverse := strings.TrimSpace(cfg.UniverseDomain)
	p := &serviceAccountTokenProvider{universeDomain: fileUniverse}
	if p.universeDomain == "" {
		p.universeDomain = cfgUniverse
	}
	if p.universeDomain == "" {
		p.universeDomain = defaultUniverseDomain
	}

	// Outside the Google universe there is no token endpoint for the JWT
	// bearer grant, so tokens must be self-signed. As in Python gcloud
	// (creds.UseSelfSignedJwt), a non-default universe in either the JSON or
	// the caller's configuration is enough, even if the other one is the
	// default.
	p.selfSignedJWT = cfg.UseSelfSignedJWT ||
		(fileUniverse != "" && fileUniverse != defaultUniverseDomain) ||
		(cfgUniverse != "" && cfgUniverse != defaultUniverseDomain)
	scopes := cleanScopes(cfg.Scopes) // a new slice, so later changes by the caller can't affect it
	if p.selfSignedJWT {
		if len(scopes) == 0 {
			return nil, errors.New("oauth2lib: a self-signed JWT needs Config.Scopes")
		}
		// A copy, so a caller changing its slice later can't affect (or race
		// with) later Token calls.
		p.jsonData = bytes.Clone(cfg.JSON)
		p.jsonOpts = &credentials.DetectOptions{
			Scopes:           scopes,
			UseSelfSignedJWT: true,
			UniverseDomain:   p.universeDomain,
			Client:           cfg.Client,
			Logger:           discardLogger,
		}
		// go/auth parses the JSON into its own struct, with more typed fields
		// (project_id, client_id, auth_uri) than serviceAccountJSON. Build
		// the credentials once now, which makes no network call and starts no
		// goroutine, so such a JSON fails here instead of on every Token call.
		if _, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, p.jsonData, p.jsonOpts); err != nil {
			return nil, fmt.Errorf("oauth2lib: self-signed JWT: %w", err)
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
		Scopes:       scopes,
		TokenURL:     p.tokenURL,
		Client:       tagTransportErrors(cfg.Client),
		Logger:       discardLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth2lib: service account: %w", err)
	}
	p.twoLO = tp
	return p, nil
}

var errECKey = errors.New("oauth2lib: service_account private_key is an EC key; only RSA keys are supported")

// checkPrivateKey reports whether key is a PEM or DER private key in a form
// cloud.google.com/go/auth can sign with (PKCS #8 or PKCS #1), so a bad key
// fails when the credentials are built rather than on every Token call.
func checkPrivateKey(key string) error {
	der := []byte(key)
	if block, _ := pem.Decode(der); block != nil {
		der = block.Bytes
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		// PKCS #8 can also hold keys that can't sign (X25519, for example).
		// go/auth's ParseKey rejects those on every Token call.
		if _, ok := k.(crypto.Signer); !ok {
			return errors.New("oauth2lib: service_account private_key cannot sign")
		}
		// go/auth supports only RSA service account keys.
		if _, ok := k.(*ecdsa.PrivateKey); ok {
			return errECKey
		}
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return errECKey
	}
	return errors.New("oauth2lib: service_account private_key is not a PKCS #8 or PKCS #1 private key")
}

// Token returns a new access token or self-signed JWT. It never returns a
// cached token.
func (p *serviceAccountTokenProvider) Token(ctx context.Context) (*auth.Token, error) {
	if p.selfSignedJWT {
		return p.selfSignedToken(ctx)
	}
	// The tagging transport records the response's status code here, so
	// errors about a 2xx body keep it (StatusCode 0 means no response).
	var status int
	tok, err := p.twoLO.Token(context.WithValue(ctx, statusKey{}, &status))
	if err != nil {
		return nil, classify2LOError(ctx, err, status)
	}
	if tok.Value == "" {
		return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "token response has no access_token"}
	}
	// go/auth ignores a negative expires_in and computes Expiry without an
	// overflow check, so apply user.go's rule to the raw value. go/auth copies
	// the whole response into Metadata.
	if v, ok := tok.Metadata["expires_in"]; ok {
		raw, err := json.Marshal(v)
		secs, valid := parseExpiresIn(raw)
		if err != nil || !valid {
			return nil, &RefreshError{Kind: KindUnknown, StatusCode: status, Description: "token response has an invalid expires_in"}
		}
		// go/auth sets Expiry only when expires_in > 0, and a zero Expiry
		// means "never expires" to auth.Token.IsValid. Like user.go, treat
		// expires_in 0 as expiring now.
		if secs != nil && *secs == 0 && tok.Expiry.IsZero() {
			tok.Expiry = time.Now()
		}
	}
	return newServiceAccountToken(tok), nil
}

// statusKey is the context key under which Token passes a *int for the
// tagging transport to store the response status code in.
type statusKey struct{}

// selfSignedToken signs a new self-signed JWT. go/auth only exposes
// self-signed JWTs through NewCredentialsFromJSON, whose credentials cache
// tokens, so the credentials are built on each call: their cache starts
// empty, the first Token call signs synchronously, and nothing is reused or
// refreshed in the background.
func (p *serviceAccountTokenProvider) selfSignedToken(ctx context.Context) (*auth.Token, error) {
	// Signing never looks at ctx, so check it first: a canceled or expired
	// context returns its error, as for every other credential type.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Only a done ctx returns ctx's error; every other failure is a
	// *RefreshError, as errors.go documents.
	creds, err := credentials.NewCredentialsFromJSON(credentials.ServiceAccount, p.jsonData, p.jsonOpts)
	if err != nil {
		return nil, &RefreshError{Kind: KindUnknown, Err: fmt.Errorf("self-signed JWT: %w", err)}
	}
	tok, err := creds.Token(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, &RefreshError{Kind: KindUnknown, Err: fmt.Errorf("self-signed JWT: %w", err)}
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
		Metadata: map[string]any{},
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
func classify2LOError(ctx context.Context, err error, status int) error {
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
	// Errors from sending the request or reading the response, as in
	// doRequest: anything the client's transport or body returned (tagged by
	// tagTransportErrors), http.Client's own errors (*url.Error), and a body
	// read cut short by http.Client.Timeout (a net.Error). A bare
	// io.ErrUnexpectedEOF is not matched: a real one from the body is already
	// tagged, and go/auth's JSON decoding of a truncated id_token returns one
	// too, which is a bad response, not a network error.
	var tagged *transportError
	var urlErr *url.Error
	var netErr net.Error
	if errors.As(err, &tagged) || errors.As(err, &urlErr) || errors.As(err, &netErr) {
		return classifyTransportError(ctx, err)
	}
	// Anything else came from go/auth itself, such as a 2xx body that is not
	// valid JSON, an id_token it can't decode, or a signing failure. Sending
	// the request again won't help.
	return &RefreshError{Kind: KindUnknown, StatusCode: status, Err: err}
}

// transportError marks an error returned by the client's transport or while
// reading a response body.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// tagTransportErrors returns a copy of c whose transport marks every error
// from sending a request or reading its response body as a transportError.
// go/auth reads the body after http.Client.Do returns, so body-read errors
// reach classify2LOError unwrapped, and they need not be net.Errors (an HTTP/2
// stream reset, for example). The copy keeps c's transport, timeout, cookie
// jar and redirect policy.
func tagTransportErrors(c *http.Client) *http.Client {
	cc := *c
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cc.Transport = taggingTransport{base: base}
	return &cc
}

type taggingTransport struct{ base http.RoundTripper }

func (t taggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, &transportError{err: err}
	}
	if status, ok := req.Context().Value(statusKey{}).(*int); ok {
		*status = resp.StatusCode // the last one wins if there are redirects
	}
	resp.Body = taggingBody{ReadCloser: resp.Body}
	return resp, nil
}

type taggingBody struct{ io.ReadCloser }

func (b taggingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF { // io.EOF must be returned unchanged
		err = &transportError{err: err}
	}
	return n, err
}
