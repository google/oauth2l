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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"github.com/google/oauth2l/oauth2lib/goldenvectors"
)

// vectorClientTimeout is the http.Client.Timeout of a vector with a
// client_timeout transport error.
const vectorClientTimeout = 200 * time.Millisecond

// TestGoldenVectors runs every vector in goldenvectors: it builds the
// credentials, calls Token once, and checks each request, the token or
// error, and the universe domain. An impersonated_service_account vector
// also runs as "<name>/parse_and_impersonate", with the credentials built
// the way a caller that builds the source itself would.
func TestGoldenVectors(t *testing.T) {
	vectors, err := goldenvectors.All()
	if err != nil {
		t.Fatalf("goldenvectors.All() error = %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("goldenvectors.All() returned no vectors")
	}
	_, keyPEM := testServiceAccountKey(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			runGoldenVector(t, v, func(ctx context.Context, client *http.Client) *auth.Credentials {
				return buildVectorCredentials(ctx, t, v.Input, keyPEM, client)
			})
		})
		if isImpersonatedJSONVector(t, v) {
			t.Run(v.Name+"/parse_and_impersonate", func(t *testing.T) {
				runGoldenVector(t, v, func(ctx context.Context, client *http.Client) *auth.Credentials {
					return parseAndImpersonate(ctx, t, *v.Input.Config, keyPEM, client)
				})
			})
		}
	}
}

// buildVectorCredentials builds in as the vector says: BuildCredentials for a
// config, or BuildCredentials and Impersonate for an impersonation.
func buildVectorCredentials(ctx context.Context, t *testing.T, in goldenvectors.Input, keyPEM string, client *http.Client) *auth.Credentials {
	t.Helper()
	switch {
	case in.Config != nil && in.Impersonation == nil:
		creds, err := BuildCredentials(ctx, vectorConfig(t, *in.Config, keyPEM, client))
		if err != nil {
			t.Fatalf("BuildCredentials() error = %v", err)
		}
		return creds
	case in.Impersonation != nil && in.Config == nil:
		imp := in.Impersonation
		src, err := BuildCredentials(ctx, vectorConfig(t, imp.Source, keyPEM, client))
		if err != nil {
			t.Fatalf("BuildCredentials(source) error = %v", err)
		}
		creds, err := Impersonate(ctx, &ImpersonationConfig{
			Source:    src,
			Target:    imp.Target,
			Delegates: imp.Delegates,
			Scopes:    imp.Scopes,
			Lifetime:  time.Duration(imp.LifetimeSeconds) * time.Second,
			Endpoint:  imp.Endpoint,
			Client:    client,
		})
		if err != nil {
			t.Fatalf("Impersonate() error = %v", err)
		}
		return creds
	}
	t.Fatal("vector input must set exactly one of config and impersonation")
	return nil
}

// isImpersonatedJSONVector reports whether v builds impersonated_service_account
// JSON with BuildCredentials.
func isImpersonatedJSONVector(t *testing.T, v goldenvectors.Vector) bool {
	t.Helper()
	if v.Input.Config == nil {
		return false
	}
	var ct credentialType
	if err := json.Unmarshal(v.Input.Config.CredentialsJSON, &ct); err != nil {
		t.Fatalf("%s: credentials_json: %v", v.Name, err)
	}
	return ct.Type == "impersonated_service_account"
}

// parseAndImpersonate builds impersonated_service_account credentials with
// ParseImpersonatedServiceAccountJSON, SourceConfig, BuildCredentials and
// Impersonate, mapping the fields as buildImpersonatedFromJSON does:
// Config.Scopes win over the JSON's, and Endpoint stays empty, so IAM is
// called in the source's universe.
func parseAndImpersonate(ctx context.Context, t *testing.T, c goldenvectors.Config, keyPEM string, client *http.Client) *auth.Credentials {
	t.Helper()
	cfg := vectorConfig(t, c, keyPEM, client)
	a, err := ParseImpersonatedServiceAccountJSON(cfg.JSON)
	if err != nil {
		t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
	}
	src, err := BuildCredentials(ctx, a.SourceConfig(cfg))
	if err != nil {
		t.Fatalf("BuildCredentials(SourceConfig()) error = %v", err)
	}
	scopes := a.Scopes
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}
	creds, err := Impersonate(ctx, &ImpersonationConfig{
		Source:    src,
		Target:    a.Target,
		Delegates: a.Delegates,
		Scopes:    scopes,
		Client:    client,
	})
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	return creds
}

func runGoldenVector(t *testing.T, v goldenvectors.Vector, build func(context.Context, *http.Client) *auth.Credentials) {
	rt := &vectorTransport{t: t, exchanges: v.Exchanges}
	client := &http.Client{Transport: rt}
	for _, ex := range v.Exchanges {
		if te := ex.Response.TransportError; te != nil && te.Type == goldenvectors.TransportErrorClientTimeout {
			client.Timeout = vectorClientTimeout
		}
	}
	ctx := t.Context()
	creds := build(ctx, client)

	start := time.Now()
	tok, err := creds.Token(ctx)
	end := time.Now()
	if got := rt.sent(); got != len(v.Exchanges) {
		t.Errorf("Token() sent %d requests, want %d", got, len(v.Exchanges))
	}
	if u, uerr := creds.UniverseDomain(ctx); uerr != nil || u != v.Expected.UniverseDomain {
		t.Errorf("UniverseDomain() = %q, %v, want %q", u, uerr, v.Expected.UniverseDomain)
	}
	switch want := v.Expected; {
	case want.Token != nil && want.Error == nil:
		if err != nil {
			t.Fatalf("Token() error = %v, want a token", err)
		}
		checkVectorToken(t, tok, want.Token, start, end)
	case want.Error != nil && want.Token == nil:
		if err == nil {
			t.Fatalf("Token() = %v, want error %+v", tok, *want.Error)
		}
		checkVectorError(t, err, want.Error)
	default:
		t.Fatal("vector expected must set exactly one of token and error")
	}
}

func vectorConfig(t *testing.T, c goldenvectors.Config, keyPEM string, client *http.Client) *Config {
	t.Helper()
	js, err := c.JSON(keyPEM)
	if err != nil {
		t.Fatalf("Config.JSON() error = %v", err)
	}
	cfg := &Config{
		JSON:             js,
		Scopes:           c.Scopes,
		TokenURL:         c.TokenURL,
		UniverseDomain:   c.UniverseDomain,
		UseSelfSignedJWT: c.UseSelfSignedJWT,
		Client:           client,
	}
	if c.RAPT != "" {
		rapt := c.RAPT
		cfg.RAPT = func(context.Context) (string, error) { return rapt, nil }
	}
	return cfg
}

// vectorTransport checks each request against the next exchange and
// answers with its response, without any network.
type vectorTransport struct {
	t         *testing.T
	exchanges []goldenvectors.Exchange

	mu   sync.Mutex
	next int
}

func (rt *vectorTransport) sent() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.next
}

func (rt *vectorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}
	rt.mu.Lock()
	i := rt.next
	rt.next++
	rt.mu.Unlock()
	if i >= len(rt.exchanges) {
		rt.t.Errorf("unexpected request %d: %s %s", i, req.Method, req.URL.Redacted())
		return nil, errors.New("vectorTransport: unexpected request")
	}
	ex := rt.exchanges[i]
	checkVectorRequest(rt.t, i, ex.Request, req, body)

	resp := ex.Response
	if te := resp.TransportError; te != nil {
		return nil, vectorTransportError(req, te)
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	h := http.Header{}
	var out string
	switch {
	case resp.BodyText != "":
		h.Set("Content-Type", "text/plain")
		out = resp.BodyText
	case len(resp.Body) > 0:
		h.Set("Content-Type", "application/json")
		out = string(resp.Body)
	}
	return &http.Response{
		Status:        http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(out)),
		ContentLength: int64(len(out)),
		Request:       req,
	}, nil
}

// vectorTransportError returns the error for te, as its type describes.
func vectorTransportError(req *http.Request, te *goldenvectors.TransportError) error {
	switch te.Type {
	case goldenvectors.TransportErrorNetwork:
		return errors.New(te.Message)
	case goldenvectors.TransportErrorClientCertRefused:
		return fmt.Errorf("%s: %w", te.Message, ErrAccessDenied)
	case goldenvectors.TransportErrorClientTimeout:
		// Wait for http.Client.Timeout, so net/http builds its own error.
		<-req.Context().Done()
		return req.Context().Err()
	case goldenvectors.TransportErrorServerCertUntrusted:
		return fmt.Errorf("%s: %w", te.Message, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	}
	return fmt.Errorf("vectorTransport: unknown transport error type %q", te.Type)
}

func checkVectorRequest(t *testing.T, i int, want goldenvectors.Request, req *http.Request, body []byte) {
	t.Helper()
	if req.Method != want.Method {
		t.Errorf("request %d: method = %s, want %s", i, req.Method, want.Method)
	}
	if got := req.URL.String(); got != want.URL {
		t.Errorf("request %d: URL = %s, want %s", i, got, want.URL)
	}
	for k, v := range want.Headers {
		if got := req.Header.Get(k); got != v {
			t.Errorf("request %d: header %s = %q, want %q", i, k, got, v)
		}
	}
	if want.Form != nil || want.Assertion != nil {
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("request %d: body %q is not form-encoded: %v", i, body, err)
			return
		}
		got := map[string]string{}
		for k, vs := range form {
			if len(vs) != 1 {
				t.Errorf("request %d: form field %s has %d values, want 1", i, k, len(vs))
			}
			if k == "assertion" && want.Assertion != nil {
				checkVectorJWT(t, "request assertion", vs[0], want.Assertion)
				continue
			}
			got[k] = vs[0]
		}
		wantForm := want.Form
		if wantForm == nil {
			wantForm = map[string]string{}
		}
		if !reflect.DeepEqual(got, wantForm) {
			t.Errorf("request %d: form = %v, want %v", i, got, wantForm)
		}
		if want.Assertion != nil && !form.Has("assertion") {
			t.Errorf("request %d: form has no assertion", i)
		}
	}
	if len(want.JSON) > 0 {
		var got, w any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("request %d: body %q is not JSON: %v", i, body, err)
			return
		}
		if err := json.Unmarshal(want.JSON, &w); err != nil {
			t.Fatalf("request %d: vector JSON: %v", i, err)
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("request %d: JSON body = %s, want %s", i, body, want.JSON)
		}
	}
}

// checkVectorJWT verifies tok's signature with the test key and checks it
// against want.
func checkVectorJWT(t *testing.T, what, tok string, want *goldenvectors.JWT) {
	t.Helper()
	header, claims := verifyJWT(t, tok)
	for k, v := range want.Header {
		if !reflect.DeepEqual(header[k], v) {
			t.Errorf("%s: header %s = %v, want %v", what, k, header[k], v)
		}
	}
	for k, v := range want.Claims {
		if !reflect.DeepEqual(claims[k], v) {
			t.Errorf("%s: claim %s = %v, want %v", what, k, claims[k], v)
		}
	}
	for _, k := range want.AbsentClaims {
		if v, ok := claims[k]; ok {
			t.Errorf("%s: claim %s = %v, want it absent", what, k, v)
		}
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if iat == 0 || int64(exp-iat) != want.LifetimeSeconds {
		t.Errorf("%s: iat = %v, exp = %v, want exp-iat = %d", what, claims["iat"], claims["exp"], want.LifetimeSeconds)
	}
}

func checkVectorToken(t *testing.T, tok *auth.Token, want *goldenvectors.Token, start, end time.Time) {
	t.Helper()
	if want.JWT != nil {
		checkVectorJWT(t, "token", tok.Value, want.JWT)
	} else if tok.Value != want.Value {
		t.Errorf("token value = %q, want %q", tok.Value, want.Value)
	}
	if tok.Type != want.Type {
		t.Errorf("token type = %q, want %q", tok.Type, want.Type)
	}
	switch {
	case want.ExpiresInSeconds != nil:
		d := time.Duration(*want.ExpiresInSeconds) * time.Second
		// JWT iat/exp are whole seconds, so allow a second either way.
		lo, hi := start.Add(d-time.Second), end.Add(d+time.Second)
		if tok.Expiry.Before(lo) || tok.Expiry.After(hi) {
			t.Errorf("token expiry = %v, want between %v and %v", tok.Expiry, lo, hi)
		}
	case want.Expiry != "":
		w, err := time.Parse(time.RFC3339, want.Expiry)
		if err != nil {
			t.Fatalf("vector expiry %q: %v", want.Expiry, err)
		}
		if !tok.Expiry.Equal(w) {
			t.Errorf("token expiry = %v, want %v", tok.Expiry, w)
		}
	default:
		if !tok.Expiry.IsZero() {
			t.Errorf("token expiry = %v, want zero", tok.Expiry)
		}
	}
	got := map[string]string{}
	for k, v := range tok.Metadata {
		s, ok := v.(string)
		if !ok {
			t.Errorf("token metadata %s = %#v, want a string", k, v)
		}
		got[k] = s
	}
	wantMD := want.Metadata
	if wantMD == nil {
		wantMD = map[string]string{}
	}
	if !reflect.DeepEqual(got, wantMD) {
		t.Errorf("token metadata = %v, want %v", got, wantMD)
	}
}

var vectorSentinels = map[string]error{
	goldenvectors.ErrReauthRequired: ErrReauthRequired,
	goldenvectors.ErrAccessDenied:   ErrAccessDenied,
	goldenvectors.ErrCAADenied:      ErrCAADenied,
	goldenvectors.ErrInvalidGrant:   ErrInvalidGrant,
	goldenvectors.ErrTransient:      ErrTransient,
}

// vectorKind returns the goldenvectors id for k. A new ErrorKind must be
// added here and to goldenvectors.
func vectorKind(t *testing.T, k ErrorKind) string {
	t.Helper()
	switch k {
	case KindUnknown:
		return goldenvectors.KindUnknown
	case KindReauthRequired:
		return goldenvectors.KindReauthRequired
	case KindAccessDenied:
		return goldenvectors.KindAccessDenied
	case KindInvalidGrant:
		return goldenvectors.KindInvalidGrant
	case KindTransient:
		return goldenvectors.KindTransient
	}
	t.Fatalf("ErrorKind %d (%v) has no goldenvectors id", int(k), k)
	return ""
}

func checkVectorError(t *testing.T, err error, want *goldenvectors.Error) {
	t.Helper()
	var re *RefreshError
	if !errors.As(err, &re) {
		t.Fatalf("Token() error = %v (%T), want a *RefreshError", err, err)
	}
	got := goldenvectors.Error{
		Kind:        vectorKind(t, re.Kind),
		Code:        re.Code,
		Subtype:     re.Subtype,
		Description: re.Description,
		StatusCode:  re.StatusCode,
	}
	w := *want
	w.Is = nil
	if !reflect.DeepEqual(got, w) {
		t.Errorf("Token() error = %+v, want %+v", got, w)
	}
	for _, name := range want.Is {
		if _, ok := vectorSentinels[name]; !ok {
			t.Errorf("vector lists unknown sentinel %q", name)
		}
	}
	for name, sentinel := range vectorSentinels {
		if is, wantIs := errors.Is(err, sentinel), slices.Contains(want.Is, name); is != wantIs {
			t.Errorf("errors.Is(err, %s) = %v, want %v (err = %v)", name, is, wantIs, err)
		}
	}
	// No vector cancels the caller's ctx, so the error must not look like
	// it ended (for example after http.Client.Timeout).
	for _, ctxErr := range []error{context.DeadlineExceeded, context.Canceled} {
		if errors.Is(err, ctxErr) {
			t.Errorf("errors.Is(err, %v) = true, want false (err = %v)", ctxErr, err)
		}
	}
}
