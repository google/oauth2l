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

// TestGoldenVectors runs every vector in goldenvectors: it builds the
// credentials, calls Token once, and checks each request, the token or
// error, and the universe domain.
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
		t.Run(v.Name, func(t *testing.T) { runGoldenVector(t, v, keyPEM) })
	}
}

func runGoldenVector(t *testing.T, v goldenvectors.Vector, keyPEM string) {
	rt := &vectorTransport{t: t, exchanges: v.Exchanges}
	client := &http.Client{Transport: rt}
	ctx := t.Context()

	var creds *auth.Credentials
	switch in := v.Input; {
	case in.Config != nil && in.Impersonation == nil:
		var err error
		if creds, err = BuildCredentials(ctx, vectorConfig(t, *in.Config, keyPEM, client)); err != nil {
			t.Fatalf("BuildCredentials() error = %v", err)
		}
	case in.Impersonation != nil && in.Config == nil:
		imp := in.Impersonation
		src, err := BuildCredentials(ctx, vectorConfig(t, imp.Source, keyPEM, client))
		if err != nil {
			t.Fatalf("BuildCredentials(source) error = %v", err)
		}
		creds, err = Impersonate(ctx, &ImpersonationConfig{
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
	default:
		t.Fatal("vector input must set exactly one of config and impersonation")
	}

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
	if resp.TransportError != "" {
		return nil, errors.New(resp.TransportError)
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

func checkVectorError(t *testing.T, err error, want *goldenvectors.Error) {
	t.Helper()
	var re *RefreshError
	if !errors.As(err, &re) {
		t.Fatalf("Token() error = %v (%T), want a *RefreshError", err, err)
	}
	got := goldenvectors.Error{
		Kind:        re.Kind.String(),
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
}
