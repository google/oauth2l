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
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSAEmail = "sa@project.iam.gserviceaccount.com"

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyPEM  string
)

// testServiceAccountKey returns an RSA key, generated once per test run, and
// its PKCS #8 PEM encoding. Keys are never checked in.
func testServiceAccountKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			panic(err)
		}
		testKey = k
		testKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return testKey, testKeyPEM
}

// saJSON returns service_account JSON with the given extra fields. A nil
// value removes the field.
func saJSON(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	_, keyPEM := testServiceAccountKey(t)
	m := map[string]any{
		"type":           "service_account",
		"client_email":   testSAEmail,
		"private_key":    keyPEM,
		"private_key_id": "key-id-1",
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestSAProvider(t *testing.T, srv *fakeServer, cfg Config) *serviceAccountTokenProvider {
	t.Helper()
	if cfg.JSON == nil {
		cfg.JSON = saJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	}
	if cfg.Client == nil {
		cfg.Client = srv.Client()
	}
	p, err := newServiceAccountTokenProvider(&cfg)
	if err != nil {
		t.Fatalf("newServiceAccountTokenProvider() error = %v", err)
	}
	return p
}

// verifyJWT checks the RS256 signature of a compact JWT with the test key and
// returns its header and claims.
func verifyJWT(t *testing.T, tok string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3: %q", len(parts), tok)
	}
	key, _ := testServiceAccountKey(t)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("JWT signature does not verify: %v", err)
	}
	decode := func(s string) map[string]any {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decoding JWT part: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("parsing JWT part: %v", err)
		}
		return m
	}
	return decode(parts[0]), decode(parts[1])
}

func TestServiceAccount2LORequest(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`})
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s1", "s2"}})

	before := time.Now()
	tok, err := p.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tok.Value != "at-1" || tok.Type != "Bearer" {
		t.Errorf("token = %q %q, want at-1 Bearer", tok.Value, tok.Type)
	}
	if d := tok.Expiry.Sub(before); d < 3590*time.Second || d > 3610*time.Second {
		t.Errorf("expiry is %v from now, want about 1h", d)
	}
	if len(tok.Metadata) != 0 {
		t.Errorf("Metadata = %v, want empty (no access token copied from the response)", tok.Metadata)
	}

	forms := srv.recordedForms()
	if len(forms) != 1 {
		t.Fatalf("server got %d requests, want 1", len(forms))
	}
	const wantGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	if got := forms[0].Get("grant_type"); got != wantGrant {
		t.Errorf("grant_type = %q, want %q", got, wantGrant)
	}
	header, claims := verifyJWT(t, forms[0].Get("assertion"))
	if header["alg"] != "RS256" || header["kid"] != "key-id-1" {
		t.Errorf("JWT header = %v, want RS256 with kid key-id-1", header)
	}
	if claims["iss"] != testSAEmail || claims["aud"] != srv.URL+"/token" || claims["scope"] != "s1 s2" {
		t.Errorf("JWT claims = %v, want iss %s, aud the token URL, scope \"s1 s2\"", claims, testSAEmail)
	}
}

func TestServiceAccountEachTokenCallSendsARequest(t *testing.T) {
	body := `{"access_token":"at","expires_in":3600}`
	srv := newFakeServer(t, fakeResponse{body: body}, fakeResponse{body: body})
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
	for range 2 {
		if _, err := p.Token(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(srv.recordedForms()); n != 2 {
		t.Errorf("server got %d requests, want 2 (no caching)", n)
	}
}

func TestServiceAccountIDTokenMetadata(t *testing.T) {
	// go/auth takes the expiry from the ID token when there is one.
	exp := time.Now().Add(time.Hour).Unix()
	idTok := "ey" + "JhbGciOiJSUzI1NiJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+itoa(exp)+`}`)) + ".c2ln"
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"at","expires_in":3600,"id_token":"` + idTok + `"}`})
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
	tok, err := p.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Metadata[MetadataIDToken] != idTok {
		t.Errorf("Metadata[%q] = %v, want the ID token", MetadataIDToken, tok.Metadata[MetadataIDToken])
	}
	if _, ok := tok.Metadata["access_token"]; ok {
		t.Error("Metadata must not carry the access token")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestServiceAccountTokenURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
		json any
		want string
	}{
		{"config_overrides_json", "https://override.example/token", "https://json.example/token", "https://override.example/token"},
		{"json_token_uri", "", "https://json.example/token", "https://json.example/token"},
		{"default", "", nil, defaultTokenURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				JSON:     saJSON(t, map[string]any{"token_uri": tc.json}),
				TokenURL: tc.cfg,
				Client:   newFakeServer(t).Client(),
			}
			p, err := newServiceAccountTokenProvider(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			if p.tokenURL != tc.want {
				t.Errorf("tokenURL = %q, want %q", p.tokenURL, tc.want)
			}
		})
	}
}

func TestServiceAccountErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp fakeResponse
		want error
		kind ErrorKind
	}{
		{"invalid_grant", fakeResponse{status: 400, body: `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`}, ErrInvalidGrant, KindInvalidGrant},
		{"invalid_scope", fakeResponse{status: 400, body: `{"error":"invalid_scope"}`}, ErrInvalidGrant, KindInvalidGrant},
		{"503", fakeResponse{status: 503, body: `{"error":"server_error"}`}, ErrTransient, KindTransient},
		{"closed_connection", fakeResponse{closeConn: true}, ErrTransient, KindTransient},
		{"2xx_not_json", fakeResponse{body: `not json`}, nil, KindUnknown},
		{"2xx_without_access_token", fakeResponse{body: `{"expires_in":3600}`}, nil, KindUnknown},
		{"2xx_wrong_json_type", fakeResponse{body: `{"access_token":"at","expires_in":"3600"}`}, nil, KindUnknown},
		{"2xx_bad_id_token", fakeResponse{body: `{"access_token":"at","id_token":"a.!!!.c"}`}, nil, KindUnknown},
		{"2xx_id_token_without_dots", fakeResponse{body: `{"access_token":"at","id_token":"abc"}`}, nil, KindUnknown},
		{"2xx_overflowing_expires_in", fakeResponse{body: `{"access_token":"at","expires_in":9223372037}`}, nil, KindUnknown},
		{"2xx_negative_expires_in", fakeResponse{body: `{"access_token":"at","expires_in":-1}`}, nil, KindUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, tc.resp)
			p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
			_, err := p.Token(t.Context())
			var re *RefreshError
			if !errors.As(err, &re) || re.Kind != tc.kind {
				t.Fatalf("Token() error = %v, want a RefreshError of kind %v", err, tc.kind)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Token() error = %v, want it to match %v", err, tc.want)
			}
			if tc.kind == KindUnknown && errors.Is(err, ErrTransient) {
				t.Errorf("Token() error = %v must not be transient", err)
			}
			wantStatus := tc.resp.status
			if wantStatus == 0 {
				wantStatus = 200 // fakeServer's default
			}
			if tc.resp.closeConn {
				wantStatus = 0 // no response was received
			}
			if re.StatusCode != wantStatus {
				t.Errorf("Token() error StatusCode = %d, want %d", re.StatusCode, wantStatus)
			}
		})
	}
}

func TestServiceAccountContextCanceled(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{delay: time.Hour})
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := p.Token(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Token() error = %v, want context.DeadlineExceeded", err)
	}
	var re *RefreshError
	if errors.As(err, &re) {
		t.Errorf("Token() returned %v, want the context error, not a RefreshError", re)
	}
}

func TestServiceAccountSelfSignedJWTCanceledContext(t *testing.T) {
	srv := newFakeServer(t)
	p := newTestSAProvider(t, srv, Config{UseSelfSignedJWT: true, Scopes: []string{"s"}})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	tok, err := p.Token(ctx)
	if !errors.Is(err, context.Canceled) || tok != nil {
		t.Fatalf("Token() = %v, %v; want nil, context.Canceled", tok, err)
	}
}

func TestServiceAccountSelfSignedJWT(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		json map[string]any
	}{
		{"use_self_signed_jwt", Config{UseSelfSignedJWT: true}, nil},
		{"config_universe", Config{UniverseDomain: "example-universe.com"}, nil},
		{"json_universe", Config{}, map[string]any{"universe_domain": "example-universe.com"}},
		{"json_universe_with_default_config_universe", Config{UniverseDomain: "googleapis.com"}, map[string]any{"universe_domain": "example-universe.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t) // any request fails the test
			cfg := tc.cfg
			cfg.Scopes = []string{"s1", "s2"}
			cfg.JSON = saJSON(t, tc.json)
			p := newTestSAProvider(t, srv, cfg)

			before := time.Now()
			tok, err := p.Token(t.Context())
			if err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			if n := len(srv.recordedForms()); n != 0 {
				t.Errorf("server got %d requests, want none for a self-signed JWT", n)
			}
			header, claims := verifyJWT(t, tok.Value)
			if header["kid"] != "key-id-1" {
				t.Errorf("JWT header = %v, want kid key-id-1", header)
			}
			if claims["iss"] != testSAEmail || claims["sub"] != testSAEmail || claims["scope"] != "s1 s2" {
				t.Errorf("JWT claims = %v, want iss and sub %s and scope \"s1 s2\"", claims, testSAEmail)
			}
			if d := tok.Expiry.Sub(before); d < 59*time.Minute || d > 61*time.Minute {
				t.Errorf("expiry is %v from now, want about 1h", d)
			}
			if tok.Type != "Bearer" {
				t.Errorf("Type = %q, want Bearer", tok.Type)
			}
		})
	}
}

func TestServiceAccountUniverseDomain(t *testing.T) {
	client := newFakeServer(t).Client()
	for _, tc := range []struct {
		name, cfg string
		json      any
		want      string
	}{
		{"default", "", nil, "googleapis.com"},
		{"json", "", "example-universe.com", "example-universe.com"},
		{"config_overrides_json", "other.example", "example-universe.com", "other.example"},
		{"default_config_overrides_json", "googleapis.com", "example-universe.com", "googleapis.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				JSON:           saJSON(t, map[string]any{"universe_domain": tc.json}),
				UniverseDomain: tc.cfg,
				Scopes:         []string{"s"},
				Client:         client,
			}
			p, err := newServiceAccountTokenProvider(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			if p.universeDomain != tc.want {
				t.Errorf("universeDomain = %q, want %q", p.universeDomain, tc.want)
			}
			if !p.selfSignedJWT && tc.want != "googleapis.com" {
				t.Errorf("selfSignedJWT = false for universe %q, want true", tc.want)
			}
		})
	}
}

func TestNewServiceAccountTokenProviderErrors(t *testing.T) {
	client := newFakeServer(t).Client()
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"nil_client", Config{JSON: saJSON(t, nil)}, "Client is nil"},
		{"bad_json", Config{JSON: []byte("{"), Client: client}, "parsing service_account JSON"},
		{"wrong_type", Config{JSON: userJSON(t, nil), Client: client}, `want service_account`},
		{"missing_fields", Config{JSON: saJSON(t, map[string]any{"client_email": nil, "private_key": nil}), Client: client}, "missing client_email, private_key"},
		{"key_cannot_sign", Config{JSON: saJSON(t, map[string]any{"private_key": x25519PKCS8(t)}), Client: client}, "cannot sign"},
		{"bad_key", Config{JSON: saJSON(t, map[string]any{"private_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"}), Client: client}, "not a PKCS #8"},
		{"self_signed_without_scopes", Config{JSON: saJSON(t, nil), Client: client, UseSelfSignedJWT: true}, "needs Config.Scopes"},
		{"relative_token_url", Config{JSON: saJSON(t, nil), TokenURL: "/token", Client: client}, "token URL must be"},
		{"token_uri_without_host", Config{JSON: saJSON(t, map[string]any{"token_uri": "https:///token"}), Client: client}, "token URL must be"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newServiceAccountTokenProvider(&tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("newServiceAccountTokenProvider() error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestServiceAccountDoesNotLogSecrets(t *testing.T) {
	// With debug logging on, go/auth would print the signed assertion and the
	// access token to stderr if oauth2lib passed it a nil logger.
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close() // a no-op error after the explicit Close below
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"secret-access-token","expires_in":3600}`})
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
	if _, err := p.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	ss := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}, UseSelfSignedJWT: true, JSON: saJSON(t, nil)})
	if _, err := ss.Token(t.Context()); err != nil {
		t.Fatal(err)
	}

	w.Close()
	os.Stderr = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading stderr: %v", err)
	}
	for _, secret := range []string{"secret-access-token", "assertion", "eyJ"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("stderr contains %q: %s", secret, out)
		}
	}
}

func TestServiceAccountConcurrentTokens(t *testing.T) {
	const n = 8
	responses := make([]fakeResponse, n)
	for i := range responses {
		responses[i] = fakeResponse{body: `{"access_token":"at","expires_in":3600}`}
	}
	srv := newFakeServer(t, responses...)
	p := newTestSAProvider(t, srv, Config{Scopes: []string{"s"}})
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Token(t.Context()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// x25519PKCS8 returns a PEM PKCS #8 X25519 key, which parses but can't sign.
func x25519PKCS8(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// bodyErrorTransport returns a 200 response whose body fails with err after
// a few bytes, like an HTTP/2 stream reset while reading.
type bodyErrorTransport struct{ err error }

func (b bodyErrorTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(io.MultiReader(strings.NewReader(`{"access`), errReader{b.err})),
		Request:    req,
	}, nil
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestServiceAccountBodyReadErrorIsTransient(t *testing.T) {
	// Not a net.Error, like net/http's HTTP/2 stream errors.
	streamReset := errors.New("stream error: stream ID 1; INTERNAL_ERROR")
	cfg := Config{
		JSON:   saJSON(t, nil),
		Scopes: []string{"s"},
		Client: &http.Client{Transport: bodyErrorTransport{streamReset}},
	}
	p, err := newServiceAccountTokenProvider(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Token(t.Context())
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("Token() error = %v, want ErrTransient", err)
	}
}

func TestServiceAccountCopiesConfigSlices(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"at","expires_in":3600}`})
	cfg := Config{Scopes: []string{"s1"}}
	p := newTestSAProvider(t, srv, cfg)
	cfg.Scopes[0] = "changed"
	if _, err := p.Token(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, claims := verifyJWT(t, srv.recordedForms()[0].Get("assertion"))
	if claims["scope"] != "s1" {
		t.Errorf("JWT scope = %v, want s1 (the scopes at construction)", claims["scope"])
	}
}

func TestCheckPrivateKeyAcceptsKeyForms(t *testing.T) {
	k, _ := testServiceAccountKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]string{
		"pkcs8_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		"pkcs1_pem": string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})),
		"pkcs8_der": string(pkcs8),
	} {
		if err := checkPrivateKey(key); err != nil {
			t.Errorf("checkPrivateKey(%s) = %v, want nil", name, err)
		}
	}
}
