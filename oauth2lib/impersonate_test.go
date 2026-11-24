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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

const (
	testTarget     = "target@project.iam.gserviceaccount.com"
	testIAMPath    = "/v1/projects/-/serviceAccounts/" + testTarget + ":generateAccessToken"
	testExpireTime = "2030-01-02T03:04:05Z"
	okIAMBody      = `{"accessToken":"imp-token","expireTime":"` + testExpireTime + `"}`
)

// iamRequest is one request the fake IAM server received.
type iamRequest struct {
	path, auth, contentType string
	body                    string
}

// fakeIAM is an IAM Credentials server that records requests and answers
// with queued responses (status, body). It also serves /token as an OAuth
// token endpoint, for source credentials, recording the forms.
type fakeIAM struct {
	*httptest.Server
	t testing.TB

	mu         sync.Mutex
	iamReqs    []iamRequest
	iamResps   []fakeResponse
	tokenForms []url.Values
	tokenResps []fakeResponse
}

func newFakeIAM(t testing.TB, iamResps ...fakeResponse) *fakeIAM {
	t.Helper()
	f := &fakeIAM{t: t, iamResps: iamResps}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeIAM) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		r.ParseForm()
		f.mu.Lock()
		f.tokenForms = append(f.tokenForms, r.PostForm)
		if len(f.tokenResps) == 0 {
			f.mu.Unlock()
			f.t.Errorf("fakeIAM: unexpected token request")
			http.Error(w, "no response queued", http.StatusInternalServerError)
			return
		}
		resp := f.tokenResps[0]
		f.tokenResps = f.tokenResps[1:]
		f.mu.Unlock()
		writeFake(f.t, w, r, resp)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.iamReqs = append(f.iamReqs, iamRequest{
		path:        r.URL.EscapedPath(),
		auth:        r.Header.Get("Authorization"),
		contentType: r.Header.Get("Content-Type"),
		body:        string(body),
	})
	if len(f.iamResps) == 0 {
		f.mu.Unlock()
		f.t.Errorf("fakeIAM: unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "no response queued", http.StatusInternalServerError)
		return
	}
	resp := f.iamResps[0]
	f.iamResps = f.iamResps[1:]
	f.mu.Unlock()
	writeFake(f.t, w, r, resp)
}

func (f *fakeIAM) requests() []iamRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]iamRequest(nil), f.iamReqs...)
}

func (f *fakeIAM) forms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.tokenForms...)
}

// countingSource returns credentials whose tokens are "src-1", "src-2", ...
// and that report universe.
type countingSource struct {
	n   atomic.Int64
	err error
}

func (s *countingSource) Token(ctx context.Context) (*auth.Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.err != nil {
		return nil, s.err
	}
	return &auth.Token{Value: fmt.Sprintf("src-%d", s.n.Add(1)), Type: "Bearer"}, nil
}

func newSource(universe string) (*auth.Credentials, *countingSource) {
	s := &countingSource{}
	opts := &auth.CredentialsOptions{TokenProvider: s}
	if universe != "" {
		opts.UniverseDomainProvider = auth.CredentialsPropertyFunc(func(context.Context) (string, error) {
			return universe, nil
		})
	}
	return auth.NewCredentials(opts), s
}

// testImpersonationConfig returns a config that sends IAM requests to srv.
func testImpersonationConfig(srv *fakeIAM, source *auth.Credentials) *ImpersonationConfig {
	return &ImpersonationConfig{
		Source:   source,
		Target:   testTarget,
		Scopes:   []string{"s1", "s2"},
		Endpoint: srv.URL + "/",
		Client:   srv.Client(),
	}
}

func TestImpersonateRequest(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody}, fakeResponse{body: okIAMBody})
	source, counter := newSource("")
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	// The credentials are uncached: each Token call gets a new source token
	// and sends a new IAM request.
	for range 2 {
		tok, err := creds.Token(t.Context())
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		want, _ := time.Parse(time.RFC3339, testExpireTime)
		if tok.Value != "imp-token" || tok.Type != "Bearer" || !tok.Expiry.Equal(want) {
			t.Errorf("Token() = %+v, want imp-token, Bearer, expiry %v", tok, want)
		}
		if len(tok.Metadata) != 0 {
			t.Errorf("Token().Metadata = %v, want empty", tok.Metadata)
		}
	}
	if got := counter.n.Load(); got != 2 {
		t.Errorf("source Token called %d times, want 2", got)
	}
	reqs := srv.requests()
	if len(reqs) != 2 {
		t.Fatalf("IAM got %d requests, want 2", len(reqs))
	}
	for i, r := range reqs {
		wantAuth := fmt.Sprintf("Bearer src-%d", i+1)
		if r.path != testIAMPath || r.auth != wantAuth || r.contentType != "application/json" {
			t.Errorf("request %d = %+v, want path %s, Authorization %q, JSON", i, r, testIAMPath, wantAuth)
		}
		// The same body google-auth sends, including null delegates.
		if want := `{"delegates":null,"scope":["s1","s2"],"lifetime":"3600s"}`; r.body != want {
			t.Errorf("request %d body = %s, want %s", i, r.body, want)
		}
	}
	if ud, err := creds.UniverseDomain(t.Context()); err != nil || ud != "googleapis.com" {
		t.Errorf("UniverseDomain() = %q, %v, want googleapis.com", ud, err)
	}
	if creds.JSON() != nil {
		t.Errorf("JSON() = %s, want nil", creds.JSON())
	}
}

func TestImpersonateDelegatesAndLifetime(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
	source, _ := newSource("")
	cfg := testImpersonationConfig(srv, source)
	cfg.Delegates = []string{"d1@p.iam.gserviceaccount.com", "projects/-/serviceAccounts/d2@p.iam.gserviceaccount.com"}
	cfg.Lifetime = 12 * time.Hour
	creds, err := Impersonate(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	// Changing the config afterwards has no effect.
	cfg.Delegates[0], cfg.Scopes[0] = "changed", "changed"
	if _, err := creds.Token(t.Context()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	want := `{"delegates":["d1@p.iam.gserviceaccount.com","projects/-/serviceAccounts/d2@p.iam.gserviceaccount.com"],"scope":["s1","s2"],"lifetime":"43200s"}`
	if got := srv.requests()[0].body; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

// recordingTransport records request URLs and answers with okIAMBody.
type recordingTransport struct {
	mu   sync.Mutex
	urls []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.urls = append(rt.urls, r.URL.String())
	rt.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(okIAMBody)),
		Request:    r,
	}, nil
}

// TestImpersonateTrimsDelegatesAndScopes checks that the request carries
// the trimmed values that were validated, with empty scopes dropped, as for
// Config.Scopes.
func TestImpersonateTrimsDelegatesAndScopes(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
	source, _ := newSource("")
	cfg := testImpersonationConfig(srv, source)
	cfg.Delegates = []string{" d1@p.iam.gserviceaccount.com\t"}
	cfg.Scopes = []string{" s1 ", "", "s2\n"}
	creds, err := Impersonate(t.Context(), cfg)
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	if _, err := creds.Token(t.Context()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	want := `{"delegates":["d1@p.iam.gserviceaccount.com"],"scope":["s1","s2"],"lifetime":"3600s"}`
	if got := srv.requests()[0].body; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestImpersonateEndpoint(t *testing.T) {
	tests := []struct {
		name, universe, endpoint, want string
	}{
		{"default", "", "", "https://iamcredentials.googleapis.com" + testIAMPath},
		{"source_universe", "example.com", "", "https://iamcredentials.example.com" + testIAMPath},
		{"padded_source_universe", " example.com ", "", "https://iamcredentials.example.com" + testIAMPath},
		// The override wins over Source's universe, and the credentials
		// still report Source's universe (google-auth).
		{"override_wins_over_source_universe", "example.com", "https://override.example/", "https://override.example" + testIAMPath},
		{"override", "", "https://iamcredentials.mtls.googleapis.com/", "https://iamcredentials.mtls.googleapis.com" + testIAMPath},
		{"override_without_slash", "", "https://regional.example", "https://regional.example" + testIAMPath},
		{"override_with_path", "", "https://proxy.example/iam", "https://proxy.example/iam" + testIAMPath},
		{"override_with_port", "", "https://iam.example:8443/", "https://iam.example:8443" + testIAMPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			source, _ := newSource(tt.universe)
			creds, err := Impersonate(t.Context(), &ImpersonationConfig{
				Source:   source,
				Target:   testTarget,
				Scopes:   []string{"s"},
				Endpoint: tt.endpoint,
				Client:   &http.Client{Transport: rt},
			})
			if err != nil {
				t.Fatalf("Impersonate() error = %v", err)
			}
			if _, err := creds.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			if len(rt.urls) != 1 || rt.urls[0] != tt.want {
				t.Errorf("requests went to %v, want [%s]", rt.urls, tt.want)
			}
			wantUD := strings.TrimSpace(tt.universe)
			if wantUD == "" {
				wantUD = "googleapis.com"
			}
			if ud, _ := creds.UniverseDomain(t.Context()); ud != wantUD {
				t.Errorf("UniverseDomain() = %q, want %q", ud, wantUD)
			}
		})
	}
}

func TestImpersonateConfigErrors(t *testing.T) {
	source, _ := newSource("")
	client := noNetworkClient(t) // building never makes a request
	valid := func() *ImpersonationConfig {
		return &ImpersonationConfig{Source: source, Target: testTarget, Scopes: []string{"s"}, Client: client}
	}
	tests := []struct {
		name   string
		mutate func(*ImpersonationConfig) *ImpersonationConfig
		want   string
	}{
		{"nil_config", func(*ImpersonationConfig) *ImpersonationConfig { return nil }, "ImpersonationConfig is nil"},
		{"nil_client", func(c *ImpersonationConfig) *ImpersonationConfig { c.Client = nil; return c }, "Client is nil"},
		{"nil_source", func(c *ImpersonationConfig) *ImpersonationConfig { c.Source = nil; return c }, "Source is nil"},
		{"empty_target", func(c *ImpersonationConfig) *ImpersonationConfig { c.Target = " "; return c }, "Target is empty"},
		{"target_with_slash", func(c *ImpersonationConfig) *ImpersonationConfig { c.Target = "a/b"; return c }, "not a service account"},
		{"target_with_colon", func(c *ImpersonationConfig) *ImpersonationConfig { c.Target = "a:b"; return c }, "not a service account"},
		{"empty_delegate", func(c *ImpersonationConfig) *ImpersonationConfig { c.Delegates = []string{"d", ""}; return c }, "empty delegate"},
		{"blank_delegate", func(c *ImpersonationConfig) *ImpersonationConfig { c.Delegates = []string{"d", " \t"}; return c }, "empty delegate"},
		{"delegate_with_space", func(c *ImpersonationConfig) *ImpersonationConfig { c.Delegates = []string{"a b"}; return c }, "delegate with spaces"},
		{"no_scopes", func(c *ImpersonationConfig) *ImpersonationConfig { c.Scopes = nil; return c }, "Scopes is empty"},
		{"only_empty_scopes", func(c *ImpersonationConfig) *ImpersonationConfig { c.Scopes = []string{"", " "}; return c }, "Scopes is empty"},
		{"scope_with_space", func(c *ImpersonationConfig) *ImpersonationConfig { c.Scopes = []string{"a b"}; return c }, "with spaces"},
		{"negative_lifetime", func(c *ImpersonationConfig) *ImpersonationConfig { c.Lifetime = -time.Second; return c }, "Lifetime"},
		{"sub_second_lifetime", func(c *ImpersonationConfig) *ImpersonationConfig { c.Lifetime = 500 * time.Millisecond; return c }, "Lifetime"},
		{"fractional_lifetime", func(c *ImpersonationConfig) *ImpersonationConfig { c.Lifetime = 1500 * time.Millisecond; return c }, "Lifetime"},
		{"endpoint_bare_query", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "https://iam.example/?"; return c }, "IAM endpoint must be"},
		{"endpoint_bare_fragment", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "https://iam.example/#"; return c }, "IAM endpoint must be"},
		{"endpoint_with_userinfo", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Endpoint = "https://user:pass@iam.example/"
			return c
		}, "IAM endpoint must be"},
		{"endpoint_empty_host", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "https://:8080/"; return c }, "IAM endpoint must be"},
		{"endpoint_with_space", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "https://iam.example/ x"; return c }, "IAM endpoint must be"},
		{"source_universe_with_port", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source, _ = newSource("example.com:8443")
			return c
		}, "not a valid domain name"},
		{"source_universe_with_backslash", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source, _ = newSource(`example.com\x`)
			return c
		}, "not a valid domain name"},
		{"source_universe_with_query", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source, _ = newSource("example.com?x")
			return c
		}, "not a valid domain name"},
		{"source_universe_with_fragment", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source, _ = newSource("example.com#x")
			return c
		}, "not a valid domain name"},
		{"source_universe_with_slash", func(c *ImpersonationConfig) *ImpersonationConfig { c.Source, _ = newSource("example.com/x"); return c }, "not a valid domain name"},
		{"source_universe_with_at", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source, _ = newSource("x@attacker.example")
			return c
		}, "not a valid domain name"},
		{"lifetime_over_12h", func(c *ImpersonationConfig) *ImpersonationConfig { c.Lifetime = 12*time.Hour + time.Second; return c }, "Lifetime"},
		{"endpoint_no_scheme", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Endpoint = "iamcredentials.googleapis.com"
			return c
		}, "IAM endpoint"},
		{"endpoint_ftp", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "ftp://h/"; return c }, "IAM endpoint"},
		{"endpoint_query", func(c *ImpersonationConfig) *ImpersonationConfig { c.Endpoint = "https://h/?x=1"; return c }, "IAM endpoint"},
		{"bad_universe_endpoint", func(c *ImpersonationConfig) *ImpersonationConfig {
			s, _ := newSource("bad host")
			c.Source = s
			return c
		}, "not a valid domain name"},
		{"universe_error", func(c *ImpersonationConfig) *ImpersonationConfig {
			c.Source = auth.NewCredentials(&auth.CredentialsOptions{
				TokenProvider: &countingSource{},
				UniverseDomainProvider: auth.CredentialsPropertyFunc(func(context.Context) (string, error) {
					return "", errors.New("metadata unavailable")
				}),
			})
			return c
		}, "metadata unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Impersonate(t.Context(), tt.mutate(valid()))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Impersonate() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Impersonate(ctx, valid()); !errors.Is(err, context.Canceled) {
		t.Errorf("Impersonate(canceled ctx) error = %v, want context.Canceled", err)
	}
}

func TestImpersonateTokenErrors(t *testing.T) {
	tests := []struct {
		name       string
		resp       fakeResponse
		wantKind   ErrorKind
		wantCode   string
		wantStatus int
		wantDesc   string
	}{
		{
			name:       "permission_denied",
			resp:       fakeResponse{status: 403, body: `{"error":{"code":403,"message":"Permission 'iam.serviceAccounts.getAccessToken' denied","status":"PERMISSION_DENIED"}}`},
			wantKind:   KindUnknown,
			wantCode:   "PERMISSION_DENIED",
			wantStatus: 403,
			wantDesc:   "Permission 'iam.serviceAccounts.getAccessToken' denied",
		},
		{
			name:       "unavailable",
			resp:       fakeResponse{status: 503, body: `{"error":{"code":503,"message":"try again","status":"UNAVAILABLE"}}`},
			wantKind:   KindTransient,
			wantCode:   "UNAVAILABLE",
			wantStatus: 503,
		},
		{name: "not_json", resp: fakeResponse{body: `<html>`, contentType: "text/html"}, wantKind: KindUnknown, wantStatus: 200, wantDesc: "not valid JSON"},
		{name: "no_access_token", resp: fakeResponse{body: `{"expireTime":"` + testExpireTime + `"}`}, wantKind: KindUnknown, wantStatus: 200, wantDesc: "no accessToken"},
		{name: "bad_expire_time", resp: fakeResponse{body: `{"accessToken":"x","expireTime":"tomorrow"}`}, wantKind: KindUnknown, wantStatus: 200, wantDesc: "invalid expireTime"},
		{name: "no_expire_time", resp: fakeResponse{body: `{"accessToken":"x"}`}, wantKind: KindUnknown, wantStatus: 200, wantDesc: "invalid expireTime"},
		{name: "zero_expire_time", resp: fakeResponse{body: `{"accessToken":"x","expireTime":"0001-01-01T00:00:00Z"}`}, wantKind: KindUnknown, wantStatus: 200, wantDesc: "invalid expireTime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeIAM(t, tt.resp)
			source, _ := newSource("")
			creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
			if err != nil {
				t.Fatalf("Impersonate() error = %v", err)
			}
			_, err = creds.Token(t.Context())
			var re *RefreshError
			if !errors.As(err, &re) {
				t.Fatalf("Token() error = %v, want a *RefreshError", err)
			}
			if re.Kind != tt.wantKind || re.Code != tt.wantCode || re.StatusCode != tt.wantStatus || !strings.Contains(re.Description, tt.wantDesc) {
				t.Errorf("Token() error = %+v, want kind %v, code %q, status %d, description containing %q",
					re, tt.wantKind, tt.wantCode, tt.wantStatus, tt.wantDesc)
			}
			if strings.Contains(err.Error(), "src-1") {
				t.Errorf("Token() error %q contains the source token", err)
			}
		})
	}
}

func TestImpersonateSourceErrorPassedThrough(t *testing.T) {
	srv := newFakeIAM(t) // no IAM request expected
	sourceErr := &RefreshError{Kind: KindReauthRequired, Code: "invalid_grant", Subtype: "rapt_required"}
	s := &countingSource{err: sourceErr}
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, auth.NewCredentials(&auth.CredentialsOptions{TokenProvider: s})))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	_, err = creds.Token(t.Context())
	if err != sourceErr || !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Token() error = %v, want the source's error unchanged", err)
	}
	if n := len(srv.requests()); n != 0 {
		t.Errorf("IAM got %d requests, want 0", n)
	}
}

func TestImpersonateEmptySourceToken(t *testing.T) {
	srv := newFakeIAM(t)
	var empty emptyTokenProvider
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, auth.NewCredentials(&auth.CredentialsOptions{TokenProvider: empty})))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	var re *RefreshError
	if _, err := creds.Token(t.Context()); !errors.As(err, &re) || re.Kind != KindUnknown {
		t.Errorf("Token() error = %v, want a KindUnknown *RefreshError", err)
	}
}

func TestImpersonateContext(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody, delay: time.Minute})
	source, _ := newSource("")
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := creds.Token(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Token(expiring ctx) error = %v, want context.DeadlineExceeded", err)
	}

	canceled, cancel2 := context.WithCancel(t.Context())
	cancel2()
	if _, err := creds.Token(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("Token(canceled ctx) error = %v, want context.Canceled", err)
	}
}

func TestImpersonateConcurrent(t *testing.T) {
	const n = 8
	resps := make([]fakeResponse, n)
	for i := range resps {
		resps[i] = fakeResponse{body: okIAMBody}
	}
	srv := newFakeIAM(t, resps...)
	source, counter := newSource("")
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if _, err := creds.Token(t.Context()); err != nil {
				t.Errorf("Token() error = %v", err)
			}
		})
	}
	wg.Wait()
	if got := counter.n.Load(); got != n {
		t.Errorf("source Token called %d times, want %d", got, n)
	}
	if got := len(srv.requests()); got != n {
		t.Errorf("IAM got %d requests, want %d", got, n)
	}
}

func TestImpersonationConfigFormatting(t *testing.T) {
	source, _ := newSource("")
	cfg := ImpersonationConfig{Source: source, Target: testTarget, Scopes: []string{"s"}}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("cfg", "config", cfg)
	for name, got := range map[string]string{
		"%v":   fmt.Sprintf("%v", cfg),
		"%#v":  fmt.Sprintf("%#v", cfg),
		"slog": logs.String(),
	} {
		if !strings.Contains(got, testTarget) {
			t.Errorf("%s output %q is missing Target", name, got)
		}
		if strings.Contains(got, "TokenProvider") {
			t.Errorf("%s output %q dumps Source", name, got)
		}
	}
}

// impersonatedJSON returns impersonated_service_account JSON with source as
// source_credentials and the given extra fields. A nil value removes a field.
func impersonatedJSON(t *testing.T, source []byte, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"type":                              "impersonated_service_account",
		"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + testTarget + ":generateAccessToken",
		"source_credentials":                json.RawMessage(source),
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

func TestParseImpersonatedServiceAccountJSON(t *testing.T) {
	src := userJSON(t, nil)
	js := impersonatedJSON(t, src, map[string]any{
		"delegates": []string{"d1", "d2"},
		"scopes":    []string{"a", " ", "b"},
	})
	got, err := ParseImpersonatedServiceAccountJSON(js)
	if err != nil {
		t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
	}
	gotSrc := got.SourceJSON
	var gotM, wantM map[string]any
	if err := json.Unmarshal(gotSrc, &gotM); err != nil {
		t.Fatalf("json.Unmarshal(source JSON) error = %v", err)
	}
	if err := json.Unmarshal(src, &wantM); err != nil {
		t.Fatalf("json.Unmarshal(want source JSON) error = %v", err)
	}
	if !reflect.DeepEqual(gotM, wantM) {
		t.Errorf("ParseImpersonatedServiceAccountJSON() source JSON = %s, want %s", gotSrc, src)
	}
	want := &ImpersonatedServiceAccount{
		SourceJSON: gotSrc,
		SourceType: "authorized_user",
		Target:     testTarget,
		Delegates:  []string{"d1", "d2"},
		Scopes:     []string{"a", "b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseImpersonatedServiceAccountJSON() = %v, want %v", got, want)
	}
	// The returned source JSON is a copy.
	gotSrc[0] = 'X'
	if js[bytes.Index(js, []byte(`"source_credentials":`))+len(`"source_credentials":`)] == 'X' {
		t.Error("source JSON shares memory with the input")
	}
}

func TestParseImpersonatedServiceAccountJSONErrors(t *testing.T) {
	user := userJSON(t, nil)
	tests := []struct {
		name string
		js   []byte
		want string
	}{
		{"empty", nil, "not a valid JSON object"},
		{"null", []byte("null"), "not a valid JSON object"},
		{"not_json", []byte("{"), "not a valid JSON object"},
		{"array", []byte(`["secret"]`), "not a valid JSON object"},
		{"nbsp_padded", append([]byte("\u00a0"), impersonatedJSON(t, user, nil)...), "not a valid JSON object"},
		{"delegates_not_list", impersonatedJSON(t, user, map[string]any{"delegates": "d@p.iam.gserviceaccount.com"}), `field "delegates" has the wrong type`},
		{"scopes_not_list", impersonatedJSON(t, user, map[string]any{"scopes": "a b"}), `field "scopes" has the wrong type`},
		{"wrong_type", userJSON(t, nil), `"authorized_user", want impersonated_service_account`},
		{"no_url", impersonatedJSON(t, user, map[string]any{"service_account_impersonation_url": nil}), "target service account"},
		{"url_without_method", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + testTarget,
		}), "target service account"},
		{"url_empty_target", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/:generateAccessToken",
		}), "target service account"},
		{"no_source", impersonatedJSON(t, user, map[string]any{"source_credentials": nil}), `no "source_credentials"`},
		{"url_target_with_query", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a?x=1:generateAccessToken",
		}), "target service account"},
		{"url_blank_target", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/ :generateAccessToken",
		}), "target service account"},
		{"url_encoded_slash_target", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a%2Fb:generateAccessToken",
		}), "target service account"},
		{"url_encoded_query_target", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a%3Fx=1:generateAccessToken",
		}), "target service account"},
		{"url_bad_escape_target", impersonatedJSON(t, user, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/a%zz:generateAccessToken",
		}), "target service account"},
		{"blank_delegate", impersonatedJSON(t, user, map[string]any{"delegates": []string{"d", " "}}), `"delegates" has an empty delegate`},
		{"delegate_with_space", impersonatedJSON(t, user, map[string]any{"delegates": []string{"a b"}}), `"delegates" has a delegate with spaces`},
		{"scope_with_space", impersonatedJSON(t, user, map[string]any{"scopes": []string{"a b"}}), `"scopes" has a scope with spaces`},
		{"source_not_object", impersonatedJSON(t, []byte(`"x"`), nil), "not a JSON object"},
		{"source_type_not_string", impersonatedJSON(t, []byte(`{"type":123}`), nil), `"source_credentials" field "type" must be a string`},
		{"source_universe_not_string", impersonatedJSON(t, []byte(`{"type":"authorized_user","universe_domain":["client-secret"]}`), nil), `"source_credentials" field "universe_domain" must be a string`},
		{"source_no_type", impersonatedJSON(t, []byte(`{"client_id":"x"}`), nil), `has no "type"`},
		{"source_external_account", impersonatedJSON(t, []byte(`{"type":"external_account"}`), nil), `"external_account" are not supported`},
		{"nested_impersonation", impersonatedJSON(t, impersonatedJSON(t, user, nil), nil), `"impersonated_service_account" are not supported`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseImpersonatedServiceAccountJSON(tt.js)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ParseImpersonatedServiceAccountJSON() error = %v, want it to contain %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "client-secret") {
				t.Errorf("error %q contains a secret", err)
			}
		})
	}
}

// iamRedirect sends requests for iamcredentials.googleapis.com to srv, so
// BuildCredentials' default IAM endpoint can be tested.
type iamRedirect struct{ srv *fakeIAM }

func (r iamRedirect) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "iamcredentials.googleapis.com" {
		u, _ := url.Parse(r.srv.URL)
		req = req.Clone(req.Context())
		req.URL.Scheme, req.URL.Host, req.Host = u.Scheme, u.Host, ""
	}
	return r.srv.Client().Transport.RoundTrip(req)
}

func TestBuildCredentialsImpersonatedUserSource(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
	srv.tokenResps = []fakeResponse{{body: `{"access_token":"user-at","expires_in":3600}`}}
	src := userJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	js := impersonatedJSON(t, src, map[string]any{"delegates": []string{"d1"}, "scopes": []string{"json-scope"}})
	creds, err := BuildCredentials(t.Context(), &Config{
		JSON:     js,
		Scopes:   []string{"s1"},
		TokenURL: "https://not-used.example/token", // not applied to the source
		RAPT: func(context.Context) (string, error) { // not applied to the source
			t.Error("Config.RAPT called for an impersonated_service_account source")
			return "rapt-1", nil
		},
		Client: &http.Client{Transport: iamRedirect{srv}},
	})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tok.Value != "imp-token" {
		t.Errorf("Token().Value = %q, want imp-token", tok.Value)
	}
	forms := srv.forms()
	if len(forms) != 1 {
		t.Fatalf("token endpoint got %d requests, want 1", len(forms))
	}
	// The user source keeps its own (empty) scopes and gets no RAPT.
	if forms[0].Has("scope") || forms[0].Has("rapt") || forms[0].Get("grant_type") != "refresh_token" {
		t.Errorf("source refresh form = %v, want a refresh_token grant with no rapt or scope", forms[0])
	}
	reqs := srv.requests()
	if len(reqs) != 1 {
		t.Fatalf("IAM got %d requests, want 1", len(reqs))
	}
	want := iamRequest{
		path:        testIAMPath,
		auth:        "Bearer user-at",
		contentType: "application/json",
		body:        `{"delegates":["d1"],"scope":["s1"],"lifetime":"3600s"}`,
	}
	if reqs[0] != want {
		t.Errorf("IAM request = %+v, want %+v", reqs[0], want)
	}
	if !bytes.Equal(creds.JSON(), js) {
		t.Errorf("JSON() = %s, want the impersonated_service_account JSON", creds.JSON())
	}
	if ud, _ := creds.UniverseDomain(t.Context()); ud != "googleapis.com" {
		t.Errorf("UniverseDomain() = %q, want googleapis.com", ud)
	}
}

func TestBuildCredentialsImpersonatedServiceAccountSource(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
	srv.tokenResps = []fakeResponse{{body: `{"access_token":"sa-at","expires_in":3600}`}}
	src := saJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	creds, err := BuildCredentials(t.Context(), &Config{
		JSON:   impersonatedJSON(t, src, map[string]any{"scopes": []string{"json-scope"}}),
		Client: &http.Client{Transport: iamRedirect{srv}},
	})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	if _, err := creds.Token(t.Context()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	forms := srv.forms()
	if len(forms) != 1 {
		t.Fatalf("token endpoint got %d requests, want 1", len(forms))
	}
	// As in google-auth, a service account source gets the iam scope.
	_, claims := verifyJWT(t, forms[0].Get("assertion"))
	if claims["scope"] != IAMScope {
		t.Errorf("source assertion scope = %v, want %s", claims["scope"], IAMScope)
	}
	reqs := srv.requests()
	if len(reqs) != 1 || reqs[0].auth != "Bearer sa-at" || reqs[0].body != `{"delegates":null,"scope":["json-scope"],"lifetime":"3600s"}` {
		t.Errorf("IAM requests = %+v, want one with the source token and the JSON's scopes", reqs)
	}
}

func TestBuildCredentialsImpersonatedErrors(t *testing.T) {
	client := &http.Client{Transport: &recordingTransport{}}
	user := userJSON(t, nil)
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"no_scopes", &Config{JSON: impersonatedJSON(t, user, nil), Client: client}, `need Config.Scopes or "scopes"`},
		{"bad_source", &Config{JSON: impersonatedJSON(t, []byte(`{"type":"authorized_user"}`), nil), Scopes: []string{"s"}, Client: client}, "source credentials"},
		{"bad_url", &Config{JSON: impersonatedJSON(t, user, map[string]any{"service_account_impersonation_url": "x"}), Scopes: []string{"s"}, Client: client}, "target service account"},
		{"blank_json_delegate", &Config{JSON: impersonatedJSON(t, user, map[string]any{"delegates": []string{" "}}), Scopes: []string{"s"}, Client: client}, `impersonated_service_account "delegates" has an empty delegate`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildCredentials(t.Context(), tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("BuildCredentials() error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestBuildCredentialsImpersonatedUniverseDomain checks the source's
// universe for impersonated_service_account JSON: its own universe_domain,
// else the file's top-level universe_domain, else Config.UniverseDomain,
// else googleapis.com (the same JSON-then-Config order as the other types).
func TestBuildCredentialsImpersonatedUniverseDomain(t *testing.T) {
	tests := []struct {
		name, sourceUniverse, fileUniverse, cfgUniverse, want string
	}{
		{name: "none", want: "googleapis.com"},
		{name: "config_fallback", cfgUniverse: "other.example", want: "other.example"},
		{name: "file_fallback", fileUniverse: "file.example", want: "file.example"},
		{name: "file_wins_over_config", fileUniverse: "file.example", cfgUniverse: "other.example", want: "file.example"},
		{name: "source_universe", sourceUniverse: "example.com", want: "example.com"},
		{name: "source_wins_over_file_and_config", sourceUniverse: "example.com", fileUniverse: "file.example", cfgUniverse: "other.example", want: "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var extra map[string]any
			if tt.sourceUniverse != "" {
				extra = map[string]any{"universe_domain": tt.sourceUniverse}
			}
			outer := map[string]any{"scopes": []string{"s"}}
			if tt.fileUniverse != "" {
				outer["universe_domain"] = tt.fileUniverse
			}
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:           impersonatedJSON(t, userJSON(t, extra), outer),
				UniverseDomain: tt.cfgUniverse,
				Client:         noNetworkClient(t),
			})
			if err != nil {
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			if ud, _ := creds.UniverseDomain(t.Context()); ud != tt.want {
				t.Errorf("UniverseDomain() = %q, want %q", ud, tt.want)
			}
		})
	}
}

// TestBuildCredentialsImpersonatedIAMHost checks that IAM is called in the
// source's universe, including one that came from Config.UniverseDomain.
func TestBuildCredentialsImpersonatedIAMHost(t *testing.T) {
	for _, tt := range []struct{ name, sourceUniverse, cfgUniverse, wantHost string }{
		{"default", "", "", "iamcredentials.googleapis.com"},
		{"config_fallback", "", "other.example", "iamcredentials.other.example"},
		{"source_universe", "example.com", "other.example", "iamcredentials.example.com"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			extra := map[string]any{"token_uri": "https://oauth2.example/token"}
			if tt.sourceUniverse != "" {
				extra["universe_domain"] = tt.sourceUniverse
			}
			rt := &hostRecorder{tokenBody: `{"access_token":"user-at","expires_in":3600}`}
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:           impersonatedJSON(t, userJSON(t, extra), map[string]any{"scopes": []string{"s"}}),
				UniverseDomain: tt.cfgUniverse,
				Client:         &http.Client{Transport: rt},
			})
			if err != nil {
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			creds.Token(t.Context()) // fails at IAM on purpose; only the hosts matter
			if len(rt.hosts) != 2 || rt.hosts[1] != tt.wantHost {
				t.Errorf("requests went to %v, want the source refresh and then %s", rt.hosts, tt.wantHost)
			}
		})
	}
}

// hostRecorder answers token requests with tokenBody and fails every other
// request, recording each request's host.
type hostRecorder struct {
	mu        sync.Mutex
	hosts     []string
	tokenBody string
}

func (h *hostRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, req.URL.Host)
	h.mu.Unlock()
	if req.Body != nil {
		req.Body.Close()
	}
	if strings.HasSuffix(req.URL.Path, "/token") {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(h.tokenBody)), Request: req}, nil
	}
	return nil, errors.New("hostRecorder: no IAM server")
}

// TestBuildCredentialsImpersonatedSourceIgnoresSelfSignedOptions checks that
// neither Config.UseSelfSignedJWT nor a non-default Config.UniverseDomain
// makes a googleapis.com service account source self-sign: as in Python
// gcloud, the source still exchanges a JWT assertion at its token endpoint.
func TestBuildCredentialsImpersonatedSourceIgnoresSelfSignedOptions(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  func(*Config)
	}{
		{"use_self_signed_jwt", func(c *Config) { c.UseSelfSignedJWT = true }},
		{"non_default_config_universe", func(c *Config) { c.UniverseDomain = "other.example" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
			srv.tokenResps = []fakeResponse{{body: `{"access_token":"sa-at","expires_in":3600}`}}
			src := saJSON(t, map[string]any{"token_uri": srv.URL + "/token", "universe_domain": "googleapis.com"})
			cfg := &Config{
				JSON:   impersonatedJSON(t, src, map[string]any{"scopes": []string{"s"}}),
				Client: &http.Client{Transport: iamRedirect{srv}},
			}
			tt.cfg(cfg)
			creds, err := BuildCredentials(t.Context(), cfg)
			if err != nil {
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			if _, err := creds.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			if forms := srv.forms(); len(forms) != 1 || forms[0].Get("assertion") == "" {
				t.Errorf("token endpoint forms = %v, want one JWT assertion exchange", forms)
			}
			if reqs := srv.requests(); len(reqs) != 1 || reqs[0].auth != "Bearer sa-at" {
				t.Errorf("IAM requests = %+v, want one with the exchanged source token", reqs)
			}
		})
	}
}

// TestBuildCredentialsImpersonatedNonDefaultUniverseSource covers a service
// account source in another universe: it self-signs a JWT (no token
// endpoint call) and IAM is called in that universe.
func TestBuildCredentialsImpersonatedNonDefaultUniverseSource(t *testing.T) {
	rt := &hostRecorder{}
	src := saJSON(t, map[string]any{"universe_domain": "example.com"})
	creds, err := BuildCredentials(t.Context(), &Config{
		JSON:   impersonatedJSON(t, src, map[string]any{"scopes": []string{"s"}}),
		Client: &http.Client{Transport: rt},
	})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	if ud, _ := creds.UniverseDomain(t.Context()); ud != "example.com" {
		t.Errorf("UniverseDomain() = %q, want example.com", ud)
	}
	creds.Token(t.Context()) // fails at IAM on purpose; only the hosts matter
	if len(rt.hosts) != 1 || rt.hosts[0] != "iamcredentials.example.com" {
		t.Errorf("requests went to %v, want only iamcredentials.example.com", rt.hosts)
	}
}

// typedSource returns a fixed token with the given type.
type typedSource struct{ typ string }

func (s typedSource) Token(context.Context) (*auth.Token, error) {
	return &auth.Token{Value: "src-token", Type: s.typ}, nil
}

// TestImpersonateSourceTokenType checks that the source token's type is sent
// as given, and that an empty type is sent as Bearer.
func TestImpersonateSourceTokenType(t *testing.T) {
	tests := []struct{ name, typ, want string }{
		{name: "empty_is_bearer", typ: "", want: "Bearer src-token"},
		{name: "custom_type", typ: "MAC", want: "MAC src-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
			source := auth.NewCredentials(&auth.CredentialsOptions{TokenProvider: typedSource{tt.typ}})
			creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
			if err != nil {
				t.Fatalf("Impersonate() error = %v", err)
			}
			if _, err := creds.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			if reqs := srv.requests(); len(reqs) != 1 || reqs[0].auth != tt.want {
				t.Errorf("IAM requests = %+v, want one with Authorization %q", reqs, tt.want)
			}
		})
	}
}

// TestImpersonateFractionalExpireTime checks that IAM's expireTime with
// fractional seconds is accepted.
func TestImpersonateFractionalExpireTime(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: `{"accessToken":"imp-token","expireTime":"2030-01-02T03:04:05.123456789Z"}`})
	source, _ := newSource("")
	creds, err := Impersonate(t.Context(), testImpersonationConfig(srv, source))
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if want := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.UTC); !tok.Expiry.Equal(want) {
		t.Errorf("Token().Expiry = %v, want %v", tok.Expiry, want)
	}
}

type emptyTokenProvider struct{}

func (emptyTokenProvider) Token(context.Context) (*auth.Token, error) { return &auth.Token{}, nil }

// TestBuildCredentialsImpersonatedLogsNoSecrets mirrors
// TestBuildCredentialsLogsNoSecrets for impersonated_service_account JSON:
// neither Config.Logger nor stderr (go/auth's debug logging) may contain the
// source or impersonated tokens, the assertion or the private key.
func TestBuildCredentialsImpersonatedLogsNoSecrets(t *testing.T) {
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	_, keyPEM := testServiceAccountKey(t)
	keyLine := strings.Split(keyPEM, "\n")[1]
	const impBody = `{"accessToken":"secret-imp-at","expireTime":"` + testExpireTime + `"}`
	tests := []struct {
		name      string
		source    func(srv *fakeIAM) []byte
		tokenBody string
	}{
		{
			name: "authorized_user_source",
			source: func(srv *fakeIAM) []byte {
				return userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "refresh_token": "secret-rt"})
			},
			tokenBody: `{"access_token":"secret-src-at","expires_in":3600,"refresh_token":"secret-rt-2"}`,
		},
		{
			name:      "service_account_source",
			source:    func(srv *fakeIAM) []byte { return saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}) },
			tokenBody: `{"access_token":"secret-src-at","expires_in":3600}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, debugLogger := range []bool{false, true} {
				t.Run(fmt.Sprintf("debug_logger_%v", debugLogger), func(t *testing.T) {
					srv := newFakeIAM(t, fakeResponse{body: impBody})
					srv.tokenResps = []fakeResponse{{body: tc.tokenBody}}
					var logs bytes.Buffer
					cfg := &Config{
						JSON:   impersonatedJSON(t, tc.source(srv), map[string]any{"scopes": []string{"s1"}}),
						Client: &http.Client{Transport: iamRedirect{srv}},
					}
					if debugLogger {
						cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
					}
					stderr := captureStderr(t)
					creds, err := BuildCredentials(t.Context(), cfg)
					if err != nil {
						t.Fatalf("BuildCredentials(%s) error = %v", tc.name, err)
					}
					tok, err := creds.Token(t.Context())
					if err != nil {
						t.Fatalf("BuildCredentials(%s).Token() error = %v", tc.name, err)
					}
					outputs := map[string]string{"stderr": stderr(), "Config.Logger": logs.String()}
					if debugLogger && !strings.Contains(outputs["Config.Logger"], "type=impersonated_service_account") {
						t.Errorf("BuildCredentials(%s): Config.Logger output = %q, want the credential type", tc.name, outputs["Config.Logger"])
					}
					secrets := []string{tok.Value, "secret-imp-at", "secret-src-at", "secret-rt", "secret-rt-2",
						"eyJ", "assertion", "client-secret", "PRIVATE KEY", keyLine}
					for where, out := range outputs {
						for _, secret := range secrets {
							if strings.Contains(out, secret) {
								t.Errorf("BuildCredentials(%s): %s contains %q: %s", tc.name, where, secret, out)
							}
						}
					}
				})
			}
		})
	}
}

// TestParseImpersonatedServiceAccountJSONDetails checks the source type, the
// percent-decoded target and the top-level universe_domain.
func TestParseImpersonatedServiceAccountJSONDetails(t *testing.T) {
	sa := saJSON(t, nil)
	got, err := ParseImpersonatedServiceAccountJSON(impersonatedJSON(t, sa, map[string]any{
		"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target%40project.iam.gserviceaccount.com:generateAccessToken",
		"universe_domain":                   " example.com ",
	}))
	if err != nil {
		t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
	}
	if got.SourceType != "service_account" || got.Target != testTarget || got.UniverseDomain != "example.com" {
		t.Errorf("ParseImpersonatedServiceAccountJSON() = %v, want source type service_account, target %s, universe example.com", got, testTarget)
	}
	for name, out := range map[string]string{"%v": fmt.Sprintf("%v", got), "%#v": fmt.Sprintf("%#v", got)} {
		if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, "private_key") {
			t.Errorf("%s output %q contains the source JSON", name, out)
		}
	}
}

// TestBuildCredentialsImpersonatedEncodedTarget checks that a percent-encoded
// target in service_account_impersonation_url is not double-escaped: "%40"
// is decoded, and url.PathEscape sends a literal "@" (not "%2540").
func TestBuildCredentialsImpersonatedEncodedTarget(t *testing.T) {
	srv := newFakeIAM(t, fakeResponse{body: okIAMBody})
	srv.tokenResps = []fakeResponse{{body: `{"access_token":"user-at","expires_in":3600}`}}
	src := userJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	creds, err := BuildCredentials(t.Context(), &Config{
		JSON: impersonatedJSON(t, src, map[string]any{
			"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target%40project.iam.gserviceaccount.com:generateAccessToken",
			"scopes":                            []string{"s"},
		}),
		Client: &http.Client{Transport: iamRedirect{srv}},
	})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	if _, err := creds.Token(t.Context()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if reqs := srv.requests(); len(reqs) != 1 || reqs[0].path != testIAMPath {
		t.Errorf("IAM requests = %+v, want one to %s", reqs, testIAMPath)
	}
}

// TestBuildCredentialsImpersonatedServiceAccountSourceFallbackSelfSigns
// checks a service_account source without universe_domain whose universe
// comes from the file's top-level universe_domain or Config.UniverseDomain:
// outside googleapis.com it self-signs (no token endpoint call) and IAM is
// called in that universe.
func TestBuildCredentialsImpersonatedServiceAccountSourceFallbackSelfSigns(t *testing.T) {
	for _, tt := range []struct{ name, fileUniverse, cfgUniverse, wantHost string }{
		{name: "file_universe", fileUniverse: "file.example", wantHost: "iamcredentials.file.example"},
		{name: "config_universe", cfgUniverse: "other.example", wantHost: "iamcredentials.other.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			outer := map[string]any{"scopes": []string{"s"}}
			if tt.fileUniverse != "" {
				outer["universe_domain"] = tt.fileUniverse
			}
			rt := &hostRecorder{}
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:           impersonatedJSON(t, saJSON(t, map[string]any{"token_uri": "https://oauth2.example/token"}), outer),
				UniverseDomain: tt.cfgUniverse,
				Client:         &http.Client{Transport: rt},
			})
			if err != nil {
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			creds.Token(t.Context()) // fails at IAM on purpose; only the hosts matter
			if len(rt.hosts) != 1 || rt.hosts[0] != tt.wantHost {
				t.Errorf("requests went to %v, want only %s (a self-signed source makes no token request)", rt.hosts, tt.wantHost)
			}
		})
	}
}

// TestImpersonatedServiceAccountSourceConfig checks the source Config that
// BuildCredentials uses for impersonated_service_account JSON.
func TestImpersonatedServiceAccountSourceConfig(t *testing.T) {
	client := noNetworkClient(t)
	logger := slog.New(slog.DiscardHandler)
	cfg := &Config{
		UniverseDomain:   "other.example",
		Client:           client,
		Logger:           logger,
		TokenURL:         "https://not-used.example/token",
		RAPT:             func(context.Context) (string, error) { return "r", nil },
		UseSelfSignedJWT: true,
		Scopes:           []string{"target-scope"},
	}
	tests := []struct {
		name         string
		source       []byte
		outer        map[string]any
		wantUniverse string
		wantScopes   []string
	}{
		{name: "sa_own_universe", source: saJSON(t, map[string]any{"universe_domain": "googleapis.com"}), outer: map[string]any{"universe_domain": "file.example"}, wantScopes: []string{IAMScope}},
		{name: "sa_file_universe", source: saJSON(t, nil), outer: map[string]any{"universe_domain": "file.example"}, wantUniverse: "file.example", wantScopes: []string{IAMScope}},
		{name: "user_config_universe", source: userJSON(t, nil), wantUniverse: "other.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := ParseImpersonatedServiceAccountJSON(impersonatedJSON(t, tt.source, tt.outer))
			if err != nil {
				t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
			}
			got := a.SourceConfig(cfg)
			if !bytes.Equal(got.JSON, tt.source) || got.Client != client || got.Logger != logger ||
				got.UniverseDomain != tt.wantUniverse || !reflect.DeepEqual(got.Scopes, tt.wantScopes) ||
				got.TokenURL != "" || got.RAPT != nil || got.UseSelfSignedJWT {
				t.Errorf("SourceConfig() = %v (Scopes %q, RAPT set %t, UseSelfSignedJWT %t), want the source JSON, cfg's Client and Logger, UniverseDomain %q, Scopes %q and nothing else",
					got, got.Scopes, got.RAPT != nil, got.UseSelfSignedJWT, tt.wantUniverse, tt.wantScopes)
			}
		})
	}
	if got := (&ImpersonatedServiceAccount{SourceJSON: []byte("{}")}).SourceConfig(nil); got == nil || got.Client != nil || string(got.JSON) != "{}" {
		t.Errorf("SourceConfig(nil) = %v, want a Config with only JSON set", got)
	}
}

// TestImpersonatedServiceAccountSplitPathMatchesBuildCredentials builds a
// googleapis.com service account source in a file with another top-level
// universe both ways (BuildCredentials, and the documented
// ParseImpersonatedServiceAccountJSON + SourceConfig + Impersonate path) and
// checks both send the same requests: a JWT exchange at the token endpoint,
// then IAM in googleapis.com.
func TestImpersonatedServiceAccountSplitPathMatchesBuildCredentials(t *testing.T) {
	js := impersonatedJSON(t,
		saJSON(t, map[string]any{"token_uri": "https://oauth2.example/token", "universe_domain": "googleapis.com"}),
		map[string]any{"scopes": []string{"s"}, "universe_domain": "other.example"})
	want := []string{"oauth2.example", "iamcredentials.googleapis.com"}

	rt := &hostRecorder{tokenBody: `{"access_token":"sa-at","expires_in":3600}`}
	creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	creds.Token(t.Context()) // fails at IAM on purpose; only the hosts matter
	if !reflect.DeepEqual(rt.hosts, want) {
		t.Errorf("BuildCredentials: requests went to %v, want %v", rt.hosts, want)
	}

	rt2 := &hostRecorder{tokenBody: `{"access_token":"sa-at","expires_in":3600}`}
	client := &http.Client{Transport: rt2}
	a, err := ParseImpersonatedServiceAccountJSON(js)
	if err != nil {
		t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
	}
	source, err := BuildCredentials(t.Context(), a.SourceConfig(&Config{Client: client}))
	if err != nil {
		t.Fatalf("BuildCredentials(SourceConfig()) error = %v", err)
	}
	imp, err := Impersonate(t.Context(), &ImpersonationConfig{Source: source, Target: a.Target, Delegates: a.Delegates, Scopes: a.Scopes, Client: client})
	if err != nil {
		t.Fatalf("Impersonate() error = %v", err)
	}
	imp.Token(t.Context()) // fails at IAM on purpose; only the hosts matter
	if !reflect.DeepEqual(rt2.hosts, want) {
		t.Errorf("split path: requests went to %v, want %v", rt2.hosts, want)
	}
}
