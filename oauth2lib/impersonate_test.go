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

	mu          sync.Mutex
	iamReqs     []iamRequest
	iamResps    []fakeResponse
	tokenForms  []url.Values
	tokenResps  []fakeResponse
	blockIAMReq bool
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
		name, universe, cfgUniverse, endpoint, want string
	}{
		{"default", "", "", "", "https://iamcredentials.googleapis.com" + testIAMPath},
		{"source_universe", "example.com", "", "", "https://iamcredentials.example.com" + testIAMPath},
		{"matching_config_universe", "example.com", " example.com ", "", "https://iamcredentials.example.com" + testIAMPath},
		// As in Python gcloud: a non-default configured universe picks the
		// IAM host (GetEffectiveIamEndpoint), without an error, while the
		// credentials still report Source's universe (google-auth).
		{"config_universe_picks_host", "example.com", "other.example", "", "https://iamcredentials.other.example" + testIAMPath},
		{"config_universe_over_default_source", "", "other.example", "", "https://iamcredentials.other.example" + testIAMPath},
		{"default_config_universe_uses_source", "example.com", "googleapis.com", "", "https://iamcredentials.example.com" + testIAMPath},
		{"override_wins_over_config_universe", "example.com", "other.example", "https://override.example/", "https://override.example" + testIAMPath},
		{"override", "", "", "https://iamcredentials.mtls.googleapis.com/", "https://iamcredentials.mtls.googleapis.com" + testIAMPath},
		{"override_without_slash", "", "", "https://regional.example", "https://regional.example" + testIAMPath},
		{"override_with_path", "", "", "https://proxy.example/iam", "https://proxy.example/iam" + testIAMPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			source, _ := newSource(tt.universe)
			creds, err := Impersonate(t.Context(), &ImpersonationConfig{
				Source:         source,
				Target:         testTarget,
				Scopes:         []string{"s"},
				Endpoint:       tt.endpoint,
				UniverseDomain: tt.cfgUniverse,
				Client:         &http.Client{Transport: rt},
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
			wantUD := tt.universe
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
			c.UniverseDomain = ""
			return c
		}, "IAM endpoint"},
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
	gotSrc, base, err := ParseImpersonatedServiceAccountJSON(js)
	if err != nil {
		t.Fatalf("ParseImpersonatedServiceAccountJSON() error = %v", err)
	}
	var gotM, wantM map[string]any
	json.Unmarshal(gotSrc, &gotM)
	json.Unmarshal(src, &wantM)
	if fmt.Sprint(gotM) != fmt.Sprint(wantM) {
		t.Errorf("source JSON = %s, want %s", gotSrc, src)
	}
	if base.Target != testTarget || fmt.Sprint(base.Delegates) != "[d1 d2]" || fmt.Sprint(base.Scopes) != "[a b]" ||
		base.Endpoint != "" || base.Source != nil || base.Client != nil {
		t.Errorf("base = %v, want target %s, delegates [d1 d2], scopes [a b] and nothing else", base, testTarget)
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
		{"source_not_object", impersonatedJSON(t, []byte(`"x"`), nil), "not a JSON object"},
		{"source_no_type", impersonatedJSON(t, []byte(`{"client_id":"x"}`), nil), `has no "type"`},
		{"source_external_account", impersonatedJSON(t, []byte(`{"type":"external_account"}`), nil), `"external_account" are not supported`},
		{"nested_impersonation", impersonatedJSON(t, impersonatedJSON(t, user, nil), nil), `"impersonated_service_account" are not supported`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseImpersonatedServiceAccountJSON(tt.js)
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
		RAPT:     func(context.Context) (string, error) { return "rapt-1", nil },
		Client:   &http.Client{Transport: iamRedirect{srv}},
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
	// The user source keeps its own (empty) scopes, and gets the RAPT.
	if forms[0].Has("scope") || forms[0].Get("rapt") != "rapt-1" || forms[0].Get("grant_type") != "refresh_token" {
		t.Errorf("source refresh form = %v, want a refresh_token grant with rapt and no scope", forms[0])
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
	if claims["scope"] != iamScope {
		t.Errorf("source assertion scope = %v, want %s", claims["scope"], iamScope)
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
