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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// userJSON returns authorized_user JSON with the given extra fields.
func userJSON(t *testing.T, extra map[string]any) []byte {
	t.Helper()
	m := map[string]any{
		"type":          "authorized_user",
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"refresh_token": "refresh-1",
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

// newTestUserProvider builds a provider that talks to srv's /token.
func newTestUserProvider(t *testing.T, srv *fakeServer, cfg Config) *userTokenProvider {
	t.Helper()
	if cfg.JSON == nil {
		cfg.JSON = userJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	}
	if cfg.Client == nil {
		cfg.Client = srv.Client()
	}
	p, err := newUserTokenProvider(&cfg)
	if err != nil {
		t.Fatalf("newUserTokenProvider() error = %v", err)
	}
	return p
}

func (f *fakeServer) recordedForms() []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]url.Values(nil), f.forms...)
}

const okTokenBody = `{"access_token":"at-1","token_type":"Bearer","expires_in":3600}`

func TestUserTokenRequest(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: okTokenBody})
	p := newTestUserProvider(t, srv, Config{})

	tok, err := p.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tok.Value != "at-1" || tok.Type != "Bearer" {
		t.Errorf("Token() = %+v, want value at-1, type Bearer", tok)
	}
	if d := time.Until(tok.Expiry); d < 3590*time.Second || d > 3600*time.Second {
		t.Errorf("Token().Expiry is %v from now, want about 1h", d)
	}
	want := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"client-id"},
		"client_secret": {"client-secret"},
		"refresh_token": {"refresh-1"},
	}
	forms := srv.recordedForms()
	if len(forms) != 1 || forms[0].Encode() != want.Encode() {
		t.Errorf("server got forms %v, want [%v]", forms, want)
	}
	if len(tok.Metadata) != 0 {
		t.Errorf("Token().Metadata = %v, want empty", tok.Metadata)
	}
}

func TestUserTokenScopes(t *testing.T) {
	tests := []struct {
		name       string
		jsonScopes any
		cfgScopes  []string
		want       string // "" means no scope parameter
	}{
		{"none", nil, nil, ""},
		{"json_list", []string{"a", "b"}, nil, "a b"},
		{"json_string", "a  b", nil, "a b"},
		{"config_overrides_json", []string{"a"}, []string{"x", "y"}, "x y"},
		{"json_list_drops_empty_items", []string{"a", "", " b "}, nil, "a b"},
		{"empty_config_uses_json", []string{"a"}, []string{}, "a"},
		{"config_trimmed", nil, []string{" a ", "", "b"}, "a b"},
		{"blank_config_uses_json", []string{"a"}, []string{"", " "}, "a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, fakeResponse{body: okTokenBody})
			cfg := Config{
				JSON:   userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "scopes": tc.jsonScopes}),
				Scopes: tc.cfgScopes,
			}
			p := newTestUserProvider(t, srv, cfg)
			if _, err := p.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			form := srv.recordedForms()[0]
			if _, ok := form["scope"]; ok != (tc.want != "") || form.Get("scope") != tc.want {
				t.Errorf("server got scope %q (present %v), want %q", form.Get("scope"), ok, tc.want)
			}
		})
	}
}

func TestUserTokenRAPT(t *testing.T) {
	t.Run("nil_callback", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: okTokenBody})
		p := newTestUserProvider(t, srv, Config{})
		tok, err := p.Token(t.Context())
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if _, ok := srv.recordedForms()[0]["rapt"]; ok {
			t.Error("server got a rapt parameter, want none")
		}
		if _, ok := tok.Metadata[MetadataRAPT]; ok {
			t.Errorf("Token().Metadata = %v, want no %s", tok.Metadata, MetadataRAPT)
		}
	})

	t.Run("empty_omits_rapt", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: okTokenBody})
		p := newTestUserProvider(t, srv, Config{RAPT: func(context.Context) (string, error) { return "", nil }})
		if _, err := p.Token(t.Context()); err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if _, ok := srv.recordedForms()[0]["rapt"]; ok {
			t.Error("server got a rapt parameter, want none")
		}
	})

	t.Run("read_before_each_refresh", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: okTokenBody}, fakeResponse{body: okTokenBody})
		var calls int
		p := newTestUserProvider(t, srv, Config{RAPT: func(context.Context) (string, error) {
			calls++
			return fmt.Sprintf("rapt-%d", calls), nil
		}})
		for i := 1; i <= 2; i++ {
			tok, err := p.Token(t.Context())
			if err != nil {
				t.Fatalf("Token() #%d error = %v", i, err)
			}
			want := fmt.Sprintf("rapt-%d", i)
			if got := srv.recordedForms()[i-1].Get("rapt"); got != want {
				t.Errorf("Token() #%d sent rapt %q, want %q", i, got, want)
			}
			if got := tok.MetadataString(MetadataRAPT); got != want {
				t.Errorf("Token() #%d metadata %s = %q, want %q", i, MetadataRAPT, got, want)
			}
		}
	})

	t.Run("error_stops_before_request", func(t *testing.T) {
		srv := newFakeServer(t) // no responses: any request fails the test
		raptErr := errors.New("database locked")
		p := newTestUserProvider(t, srv, Config{RAPT: func(context.Context) (string, error) { return "", raptErr }})
		_, err := p.Token(t.Context())
		if !errors.Is(err, raptErr) {
			t.Fatalf("Token() error = %v, want it to wrap %v", err, raptErr)
		}
		var re *RefreshError
		if errors.As(err, &re) {
			t.Errorf("Token() error = %v, want the RAPT error, not a RefreshError", err)
		}
		if n := len(srv.recordedForms()); n != 0 {
			t.Errorf("server got %d requests, want 0", n)
		}
	})
}

func TestUserTokenURL(t *testing.T) {
	tests := []struct {
		name     string
		cfgURL   string
		tokenURI any
		want     string
	}{
		{"config_overrides_json", "https://mtls.example/token", "https://json.example/token", "https://mtls.example/token"},
		{"json_token_uri", "", "https://json.example/token", "https://json.example/token"},
		{"default", "", nil, "https://oauth2.googleapis.com/token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				JSON:     userJSON(t, map[string]any{"token_uri": tc.tokenURI}),
				TokenURL: tc.cfgURL,
				Client:   newFakeServer(t).Client(),
			}
			p, err := newUserTokenProvider(cfg)
			if err != nil {
				t.Fatalf("newUserTokenProvider() error = %v", err)
			}
			if p.tokenURL != tc.want {
				t.Errorf("tokenURL = %q, want %q", p.tokenURL, tc.want)
			}
		})
	}

	t.Run("override_is_used", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: okTokenBody})
		p := newTestUserProvider(t, srv, Config{
			JSON:     userJSON(t, map[string]any{"token_uri": "https://unused.invalid/token"}),
			TokenURL: srv.URL + "/token",
		})
		if _, err := p.Token(t.Context()); err != nil {
			t.Fatalf("Token() error = %v", err)
		}
	})
}

func TestUserTokenMetadataAndRotation(t *testing.T) {
	srv := newFakeServer(t,
		fakeResponse{body: `{"access_token":"at-1","expires_in":3600,"id_token":"idt-1","refresh_token":"refresh-2"}`},
		fakeResponse{body: `{"access_token":"at-2","expires_in":"3599"}`},
	)
	p := newTestUserProvider(t, srv, Config{})

	tok, err := p.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() #1 error = %v", err)
	}
	if got := tok.MetadataString(MetadataIDToken); got != "idt-1" {
		t.Errorf("Token() #1 metadata %s = %q, want idt-1", MetadataIDToken, got)
	}
	if got := tok.MetadataString(MetadataRefreshToken); got != "refresh-2" {
		t.Errorf("Token() #1 metadata %s = %q, want refresh-2", MetadataRefreshToken, got)
	}

	tok, err = p.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() #2 error = %v", err)
	}
	if got := srv.recordedForms()[1].Get("refresh_token"); got != "refresh-2" {
		t.Errorf("Token() #2 sent refresh_token %q, want the rotated refresh-2", got)
	}
	if _, ok := tok.Metadata[MetadataRefreshToken]; ok {
		t.Errorf("Token() #2 metadata = %v, want no %s when none was returned", tok.Metadata, MetadataRefreshToken)
	}
	if tok.Type != "Bearer" {
		t.Errorf("Token() #2 type = %q, want the Bearer default", tok.Type)
	}
	if d := time.Until(tok.Expiry); d < 3590*time.Second || d > 3599*time.Second {
		t.Errorf("Token() #2 expiry is %v from now, want about 3599s (expires_in as a string)", d)
	}
}

func TestUserTokenEchoedRefreshTokenNotReported(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"at-1","refresh_token":"refresh-1"}`})
	tok, err := newTestUserProvider(t, srv, Config{}).Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if _, ok := tok.Metadata[MetadataRefreshToken]; ok {
		t.Errorf("Token().Metadata = %v, want no %s when the sent refresh token is echoed", tok.Metadata, MetadataRefreshToken)
	}
}

func TestUserTokenNoExpiresIn(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"at-1"}`})
	tok, err := newTestUserProvider(t, srv, Config{}).Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if !tok.Expiry.IsZero() {
		t.Errorf("Token().Expiry = %v, want zero when expires_in is missing", tok.Expiry)
	}
}

func TestUserTokenScopeGrant(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"all_granted", `{"access_token":"at","scope":"b a openid"}`, false},
		{"no_scope_in_response", `{"access_token":"at"}`, false},
		{"missing_scope", `{"access_token":"at","scope":"a"}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, fakeResponse{body: tc.body})
			p := newTestUserProvider(t, srv, Config{
				JSON:   userJSON(t, map[string]any{"token_uri": srv.URL + "/token"}),
				Scopes: []string{"a", "b"},
			})
			_, err := p.Token(t.Context())
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("Token() error = %v, want nil", err)
				}
				return
			}
			var re *RefreshError
			if !errors.As(err, &re) || re.Kind != KindInvalidGrant || re.StatusCode != 200 {
				t.Fatalf("Token() error = %v, want a KindInvalidGrant RefreshError with StatusCode 200", err)
			}
			if want := "missing scopes b."; !strings.Contains(re.Description, want) {
				t.Errorf("Token() error description = %q, want it to contain %q", re.Description, want)
			}
		})
	}
}

func TestUserTokenBadResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"no_access_token", `{"token_type":"Bearer"}`, "no access_token"},
		{"not_json", `<html>ok</html>`, "not valid JSON"},
		{"bad_expires_in", `{"access_token":"at","expires_in":"soon"}`, "invalid expires_in"},
		{"negative_expires_in", `{"access_token":"at","expires_in":-1}`, "invalid expires_in"},
		{"overflowing_expires_in", `{"access_token":"at","expires_in":9223372037}`, "invalid expires_in"},
		{"overflowing_expires_in_string", `{"access_token":"at","expires_in":"9223372037"}`, "invalid expires_in"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, fakeResponse{body: tc.body})
			_, err := newTestUserProvider(t, srv, Config{}).Token(t.Context())
			var re *RefreshError
			if !errors.As(err, &re) || re.Kind != KindUnknown || !strings.Contains(re.Description, tc.want) {
				t.Fatalf("Token() error = %v, want a KindUnknown RefreshError mentioning %q", err, tc.want)
			}
			if re.StatusCode != 200 {
				t.Errorf("Token() error StatusCode = %d, want 200", re.StatusCode)
			}
		})
	}
}

func TestUserTokenErrorsPassThrough(t *testing.T) {
	t.Run("reauth", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{status: 400, body: `{"error":"invalid_grant","error_subtype":"rapt_required"}`})
		_, err := newTestUserProvider(t, srv, Config{}).Token(t.Context())
		if !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("Token() error = %v, want ErrReauthRequired", err)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{delay: 5 * time.Second, body: okTokenBody})
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := newTestUserProvider(t, srv, Config{}).Token(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Token() error = %v, want context.Canceled", err)
		}
	})
}

func TestNewUserTokenProviderErrors(t *testing.T) {
	client := newFakeServer(t).Client()
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"nil_client", Config{JSON: userJSON(t, nil)}, "Client is nil"},
		{"bad_json", Config{JSON: []byte(`{`), Client: client}, "parsing authorized_user JSON"},
		{"wrong_type", Config{JSON: userJSON(t, map[string]any{"type": "service_account"}), Client: client}, `"service_account", want authorized_user`},
		{"missing_fields", Config{JSON: userJSON(t, map[string]any{"client_secret": nil, "refresh_token": ""}), Client: client}, "missing client_secret, refresh_token"},
		{"bad_scopes", Config{JSON: userJSON(t, map[string]any{"scopes": 7}), Client: client}, `"scopes" must be`},
		{"relative_token_url", Config{JSON: userJSON(t, nil), TokenURL: "/token", Client: client}, "token URL must be"},
		{"unparsable_token_uri", Config{JSON: userJSON(t, map[string]any{"token_uri": "https://a b\x7f/"}), Client: client}, "token URL must be"},
		{"token_uri_without_host", Config{JSON: userJSON(t, map[string]any{"token_uri": "https:///token"}), Client: client}, "token URL must be"},
		{"non_http_token_url", Config{JSON: userJSON(t, nil), TokenURL: "file://host/token", Client: client}, "token URL must be"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			_, err := newUserTokenProvider(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newUserTokenProvider() error = %v, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "client-secret") || strings.Contains(err.Error(), "refresh-1") {
				t.Errorf("newUserTokenProvider() error = %v, contains a secret", err)
			}
		})
	}
}

func TestUserTokenConcurrent(t *testing.T) {
	const n = 8
	responses := make([]fakeResponse, n)
	for i := range responses {
		responses[i] = fakeResponse{body: fmt.Sprintf(`{"access_token":"at-%d","refresh_token":"refresh-%d"}`, i, i+2)}
	}
	srv := newFakeServer(t, responses...)
	p := newTestUserProvider(t, srv, Config{RAPT: func(context.Context) (string, error) { return "rapt", nil }})

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Token(t.Context()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Token() error = %v", err)
	}
	if got := len(srv.recordedForms()); got != n {
		t.Errorf("server got %d requests, want %d (one per Token call)", got, n)
	}
}
