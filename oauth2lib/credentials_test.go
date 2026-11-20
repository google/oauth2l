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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestConfigFormattingHidesJSON(t *testing.T) {
	cfg := Config{
		JSON:     userJSON(t, map[string]any{"refresh_token": "secret-refresh"}),
		Scopes:   []string{"a"},
		TokenURL: "https://oauth2.googleapis.com/token",
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("cfg", "config", cfg, "ptr", &cfg)

	for name, got := range map[string]string{
		"%v":      fmt.Sprintf("%v", cfg),
		"%+v":     fmt.Sprintf("%+v", cfg),
		"%#v":     fmt.Sprintf("%#v", cfg),
		"%v_ptr":  fmt.Sprintf("%v", &cfg),
		"%#v_ptr": fmt.Sprintf("%#v", &cfg),
		"slog":    logs.String(),
	} {
		if strings.Contains(got, "secret-refresh") || strings.Contains(got, "client-secret") {
			t.Errorf("%s output %q contains a secret from Config.JSON", name, got)
		}
		if !strings.Contains(got, "oauth2.googleapis.com") {
			t.Errorf("%s output %q is missing TokenURL", name, got)
		}
	}
}

func TestBuildCredentialsAuthorizedUser(t *testing.T) {
	srv := newFakeServer(t,
		fakeResponse{body: `{"access_token":"at-1","expires_in":3600}`},
		fakeResponse{body: `{"access_token":"at-2","expires_in":3600}`})
	js := userJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	// The credentials are uncached: each Token call sends a new request.
	for _, want := range []string{"at-1", "at-2"} {
		tok, err := creds.Token(t.Context())
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if tok.Value != want {
			t.Errorf("Token().Value = %q, want %q", tok.Value, want)
		}
	}
	forms := srv.recordedForms()
	if len(forms) != 2 {
		t.Fatalf("server got %d requests, want 2", len(forms))
	}
	for _, f := range forms {
		if f.Get("scope") != "s1" || f.Get("grant_type") != "refresh_token" {
			t.Errorf("server got form %v, want a refresh_token grant with scope s1", f)
		}
	}
	if got := creds.JSON(); !bytes.Equal(got, js) {
		t.Errorf("JSON() = %s, want %s", got, js)
	}
	if got, err := creds.UniverseDomain(t.Context()); err != nil || got != "googleapis.com" {
		t.Errorf("UniverseDomain() = %q, %v, want googleapis.com, nil", got, err)
	}
}

func TestBuildCredentialsServiceAccount(t *testing.T) {
	srv := newFakeServer(t,
		fakeResponse{body: `{"access_token":"sa-at-1","token_type":"Bearer","expires_in":3600}`},
		fakeResponse{body: `{"access_token":"sa-at-2","token_type":"Bearer","expires_in":3600}`})
	js := saJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	// The credentials are uncached: each Token call sends a new request.
	for _, want := range []string{"sa-at-1", "sa-at-2"} {
		tok, err := creds.Token(t.Context())
		if err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if tok.Value != want {
			t.Errorf("Token().Value = %q, want %q", tok.Value, want)
		}
	}
	forms := srv.recordedForms()
	if len(forms) != 2 {
		t.Fatalf("server got %d requests, want 2", len(forms))
	}
	for _, f := range forms {
		if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("server got form %v, want a JWT bearer grant", f)
		}
	}
	if got, err := creds.UniverseDomain(t.Context()); err != nil || got != "googleapis.com" {
		t.Errorf("UniverseDomain() = %q, %v, want googleapis.com, nil", got, err)
	}
}

func TestBuildCredentialsSelfSignedJWT(t *testing.T) {
	// The client fails every request: a self-signed JWT makes no network call.
	client := &http.Client{Transport: failTransport{}}
	creds, err := BuildCredentials(t.Context(), &Config{
		JSON:             saJSON(t, nil),
		Client:           client,
		Scopes:           []string{"https://www.googleapis.com/auth/cloud-platform"},
		UseSelfSignedJWT: true,
	})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if _, claims := verifyJWT(t, tok.Value); claims["iss"] != testSAEmail {
		t.Errorf("JWT iss = %v, want %s", claims["iss"], testSAEmail)
	}
}

func TestBuildCredentialsUniverseDomain(t *testing.T) {
	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}
	tests := []struct {
		name   string
		json   []byte
		config string
		want   string
	}{
		{name: "user_default", json: userJSON(t, nil), want: "googleapis.com"},
		{name: "user_json", json: userJSON(t, map[string]any{"universe_domain": "json.example"}), want: "json.example"},
		{name: "user_json_wins_over_config", json: userJSON(t, map[string]any{"universe_domain": "json.example"}), config: "cfg.example", want: "json.example"},
		{name: "user_config_without_json", json: userJSON(t, nil), config: "cfg.example", want: "cfg.example"},
		{name: "user_blank_json_uses_config", json: userJSON(t, map[string]any{"universe_domain": " "}), config: " cfg.example ", want: "cfg.example"},
		{name: "sa_json", json: saJSON(t, map[string]any{"universe_domain": "json.example"}), want: "json.example"},
		{name: "sa_json_wins_over_config", json: saJSON(t, map[string]any{"universe_domain": "json.example"}), config: "cfg.example", want: "json.example"},
		{name: "sa_config_without_json", json: saJSON(t, nil), config: "cfg.example", want: "cfg.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:           tc.json,
				Client:         http.DefaultClient, // never used: no Token call
				Scopes:         scopes,
				UniverseDomain: tc.config,
			})
			if err != nil {
				t.Fatalf("BuildCredentials(%s) error = %v, want nil", tc.name, err)
			}
			if got, err := creds.UniverseDomain(t.Context()); err != nil || got != tc.want {
				t.Errorf("BuildCredentials(%s).UniverseDomain() = %q, %v, want %q, nil", tc.name, got, err, tc.want)
			}
		})
	}
}

func TestBuildCredentialsErrors(t *testing.T) {
	client := http.DefaultClient
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{name: "nil_config", cfg: nil, want: "Config is nil"},
		{name: "nil_client", cfg: &Config{JSON: userJSON(t, nil)}, want: "Client is nil"},
		{name: "empty_json", cfg: &Config{Client: client, JSON: []byte("  ")}, want: "JSON is empty"},
		{name: "not_json", cfg: &Config{Client: client, JSON: []byte(`{"refresh_token":"secret-rt"`)}, want: "not a JSON object"},
		{name: "json_null", cfg: &Config{Client: client, JSON: []byte(" null ")}, want: "not a JSON object"},
		{name: "json_array", cfg: &Config{Client: client, JSON: []byte(`["secret-rt"]`)}, want: "not a JSON object"},
		{name: "nbsp_padded_json", cfg: &Config{Client: client, JSON: append([]byte("\u00a0"), userJSON(t, nil)...)}, want: "not a JSON object"},
		{name: "vertical_tab_padded_json", cfg: &Config{Client: client, JSON: append(userJSON(t, nil), '\v')}, want: "not a JSON object"},
		{name: "json_string", cfg: &Config{Client: client, JSON: []byte(`"secret-rt"`)}, want: "not a JSON object"},
		{name: "type_not_string", cfg: &Config{Client: client, JSON: []byte(`{"type":123,"refresh_token":"secret-rt"}`)}, want: `field "type" must be a string`},
		{name: "universe_domain_not_string", cfg: &Config{Client: client, JSON: []byte(`{"type":"authorized_user","universe_domain":{"secret-rt":1}}`)}, want: `field "universe_domain" must be a string`},
		{name: "no_type", cfg: &Config{Client: client, JSON: []byte(`{}`)}, want: `no "type"`},
		{name: "unknown_type", cfg: &Config{Client: client, JSON: []byte(`{"type":"gdch_service_account"}`)}, want: `unsupported credential type "gdch_service_account"`},
		{name: "impersonated", cfg: &Config{Client: client, JSON: []byte(`{"type":"impersonated_service_account"}`)}, want: "not supported yet"},
		{name: "external_account", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account"}`)}, want: "external_account credentials are not supported"},
		{name: "external_account_authorized_user", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account_authorized_user"}`)}, want: "external_account_authorized_user credentials are not supported"},
		{name: "scope_with_space", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a b"}}, want: "with spaces"},
		{name: "scope_with_unicode_space", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a\u00a0b"}}, want: "with spaces"},
		{name: "user_missing_fields", cfg: &Config{Client: client, JSON: userJSON(t, map[string]any{"client_secret": nil})}, want: "missing client_secret"},
		{name: "user_bad_token_url", cfg: &Config{Client: client, JSON: userJSON(t, nil), TokenURL: "/token"}, want: "token URL must be"},
		{name: "sa_missing_key", cfg: &Config{Client: client, JSON: saJSON(t, map[string]any{"private_key": nil})}, want: "missing private_key"},
		{name: "sa_self_signed_no_scopes", cfg: &Config{Client: client, JSON: saJSON(t, nil), UseSelfSignedJWT: true}, want: "needs Config.Scopes"},
		{name: "sa_self_signed_blank_scopes", cfg: &Config{Client: client, JSON: saJSON(t, nil), UseSelfSignedJWT: true, Scopes: []string{"", " "}}, want: "needs Config.Scopes"},
	}
	_, keyPEM := testServiceAccountKey(t)
	keyLine := strings.Split(keyPEM, "\n")[1] // raw base64 key material, without the PEM header
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := BuildCredentials(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("BuildCredentials(%s) = %v, nil, want error containing %q", tc.name, creds, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildCredentials(%s) error = %q, want it to contain %q", tc.name, err, tc.want)
			}
			for _, secret := range []string{"secret-rt", "refresh-1", "client-secret", "PRIVATE KEY", keyLine} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("BuildCredentials(%s) error = %q, which leaks %q from the JSON", tc.name, err, secret)
				}
			}
		})
	}
}

func TestBuildCredentialsCleansScopes(t *testing.T) {
	tests := []struct {
		name       string
		jsonScopes any
		cfgScopes  []string
		want       string // the scope parameter sent
	}{
		{name: "trims_and_drops_empty", cfgScopes: []string{" s1 ", "", "s2"}, want: "s1 s2"},
		{name: "blank_config_uses_json", jsonScopes: []string{"j1"}, cfgScopes: []string{"", " "}, want: "j1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newFakeServer(t, fakeResponse{body: okTokenBody})
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:   userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "scopes": tc.jsonScopes}),
				Client: srv.Client(),
				Scopes: tc.cfgScopes,
			})
			if err != nil {
				t.Fatalf("BuildCredentials(%s) error = %v, want nil", tc.name, err)
			}
			if _, err := creds.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			if forms := srv.recordedForms(); len(forms) != 1 || forms[0].Get("scope") != tc.want {
				t.Errorf("BuildCredentials(%s): server got forms %v, want scope %q", tc.name, forms, tc.want)
			}
		})
	}
}

func TestBuildCredentialsIgnoresOptionsForOtherTypes(t *testing.T) {
	t.Run("self_signed_jwt_on_authorized_user", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: okTokenBody})
		creds, err := BuildCredentials(t.Context(), &Config{
			JSON:             userJSON(t, map[string]any{"token_uri": srv.URL + "/token"}),
			Client:           srv.Client(),
			UseSelfSignedJWT: true,
		})
		if err != nil {
			t.Fatalf("BuildCredentials(UseSelfSignedJWT: true) error = %v, want nil", err)
		}
		if _, err := creds.Token(t.Context()); err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if forms := srv.recordedForms(); len(forms) != 1 || forms[0].Get("grant_type") != "refresh_token" {
			t.Errorf("server got forms %v, want one refresh_token grant", forms)
		}
	})
	t.Run("rapt_on_service_account", func(t *testing.T) {
		srv := newFakeServer(t, fakeResponse{body: `{"access_token":"sa-at","expires_in":3600}`})
		creds, err := BuildCredentials(t.Context(), &Config{
			JSON:   saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}),
			Client: srv.Client(),
			Scopes: []string{"s1"},
			RAPT: func(context.Context) (string, error) {
				t.Error("Config.RAPT was called for service_account credentials")
				return "rapt", nil
			},
		})
		if err != nil {
			t.Fatalf("BuildCredentials(RAPT set) error = %v, want nil", err)
		}
		if _, err := creds.Token(t.Context()); err != nil {
			t.Fatalf("Token() error = %v", err)
		}
		if forms := srv.recordedForms(); len(forms) != 1 || forms[0].Has("rapt") {
			t.Errorf("server got forms %v, want one request without rapt", forms)
		}
	})
}

func TestBuildCredentialsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := BuildCredentials(ctx, &Config{JSON: userJSON(t, nil), Client: http.DefaultClient})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("BuildCredentials() error = %v, want context.Canceled", err)
	}
}

func TestBuildCredentialsCopiesConfig(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: okTokenBody})
	js := userJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	orig := bytes.Clone(js)
	cfg := &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}}
	creds, err := BuildCredentials(t.Context(), cfg)
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	// Changing the caller's slices and Config must not affect the credentials.
	for i := range js {
		js[i] = ' '
	}
	cfg.Scopes[0] = "changed"
	cfg.TokenURL = "https://changed.example/token"

	if _, err := creds.Token(t.Context()); err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if forms := srv.recordedForms(); len(forms) != 1 || forms[0].Get("scope") != "s1" {
		t.Errorf("server got forms %v, want scope s1", forms)
	}
	if got := creds.JSON(); !bytes.Equal(got, orig) {
		t.Errorf("JSON() = %s, want the JSON as it was when built", got)
	}
}

func TestBuildCredentialsLogsNoSecrets(t *testing.T) {
	// With debug logging on, go/auth writes to stderr when it gets a nil
	// logger, so stderr is captured as well as Config.Logger.
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	_, keyPEM := testServiceAccountKey(t)
	keyLine := strings.Split(keyPEM, "\n")[1] // raw base64 key material
	// The user token response carries an id_token and a rotated refresh token.
	const userBody = `{"access_token":"secret-at","expires_in":3600,"id_token":"secret-idt","refresh_token":"secret-rt-2"}`
	tests := []struct {
		name     string
		json     func(srv *fakeServer) []byte
		self     bool // UseSelfSignedJWT: no request is made
		rapt     bool
		body     string
		wantType string
	}{
		{
			name: "authorized_user",
			json: func(srv *fakeServer) []byte {
				return userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "refresh_token": "secret-rt"})
			},
			rapt:     true,
			body:     userBody,
			wantType: "authorized_user",
		},
		{
			name:     "service_account_2lo",
			json:     func(srv *fakeServer) []byte { return saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}) },
			body:     `{"access_token":"secret-at","expires_in":3600}`,
			wantType: "service_account",
		},
		{
			name:     "service_account_self_signed_jwt",
			json:     func(*fakeServer) []byte { return saJSON(t, nil) },
			self:     true,
			wantType: "service_account",
		},
	}
	for _, tc := range tests {
		for _, debugLogger := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/debug_logger_%v", tc.name, debugLogger), func(t *testing.T) {
				var srv *fakeServer
				if tc.self {
					srv = newFakeServer(t) // fails the test if any request arrives
				} else {
					srv = newFakeServer(t, fakeResponse{body: tc.body})
				}
				var logs bytes.Buffer
				cfg := &Config{
					JSON:             tc.json(srv),
					Client:           srv.Client(),
					Scopes:           []string{"s1"},
					UseSelfSignedJWT: tc.self,
				}
				if debugLogger {
					cfg.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
				}
				if tc.rapt {
					cfg.RAPT = func(context.Context) (string, error) { return "secret-rapt", nil }
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

				if debugLogger {
					for _, want := range []string{"type=" + tc.wantType, "universe_domain=googleapis.com"} {
						if !strings.Contains(outputs["Config.Logger"], want) {
							t.Errorf("BuildCredentials(%s): Config.Logger output = %q, want it to contain %q", tc.name, outputs["Config.Logger"], want)
						}
					}
				}
				secrets := []string{tok.Value, "eyJ", "assertion", "secret-at", "secret-rt", "secret-rt-2",
					"secret-rapt", "secret-idt", "client-secret", "PRIVATE KEY", keyLine}
				for where, out := range outputs {
					for _, secret := range secrets {
						if strings.Contains(out, secret) {
							t.Errorf("BuildCredentials(%s): %s contains %q: %s", tc.name, where, secret, out)
						}
					}
				}
			})
		}
	}
}

// captureStderr redirects os.Stderr to a pipe until the returned function is
// called, which restores it and returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := false
	restore := func() {
		if !done {
			done = true
			os.Stderr = orig
			w.Close()
		}
	}
	t.Cleanup(func() {
		restore()
		r.Close()
	})
	return func() string {
		restore()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("reading stderr: %v", err)
		}
		return string(out)
	}
}

// failTransport fails every request, for tests that must make no network call.
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("failTransport: unexpected request")
}
