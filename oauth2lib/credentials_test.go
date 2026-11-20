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
	"log/slog"
	"net/http"
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
		{name: "no_type", cfg: &Config{Client: client, JSON: []byte(`{}`)}, want: `no "type"`},
		{name: "unknown_type", cfg: &Config{Client: client, JSON: []byte(`{"type":"gdch_service_account"}`)}, want: `unsupported credential type "gdch_service_account"`},
		{name: "impersonated", cfg: &Config{Client: client, JSON: []byte(`{"type":"impersonated_service_account"}`)}, want: "not supported yet"},
		{name: "external_account", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account"}`)}, want: "external_account credentials are not supported"},
		{name: "external_account_authorized_user", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account_authorized_user"}`)}, want: "external_account_authorized_user credentials are not supported"},
		{name: "empty_scope", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a", ""}}, want: "empty scope"},
		{name: "scope_with_space", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a b"}}, want: "with spaces"},
		{name: "scope_with_unicode_space", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a\u00a0b"}}, want: "with spaces"},
		{name: "user_missing_fields", cfg: &Config{Client: client, JSON: userJSON(t, map[string]any{"client_secret": nil})}, want: "missing client_secret"},
		{name: "user_bad_token_url", cfg: &Config{Client: client, JSON: userJSON(t, nil), TokenURL: "/token"}, want: "token URL must be"},
		{name: "sa_missing_key", cfg: &Config{Client: client, JSON: saJSON(t, map[string]any{"private_key": nil})}, want: "missing private_key"},
		{name: "sa_self_signed_no_scopes", cfg: &Config{Client: client, JSON: saJSON(t, nil), UseSelfSignedJWT: true}, want: "needs Config.Scopes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := BuildCredentials(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("BuildCredentials(%s) = %v, nil, want error containing %q", tc.name, creds, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildCredentials(%s) error = %q, want it to contain %q", tc.name, err, tc.want)
			}
			for _, secret := range []string{"secret-rt", "client-secret", "PRIVATE KEY"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("BuildCredentials(%s) error = %q, which leaks %q from the JSON", tc.name, err, secret)
				}
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
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	const tokenBody = `{"access_token":"secret-at","expires_in":3600}`
	tests := []struct {
		name     string
		json     func(srv *fakeServer) []byte
		self     bool // UseSelfSignedJWT: no request is made
		wantType string
	}{
		{
			name: "authorized_user",
			json: func(srv *fakeServer) []byte {
				return userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "refresh_token": "secret-rt"})
			},
			wantType: "authorized_user",
		},
		{
			name:     "service_account_2lo",
			json:     func(srv *fakeServer) []byte { return saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}) },
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
		t.Run(tc.name, func(t *testing.T) {
			var srv *fakeServer
			if tc.self {
				srv = newFakeServer(t) // fails the test if any request arrives
			} else {
				srv = newFakeServer(t, fakeResponse{body: tokenBody})
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:             tc.json(srv),
				Client:           srv.Client(),
				Scopes:           []string{"s1"},
				UseSelfSignedJWT: tc.self,
				Logger:           logger,
			})
			if err != nil {
				t.Fatalf("BuildCredentials(%s) error = %v", tc.name, err)
			}
			if _, err := creds.Token(t.Context()); err != nil {
				t.Fatalf("Token() error = %v", err)
			}
			got := logs.String()
			for _, want := range []string{"type=" + tc.wantType, "universe_domain=googleapis.com"} {
				if !strings.Contains(got, want) {
					t.Errorf("logs = %q, want them to contain %q", got, want)
				}
			}
			for _, secret := range []string{"secret-at", "secret-rt", "client-secret", "PRIVATE KEY"} {
				if strings.Contains(got, secret) {
					t.Errorf("logs contain %q: %s", secret, got)
				}
			}
		})
	}
}

// failTransport fails every request, for tests that must make no network call.
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("failTransport: unexpected request")
}
