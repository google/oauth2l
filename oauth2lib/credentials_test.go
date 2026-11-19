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
	srv := newFakeServer(t, fakeResponse{body: okTokenBody})
	js := userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "quota_project_id": "qp"})
	creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tok.Value != "at-1" {
		t.Errorf("Token().Value = %q, want at-1", tok.Value)
	}
	forms := srv.recordedForms()
	if len(forms) != 1 || forms[0].Get("scope") != "s1" || forms[0].Get("grant_type") != "refresh_token" {
		t.Errorf("server got forms %v, want one refresh_token grant with scope s1", forms)
	}
	if got := creds.JSON(); !bytes.Equal(got, js) {
		t.Errorf("JSON() = %s, want %s", got, js)
	}
	if got, err := creds.UniverseDomain(t.Context()); err != nil || got != "googleapis.com" {
		t.Errorf("UniverseDomain() = %q, %v, want googleapis.com, nil", got, err)
	}
}

func TestBuildCredentialsServiceAccount(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"sa-at","token_type":"Bearer","expires_in":3600}`})
	js := saJSON(t, map[string]any{"token_uri": srv.URL + "/token"})
	creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}})
	if err != nil {
		t.Fatalf("BuildCredentials() error = %v", err)
	}
	tok, err := creds.Token(t.Context())
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if tok.Value != "sa-at" {
		t.Errorf("Token().Value = %q, want sa-at", tok.Value)
	}
	forms := srv.recordedForms()
	if len(forms) != 1 || forms[0].Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("server got forms %v, want one JWT bearer grant", forms)
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
		{name: "user_config_wins", json: userJSON(t, map[string]any{"universe_domain": "json.example"}), config: "cfg.example", want: "cfg.example"},
		{name: "sa_json", json: saJSON(t, map[string]any{"universe_domain": "json.example"}), want: "json.example"},
		{name: "sa_config_wins", json: saJSON(t, map[string]any{"universe_domain": "json.example"}), config: "cfg.example", want: "cfg.example"},
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
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			if got, err := creds.UniverseDomain(t.Context()); err != nil || got != tc.want {
				t.Errorf("UniverseDomain() = %q, %v, want %q, nil", got, err, tc.want)
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
		{name: "json_array", cfg: &Config{Client: client, JSON: []byte(`["secret-rt"]`)}, want: "not a JSON object"},
		{name: "no_type", cfg: &Config{Client: client, JSON: []byte(`{}`)}, want: `no "type"`},
		{name: "unknown_type", cfg: &Config{Client: client, JSON: []byte(`{"type":"gdch_service_account"}`)}, want: `unsupported credential type "gdch_service_account"`},
		{name: "impersonated", cfg: &Config{Client: client, JSON: []byte(`{"type":"impersonated_service_account"}`)}, want: "not supported yet"},
		{name: "external_account", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account"}`)}, want: "external_account credentials are not supported"},
		{name: "external_account_authorized_user", cfg: &Config{Client: client, JSON: []byte(`{"type":"external_account_authorized_user"}`)}, want: "external_account_authorized_user credentials are not supported"},
		{name: "empty_scope", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a", ""}}, want: "empty scope"},
		{name: "scope_with_space", cfg: &Config{Client: client, JSON: userJSON(t, nil), Scopes: []string{"a b"}}, want: "with spaces"},
		{name: "self_signed_user", cfg: &Config{Client: client, JSON: userJSON(t, nil), UseSelfSignedJWT: true}, want: "applies only to service_account"},
		{name: "user_missing_fields", cfg: &Config{Client: client, JSON: userJSON(t, map[string]any{"client_secret": nil})}, want: "missing client_secret"},
		{name: "user_bad_token_url", cfg: &Config{Client: client, JSON: userJSON(t, nil), TokenURL: "/token"}, want: "absolute URL"},
		{name: "sa_missing_key", cfg: &Config{Client: client, JSON: saJSON(t, map[string]any{"private_key": nil})}, want: "missing private_key"},
		{name: "sa_self_signed_no_scopes", cfg: &Config{Client: client, JSON: saJSON(t, nil), UseSelfSignedJWT: true}, want: "needs Config.Scopes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			creds, err := BuildCredentials(t.Context(), tc.cfg)
			if err == nil {
				t.Fatalf("BuildCredentials() = %v, nil, want error containing %q", creds, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("BuildCredentials() error = %q, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret-rt") || strings.Contains(err.Error(), "client-secret") {
				t.Errorf("BuildCredentials() error = %q, which leaks the JSON", err)
			}
		})
	}
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
	srv := newFakeServer(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	for _, js := range [][]byte{
		userJSON(t, map[string]any{"token_uri": srv.URL + "/token", "refresh_token": "secret-rt"}),
		saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}),
	} {
		srv.mu.Lock()
		srv.responses = append(srv.responses, fakeResponse{body: `{"access_token":"secret-at","expires_in":3600}`})
		srv.mu.Unlock()
		creds, err := BuildCredentials(t.Context(), &Config{JSON: js, Client: srv.Client(), Scopes: []string{"s1"}, Logger: logger})
		if err != nil {
			t.Fatalf("BuildCredentials() error = %v", err)
		}
		if _, err := creds.Token(t.Context()); err != nil {
			t.Fatalf("Token() error = %v", err)
		}
	}
	got := logs.String()
	if !strings.Contains(got, "type=authorized_user") || !strings.Contains(got, "type=service_account") {
		t.Errorf("logs = %q, want a debug line per credential type", got)
	}
	for _, secret := range []string{"secret-at", "secret-rt", "client-secret", "PRIVATE KEY"} {
		if strings.Contains(got, secret) {
			t.Errorf("logs contain %q: %s", secret, got)
		}
	}
}

// failTransport fails every request, for tests that must make no network call.
type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("failTransport: unexpected request")
}
