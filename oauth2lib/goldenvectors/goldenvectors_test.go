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

package goldenvectors

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestAllWellFormed checks the shape of every vector, so a broken file fails
// here and not only in the tests that run the vectors.
func TestAllWellFormed(t *testing.T) {
	vectors, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("All() returned no vectors")
	}
	sentinels := []string{ErrReauthRequired, ErrAccessDenied, ErrCAADenied, ErrInvalidGrant, ErrTransient}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Description == "" {
				t.Error("description is empty")
			}
			if (v.Input.Config == nil) == (v.Input.Impersonation == nil) {
				t.Error("input must set exactly one of config and impersonation")
			}
			if (v.Expected.Token == nil) == (v.Expected.Error == nil) {
				t.Error("expected must set exactly one of token and error")
			}
			if v.Expected.UniverseDomain == "" {
				t.Error("expected.universe_domain is empty")
			}
			if e := v.Expected.Error; e != nil {
				for _, s := range e.Is {
					if !slices.Contains(sentinels, s) {
						t.Errorf("expected.error.is has unknown sentinel %q", s)
					}
				}
			}
			for i, ex := range v.Exchanges {
				r := ex.Request
				if r.Method == "" || r.URL == "" {
					t.Errorf("exchange %d: request needs method and url", i)
				}
				if len(r.JSON) > 0 && (r.Form != nil || r.Assertion != nil) {
					t.Errorf("exchange %d: request has both a JSON and a form body", i)
				}
				if _, ok := r.Form["assertion"]; ok && r.Assertion != nil {
					t.Errorf("exchange %d: form.assertion and assertion are both set", i)
				}
				resp := ex.Response
				bodies := 0
				for _, set := range []bool{len(resp.Body) > 0, resp.BodyText != "", resp.TransportError != ""} {
					if set {
						bodies++
					}
				}
				if bodies > 1 {
					t.Errorf("exchange %d: response sets more than one of body, body_text and transport_error", i)
				}
			}
		})
	}
}

// TestConfigJSON checks that the placeholder is replaced with the key,
// JSON-escaped, wherever it appears (including nested source credentials).
func TestConfigJSON(t *testing.T) {
	const pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
	c := Config{CredentialsJSON: json.RawMessage(`{"private_key":"` + PrivateKeyPlaceholder +
		`","source_credentials":{"private_key":"` + PrivateKeyPlaceholder + `"}}`)}
	b, err := c.JSON(pem)
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	var got struct {
		PrivateKey string `json:"private_key"`
		Source     struct {
			PrivateKey string `json:"private_key"`
		} `json:"source_credentials"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("JSON() = %s, not valid JSON: %v", b, err)
	}
	if got.PrivateKey != pem || got.Source.PrivateKey != pem {
		t.Errorf("JSON() = %s, want both private_key fields to be the key", b)
	}
	if strings.Contains(string(b), PrivateKeyPlaceholder) {
		t.Errorf("JSON() = %s still contains the placeholder", b)
	}
}
