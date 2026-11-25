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
	"strings"
	"testing"
)

// TestAllWellFormed checks that every vector parses and passes Validate, so
// a broken file fails here and not only in the tests that run the vectors.
func TestAllWellFormed(t *testing.T) {
	vectors, err := All()
	if err != nil {
		t.Fatalf("All() error = %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("All() returned no vectors")
	}
	for _, v := range vectors {
		if err := v.Validate(); err != nil {
			t.Errorf("%s: Validate() error = %v", v.Name, err)
		}
	}
}

func int64Ptr(n int64) *int64 { return &n }

// validVector returns a vector that passes Validate.
func validVector() Vector {
	return Vector{
		Name:        "valid",
		Description: "A valid vector.",
		Input: Input{Config: &Config{
			CredentialsJSON: json.RawMessage(`{"type":"authorized_user"}`),
		}},
		Exchanges: []Exchange{{
			Request:  Request{Method: "POST", URL: "https://oauth2.googleapis.com/token"},
			Response: Response{Body: json.RawMessage(`{}`)},
		}},
		Expected: Expected{
			Token:          &Token{Value: "token", Type: "Bearer", ExpiresInSeconds: int64Ptr(3600)},
			UniverseDomain: "googleapis.com",
		},
	}
}

func TestValidate(t *testing.T) {
	if err := validVector().Validate(); err != nil {
		t.Fatalf("validVector().Validate() error = %v", err)
	}
	impersonation := func(v *Vector) {
		v.Input = Input{Impersonation: &Impersonation{
			Source: Config{CredentialsJSON: json.RawMessage(`{"type":"authorized_user"}`)},
			Target: "sa@project.iam.gserviceaccount.com",
			Scopes: []string{"scope"},
		}}
	}
	lastExchangeError := func(te *TransportError) func(*Vector) {
		return func(v *Vector) {
			v.Exchanges[0].Response = Response{TransportError: te}
			v.Expected.Token = nil
			v.Expected.Error = &Error{Kind: KindTransient}
		}
	}
	valid := []struct {
		name   string
		mutate func(*Vector)
	}{
		{name: "impersonation", mutate: impersonation},
		{name: "jwt_token", mutate: func(v *Vector) { v.Expected.Token.Value = ""; v.Expected.Token.JWT = &JWT{} }},
		{name: "expiry", mutate: func(v *Vector) {
			v.Expected.Token.ExpiresInSeconds = nil
			v.Expected.Token.Expiry = "2030-01-02T03:04:05Z"
		}},
		{name: "network_error", mutate: lastExchangeError(&TransportError{Message: "reset"})},
		{name: "client_timeout", mutate: lastExchangeError(&TransportError{Message: "timeout", Type: TransportErrorClientTimeout})},
		{name: "every_kind_and_sentinel", mutate: func(v *Vector) {
			v.Expected.Token = nil
			v.Expected.Error = &Error{Kind: KindReauthRequired, Is: []string{ErrReauthRequired, ErrAccessDenied, ErrCAADenied, ErrInvalidGrant, ErrTransient}}
		}},
	}
	for _, tc := range valid {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			v := validVector()
			tc.mutate(&v)
			if err := v.Validate(); err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}

	invalid := []struct {
		name    string
		mutate  func(*Vector)
		wantErr string
	}{
		{"empty_name", func(v *Vector) { v.Name = "" }, "name is empty"},
		{"empty_description", func(v *Vector) { v.Description = "" }, "description is empty"},
		{"no_input", func(v *Vector) { v.Input = Input{} }, "exactly one of config and impersonation"},
		{"both_inputs", func(v *Vector) {
			c := v.Input.Config
			impersonation(v)
			v.Input.Config = c
		}, "exactly one of config and impersonation"},
		{"empty_credentials_json", func(v *Vector) { v.Input.Config.CredentialsJSON = nil }, "input.config.credentials_json is empty"},
		{"null_credentials_json", func(v *Vector) { v.Input.Config.CredentialsJSON = json.RawMessage(" null ") }, "input.config.credentials_json is empty"},
		{"empty_source_credentials_json", func(v *Vector) {
			impersonation(v)
			v.Input.Impersonation.Source.CredentialsJSON = nil
		}, "input.impersonation.source.credentials_json is empty"},
		{"empty_target", func(v *Vector) {
			impersonation(v)
			v.Input.Impersonation.Target = ""
		}, "input.impersonation.target is empty"},
		{"no_method", func(v *Vector) { v.Exchanges[0].Request.Method = "" }, "request needs method and url"},
		{"no_url", func(v *Vector) { v.Exchanges[0].Request.URL = "" }, "request needs method and url"},
		{"json_and_form", func(v *Vector) {
			v.Exchanges[0].Request.JSON = json.RawMessage(`{}`)
			v.Exchanges[0].Request.Form = map[string]string{}
		}, "both a JSON and a form body"},
		{"form_and_assertion", func(v *Vector) {
			v.Exchanges[0].Request.Form = map[string]string{"assertion": "x"}
			v.Exchanges[0].Request.Assertion = &JWT{}
		}, "form.assertion and assertion are both set"},
		{"body_and_body_text", func(v *Vector) { v.Exchanges[0].Response.BodyText = "x" }, "more than one of body, body_text and transport_error"},
		{"body_and_transport_error", func(v *Vector) {
			v.Exchanges[0].Response.TransportError = &TransportError{Message: "x"}
		}, "more than one of body, body_text and transport_error"},
		{"empty_transport_error_message", lastExchangeError(&TransportError{}), "transport_error.message is empty"},
		{"unknown_transport_error_type", lastExchangeError(&TransportError{Message: "x", Type: "tls"}), `transport_error.type "tls" is unknown`},
		{"status_and_transport_error", func(v *Vector) {
			lastExchangeError(&TransportError{Message: "x"})(v)
			v.Exchanges[0].Response.Status = 500
		}, "both status and transport_error"},
		{"transport_error_not_last", func(v *Vector) {
			lastExchangeError(&TransportError{Message: "x"})(v)
			v.Exchanges = append(v.Exchanges, v.Exchanges[0])
		}, "exchange 0: transport_error must be on the last exchange"},
		{"no_expected", func(v *Vector) { v.Expected.Token = nil }, "exactly one of token and error"},
		{"token_and_error", func(v *Vector) { v.Expected.Error = &Error{Kind: KindUnknown} }, "exactly one of token and error"},
		{"empty_universe_domain", func(v *Vector) { v.Expected.UniverseDomain = "" }, "expected.universe_domain is empty"},
		{"token_without_value_or_jwt", func(v *Vector) { v.Expected.Token.Value = "" }, "exactly one of value and jwt"},
		{"token_with_value_and_jwt", func(v *Vector) { v.Expected.Token.JWT = &JWT{} }, "exactly one of value and jwt"},
		{"empty_token_type", func(v *Vector) { v.Expected.Token.Type = "" }, "expected.token.type is empty"},
		{"expires_in_and_expiry", func(v *Vector) { v.Expected.Token.Expiry = "2030-01-02T03:04:05Z" }, "both expires_in_seconds and expiry"},
		{"bad_expiry", func(v *Vector) {
			v.Expected.Token.ExpiresInSeconds = nil
			v.Expected.Token.Expiry = "2030-01-02 03:04:05"
		}, "is not RFC 3339"},
		{"empty_kind", func(v *Vector) {
			v.Expected.Token = nil
			v.Expected.Error = &Error{}
		}, `expected.error.kind "" is unknown`},
		{"display_kind", func(v *Vector) {
			v.Expected.Token = nil
			v.Expected.Error = &Error{Kind: "reauth required"}
		}, `expected.error.kind "reauth required" is unknown`},
		{"unknown_sentinel", func(v *Vector) {
			v.Expected.Token = nil
			v.Expected.Error = &Error{Kind: KindUnknown, Is: []string{"ErrUnknown"}}
		}, `unknown sentinel "ErrUnknown"`},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			v := validVector()
			tc.mutate(&v)
			err := v.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestDecode checks the checks that All makes on each file besides
// Validate.
func TestDecode(t *testing.T) {
	b, err := json.Marshal(validVector())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode("valid.json", b); err != nil {
		t.Fatalf("decode(valid.json) error = %v", err)
	}
	invalid := func(v *Vector) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	noDescription := validVector()
	noDescription.Description = ""
	for _, tc := range []struct {
		name    string
		file    string
		data    []byte
		wantErr string
	}{
		{"trailing_object", "valid.json", append(append([]byte{}, b...), "\n{}"...), "valid.json: data after the vector"},
		{"trailing_garbage", "valid.json", append(append([]byte{}, b...), " x"...), "valid.json: data after the vector"},
		{"two_vectors", "valid.json", append(append(append([]byte{}, b...), '\n'), b...), "valid.json: data after the vector"},
		{"unknown_field", "valid.json", []byte(`{"name":"valid","extra":1}`), `valid.json: json: unknown field "extra"`},
		{"not_json", "valid.json", []byte(`not json`), "valid.json: invalid character"},
		{"name_mismatch", "other.json", b, `other.json: name is "valid", want "other"`},
		{"invalid", "valid.json", invalid(&noDescription), "valid.json: description is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decode(tc.file, tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("decode() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
	// Trailing spaces and newlines are not data.
	if _, err := decode("valid.json", append(append([]byte{}, b...), " \n\t\n"...)); err != nil {
		t.Errorf("decode() with trailing spaces error = %v, want nil", err)
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
