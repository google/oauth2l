//
// Copyright 2026 Google Inc.
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
package util

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2/jws"
)

func TestIDTokenSource(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	const audience = "https://hello.a.run.app"
	exp := time.Now().Add(time.Hour).Unix()
	idToken, err := jws.Encode(&jws.Header{Algorithm: "RS256", Typ: "JWT"},
		&jws.ClaimSet{Aud: audience, Exp: exp}, key)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// jws.Decode drops private claims, so decode the payload directly.
		var claims map[string]interface{}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(r.FormValue("assertion"), ".")[1])
		if err == nil {
			err = json.Unmarshal(payload, &claims)
		}
		if err != nil {
			t.Errorf("Failed to decode assertion: %v", err)
		}
		if got := claims["target_audience"]; got != audience {
			t.Errorf("target_audience = %v, want %v", got, audience)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id_token": %q}`, idToken)
	}))
	defer server.Close()

	creds, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "sa@example.iam.gserviceaccount.com",
		"private_key":  string(keyPEM),
		"token_uri":    server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts, err := IDTokenSource(context.Background(), creds, audience)
	if err != nil {
		t.Fatal(err)
	}
	token, err := ts.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != idToken {
		t.Errorf("AccessToken = %q, want ID token %q", token.AccessToken, idToken)
	}
	if token.Expiry.Unix() != exp {
		t.Errorf("Expiry = %v, want %v", token.Expiry.Unix(), exp)
	}
}
