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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2/jws"
)

func TestGenerateServiceAccountIdToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "https://hello.a.run.app"
	const serviceAccount = "sa@example.iam.gserviceaccount.com"
	exp := time.Now().Add(time.Hour).Unix()
	idToken, err := jws.Encode(&jws.Header{Algorithm: "RS256", Typ: "JWT"},
		&jws.ClaimSet{Aud: audience, Exp: exp}, key)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/" + serviceAccount + ":generateIdToken"; r.URL.Path != want {
			t.Errorf("Path = %v, want %v", r.URL.Path, want)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer user-token" {
			t.Errorf("Authorization = %v, want Bearer user-token", got)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		if body["audience"] != audience || body["includeEmail"] != true {
			t.Errorf("Request body = %v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": %q}`, idToken)
	}))
	defer server.Close()

	oldURL := IamServiceAccountIdTokenURL
	IamServiceAccountIdTokenURL = server.URL + "/%s:generateIdToken"
	defer func() { IamServiceAccountIdTokenURL = oldURL }()

	token, err := GenerateServiceAccountIdToken("user-token", serviceAccount, audience)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != idToken {
		t.Errorf("AccessToken = %q, want ID token %q", token.AccessToken, idToken)
	}
	if token.Extra("id_token") != idToken {
		t.Errorf("id_token extra = %v, want ID token %q", token.Extra("id_token"), idToken)
	}
	if token.Expiry.Unix() != exp {
		t.Errorf("Expiry = %v, want %v", token.Expiry.Unix(), exp)
	}
}
