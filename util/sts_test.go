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
package util

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStsAuthExchange(t *testing.T) {
	var gotClaimsHeader string
	var gotSubjectToken string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaimsHeader = r.Header.Get("X-Goog-Auth-Claims")
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() unexpected error: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotSubjectToken = r.PostForm.Get("subject_token")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"sts-access-token","token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}`)
	}))
	t.Cleanup(srv.Close)

	origURL := stsEndpointURL
	t.Cleanup(func() {
		stsEndpointURL = origURL
	})
	stsEndpointURL = srv.URL

	claims := EncodeClaims(&Settings{Audience: "https://example.com", QuotaProject: "my-project"})
	tok, err := StsAuthExchange(t.Context(), "subject-token", claims)
	if err != nil {
		t.Fatalf("StsAuthExchange() unexpected error: %v", err)
	}
	if gotClaimsHeader != claims {
		t.Errorf("X-Goog-Auth-Claims = %q, want %q", gotClaimsHeader, claims)
	}
	if gotSubjectToken != "subject-token" {
		t.Errorf("subject_token = %q, want %q", gotSubjectToken, "subject-token")
	}
	if tok.Value != "sts-access-token" || tok.Type != "Bearer" {
		t.Errorf("StsAuthExchange() = %+v, want Value=%q Type=%q", tok, "sts-access-token", "Bearer")
	}
	wantIssuedType := "urn:ietf:params:oauth:token-type:access_token"
	if got := tok.MetadataString("issued_token_type"); got != wantIssuedType {
		t.Errorf("StsAuthExchange().MetadataString(\"issued_token_type\") = %q, want %q", got, wantIssuedType)
	}

	legacyTok, err := StsExchange("subject-token", claims)
	if err != nil {
		t.Fatalf("StsExchange() unexpected error: %v", err)
	}
	if legacyTok.AccessToken != "sts-access-token" || legacyTok.TokenType != "Bearer" {
		t.Errorf("StsExchange() = %+v, want AccessToken=%q TokenType=%q", legacyTok, "sts-access-token", "Bearer")
	}
	if got := legacyTok.Extra("issued_token_type"); got != wantIssuedType {
		t.Errorf("StsExchange().Extra(\"issued_token_type\") = %v, want %q", got, wantIssuedType)
	}
}

func TestStsAuthExchangeErrors(t *testing.T) {
	t.Run("non_2xx_status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid_request"}`)
		}))
		t.Cleanup(srv.Close)

		origURL := stsEndpointURL
		t.Cleanup(func() { stsEndpointURL = origURL })
		stsEndpointURL = srv.URL

		_, err := StsAuthExchange(t.Context(), "subject-token", "")
		if err == nil || !strings.Contains(err.Error(), "invalid_request") {
			t.Errorf("StsAuthExchange() error = %v, want error containing %q", err, "invalid_request")
		}
	})

	t.Run("invalid_json_response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `not-json`)
		}))
		t.Cleanup(srv.Close)

		origURL := stsEndpointURL
		t.Cleanup(func() { stsEndpointURL = origURL })
		stsEndpointURL = srv.URL

		if _, err := StsAuthExchange(t.Context(), "subject-token", ""); err == nil {
			t.Error("StsAuthExchange() error = nil, want non-nil JSON error")
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if _, err := StsAuthExchange(ctx, "subject-token", ""); !errors.Is(err, context.Canceled) {
			t.Errorf("StsAuthExchange() error = %v, want %v", err, context.Canceled)
		}
	})
}
