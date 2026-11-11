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
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"golang.org/x/oauth2"
)

func TestMarshalUnmarshalAuthTokenWithExtras(t *testing.T) {
	expiry := time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		authTok   *auth.Token
		oauth2Tok *oauth2.Token
		indent    string
		wantJSON  string
	}{
		{
			name: "with_extras_and_refresh_token",
			authTok: &auth.Token{
				Value:  "fake-access-token",
				Type:   "Bearer",
				Expiry: expiry,
				Metadata: map[string]any{
					"refresh_token":     "fake-refresh-token",
					"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
					"id_token":          "fake-id-token",
					"scope":             "scope1 scope2",
				},
			},
			oauth2Tok: (&oauth2.Token{
				AccessToken:  "fake-access-token",
				TokenType:    "Bearer",
				RefreshToken: "fake-refresh-token",
				Expiry:       expiry,
				ExpiresIn:    3600,
			}).WithExtra(map[string]any{
				"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
				"id_token":          "fake-id-token",
				"scope":             "scope1 scope2",
			}),
			indent: "  ",
			wantJSON: "{\n" +
				"  \"access_token\": \"fake-access-token\",\n" +
				"  \"expiry\": \"2026-11-04T12:00:00Z\",\n" +
				"  \"id_token\": \"fake-id-token\",\n" +
				"  \"issued_token_type\": \"urn:ietf:params:oauth:token-type:access_token\",\n" +
				"  \"refresh_token\": \"fake-refresh-token\",\n" +
				"  \"scope\": \"scope1 scope2\",\n" +
				"  \"token_type\": \"Bearer\"\n" +
				"}",
		},
		{
			name: "zero_expiry_and_empty_type",
			authTok: &auth.Token{
				Value: "iam-token",
			},
			oauth2Tok: &oauth2.Token{
				AccessToken: "iam-token",
			},
			wantJSON: "{\n" +
				"\"access_token\": \"iam-token\",\n" +
				"\"expiry\": \"0001-01-01T00:00:00Z\"\n" +
				"}",
		},
		{
			name: "form_encoded_metadata_slices",
			authTok: &auth.Token{
				Value:  "fake-form-access-token",
				Type:   "Bearer",
				Expiry: expiry,
				Metadata: map[string]any{
					"refresh_token": []string{"fake-form-refresh-token"},
					"scope":         []string{"form-scope"},
				},
			},
			oauth2Tok: (&oauth2.Token{
				AccessToken:  "fake-form-access-token",
				TokenType:    "Bearer",
				RefreshToken: "fake-form-refresh-token",
				Expiry:       expiry,
			}).WithExtra(map[string]any{
				"scope": "form-scope",
			}),
			wantJSON: "{\n" +
				"\"access_token\": \"fake-form-access-token\",\n" +
				"\"expiry\": \"2026-11-04T12:00:00Z\",\n" +
				"\"refresh_token\": \"fake-form-refresh-token\",\n" +
				"\"scope\": \"form-scope\",\n" +
				"\"token_type\": \"Bearer\"\n" +
				"}",
		},
		{
			name: "json_unmarshaled_any_slices",
			authTok: &auth.Token{
				Value:  "fake-any-access-token",
				Type:   "Bearer",
				Expiry: expiry,
				Metadata: map[string]any{
					"refresh_token": []any{"fake-any-refresh-token"},
					"scope":         []any{"any-scope"},
				},
			},
			oauth2Tok: (&oauth2.Token{
				AccessToken:  "fake-any-access-token",
				TokenType:    "Bearer",
				RefreshToken: "fake-any-refresh-token",
				Expiry:       expiry,
			}).WithExtra(map[string]any{
				"scope": "any-scope",
			}),
			wantJSON: "{\n" +
				"\"access_token\": \"fake-any-access-token\",\n" +
				"\"expiry\": \"2026-11-04T12:00:00Z\",\n" +
				"\"refresh_token\": \"fake-any-refresh-token\",\n" +
				"\"scope\": \"any-scope\",\n" +
				"\"token_type\": \"Bearer\"\n" +
				"}",
		},
		{
			name: "oauth2_extra_refresh_token_ignored_when_field_empty",
			authTok: &auth.Token{
				Value:  "fake-access-token",
				Type:   "Bearer",
				Expiry: expiry,
			},
			oauth2Tok: (&oauth2.Token{
				AccessToken: "fake-access-token",
				TokenType:   "Bearer",
				Expiry:      expiry,
			}).WithExtra(map[string]any{
				"refresh_token": "extra-only-refresh-token",
			}),
			wantJSON: "{\n" +
				"\"access_token\": \"fake-access-token\",\n" +
				"\"expiry\": \"2026-11-04T12:00:00Z\",\n" +
				"\"token_type\": \"Bearer\"\n" +
				"}",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAuthBytes, err := MarshalAuthTokenWithExtras(tc.authTok, tc.indent)
			if err != nil {
				t.Fatalf("MarshalAuthTokenWithExtras() unexpected error: %v", err)
			}
			if string(gotAuthBytes) != tc.wantJSON {
				t.Errorf("MarshalAuthTokenWithExtras() = %s, want %s", gotAuthBytes, tc.wantJSON)
			}
			gotOAuth2Bytes, err := MarshalWithExtras(tc.oauth2Tok, tc.indent)
			if err != nil {
				t.Fatalf("MarshalWithExtras() unexpected error: %v", err)
			}
			if string(gotOAuth2Bytes) != tc.wantJSON {
				t.Errorf("MarshalWithExtras() = %s, want %s", gotOAuth2Bytes, tc.wantJSON)
			}

			unmarshaledAuth, err := UnmarshalAuthTokenWithExtras(gotAuthBytes)
			if err != nil {
				t.Fatalf("UnmarshalAuthTokenWithExtras() unexpected error: %v", err)
			}
			if unmarshaledAuth.Value != tc.authTok.Value {
				t.Errorf("UnmarshalAuthTokenWithExtras().Value = %q, want %q", unmarshaledAuth.Value, tc.authTok.Value)
			}
			if unmarshaledAuth.Type != tc.authTok.Type {
				t.Errorf("UnmarshalAuthTokenWithExtras().Type = %q, want %q", unmarshaledAuth.Type, tc.authTok.Type)
			}
			if !unmarshaledAuth.Expiry.Equal(tc.authTok.Expiry) {
				t.Errorf("UnmarshalAuthTokenWithExtras().Expiry = %v, want %v", unmarshaledAuth.Expiry, tc.authTok.Expiry)
			}
			if gotRT, wantRT := unmarshaledAuth.MetadataString("refresh_token"), tc.oauth2Tok.RefreshToken; gotRT != wantRT {
				t.Errorf("UnmarshalAuthTokenWithExtras().MetadataString(\"refresh_token\") = %q, want %q", gotRT, wantRT)
			}

			unmarshaledOAuth2, err := UnmarshalWithExtras(gotAuthBytes)
			if err != nil {
				t.Fatalf("UnmarshalWithExtras() unexpected error: %v", err)
			}
			if unmarshaledOAuth2.AccessToken != tc.oauth2Tok.AccessToken {
				t.Errorf("UnmarshalWithExtras().AccessToken = %q, want %q", unmarshaledOAuth2.AccessToken, tc.oauth2Tok.AccessToken)
			}
			if unmarshaledOAuth2.TokenType != tc.oauth2Tok.TokenType {
				t.Errorf("UnmarshalWithExtras().TokenType = %q, want %q", unmarshaledOAuth2.TokenType, tc.oauth2Tok.TokenType)
			}
			if unmarshaledOAuth2.RefreshToken != tc.oauth2Tok.RefreshToken {
				t.Errorf("UnmarshalWithExtras().RefreshToken = %q, want %q", unmarshaledOAuth2.RefreshToken, tc.oauth2Tok.RefreshToken)
			}
			if got := unmarshaledOAuth2.Extra("access_token"); got != tc.oauth2Tok.AccessToken {
				t.Errorf("UnmarshalWithExtras().Extra(\"access_token\") = %v, want %q", got, tc.oauth2Tok.AccessToken)
			}
			for _, k := range []string{"issued_token_type", "id_token", "scope"} {
				if got, want := unmarshaledOAuth2.Extra(k), tc.oauth2Tok.Extra(k); !reflect.DeepEqual(got, want) {
					t.Errorf("UnmarshalWithExtras().Extra(%q) = %v, want %v", k, got, want)
				}
			}
		})
	}
}

func TestLookupAndInsertAuthCache(t *testing.T) {
	origCacheLocation := CacheLocation
	t.Cleanup(func() {
		CacheLocation = origCacheLocation
	})
	CacheLocation = filepath.Join(t.TempDir(), ".oauth2l")

	settings := &Settings{
		CredentialsJSON: `{"installed":{"client_id":"cid","redirect_uris":["http://localhost:12345"]}}`,
		Scope:           "https://www.googleapis.com/auth/cloud-platform",
	}

	// Cache miss returns (nil, nil) for LookupAuthCache and (nil, non-nil) for
	// deprecated LookupCache (matching legacy behavior).
	if got, err := LookupAuthCache(settings); got != nil || err != nil {
		t.Errorf("LookupAuthCache() on empty cache = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := LookupCache(settings); got != nil || err == nil {
		t.Errorf("LookupCache() on empty cache = (%v, %v), want (nil, non-nil)", got, err)
	}

	// Inserting a nil token is a no-op and must not poison the cache with "null".
	if err := InsertAuthCache(settings, nil); err != nil {
		t.Fatalf("InsertAuthCache(nil) unexpected error: %v", err)
	}
	if err := InsertCache(settings, nil); err != nil {
		t.Fatalf("InsertCache(nil) unexpected error: %v", err)
	}
	if got, err := LookupAuthCache(settings); got != nil || err != nil {
		t.Errorf("LookupAuthCache() after inserting nil = (%v, %v), want (nil, nil)", got, err)
	}

	expiry := time.Date(2026, time.November, 4, 15, 0, 0, 0, time.UTC)
	want := &auth.Token{
		Value:  "cached-access-token",
		Type:   "Bearer",
		Expiry: expiry,
		Metadata: map[string]any{
			"refresh_token": "cached-refresh-token",
			"id_token":      "cached-id-token",
		},
	}
	if err := InsertAuthCache(settings, want); err != nil {
		t.Fatalf("InsertAuthCache() unexpected error: %v", err)
	}

	// Dynamic localhost port in redirect_uris should hit the same cache entry.
	lookupSettings := &Settings{
		CredentialsJSON: `{"installed":{"client_id":"cid","redirect_uris":["http://localhost:54321"]}}`,
		Scope:           "https://www.googleapis.com/auth/cloud-platform",
	}
	got, err := LookupAuthCache(lookupSettings)
	if err != nil {
		t.Fatalf("LookupAuthCache() unexpected error: %v", err)
	}
	if got.Value != want.Value || got.Type != want.Type || !got.Expiry.Equal(want.Expiry) {
		t.Errorf("LookupAuthCache() = %+v, want %+v", got, want)
	}
	if gotRT := got.MetadataString("refresh_token"); gotRT != "cached-refresh-token" {
		t.Errorf("LookupAuthCache().MetadataString(\"refresh_token\") = %q, want %q", gotRT, "cached-refresh-token")
	}

	// Deprecated LookupCache and InsertCache interoperate with the same file.
	gotOAuth2, err := LookupCache(lookupSettings)
	if err != nil {
		t.Fatalf("LookupCache() unexpected error: %v", err)
	}
	if gotOAuth2.AccessToken != want.Value || gotOAuth2.RefreshToken != "cached-refresh-token" {
		t.Errorf("LookupCache() = %+v, want AccessToken=%q RefreshToken=%q", gotOAuth2, want.Value, "cached-refresh-token")
	}

	if err := ClearCache(); err != nil {
		t.Fatalf("ClearCache() unexpected error: %v", err)
	}
}
