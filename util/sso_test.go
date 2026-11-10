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
	"testing"
)

func TestSSOAuthFetch(t *testing.T) {
	tok, err := SSOAuthFetch("echo", "user@example.com", "scope1 scope2")
	if err != nil {
		t.Fatalf("SSOAuthFetch() unexpected error: %v", err)
	}
	wantValue := "user@example.com scope1 scope2\n"
	if tok.Value != wantValue {
		t.Errorf("SSOAuthFetch().Value = %q, want %q", tok.Value, wantValue)
	}
	if tok.Type != "Bearer" {
		t.Errorf("SSOAuthFetch().Type = %q, want %q", tok.Type, "Bearer")
	}

	legacyTok, err := SSOFetch("echo", "user@example.com", "scope1 scope2")
	if err != nil {
		t.Fatalf("SSOFetch() unexpected error: %v", err)
	}
	if legacyTok.AccessToken != wantValue || legacyTok.TokenType != "Bearer" {
		t.Errorf("SSOFetch() = %+v, want AccessToken=%q TokenType=%q", legacyTok, wantValue, "Bearer")
	}
}

func TestSSOAuthFetchError(t *testing.T) {
	if _, err := SSOAuthFetch("false", "user@example.com", "scope1"); err == nil {
		t.Error("SSOAuthFetch(\"false\") error = nil, want non-nil")
	}
	if _, err := SSOFetch("false", "user@example.com", "scope1"); err == nil {
		t.Error("SSOFetch(\"false\") error = nil, want non-nil")
	}
}
