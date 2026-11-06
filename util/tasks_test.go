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
	"time"

	"cloud.google.com/go/auth"
)

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name  string
		token *auth.Token
		want  bool
	}{
		{
			name: "nil_token",
		},
		{
			name:  "zero_expiry",
			token: &auth.Token{Value: "sso-token"},
		},
		{
			name:  "future_expiry",
			token: &auth.Token{Value: "valid-token", Expiry: time.Now().Add(time.Hour)},
		},
		{
			name:  "past_expiry",
			token: &auth.Token{Value: "expired-token", Expiry: time.Now().Add(-time.Hour)},
			want:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTokenExpired(tc.token); got != tc.want {
				t.Errorf("isTokenExpired(%+v) = %v, want %v", tc.token, got, tc.want)
			}
		})
	}
}

