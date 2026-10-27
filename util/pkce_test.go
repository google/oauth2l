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
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestGeneratePKCEOptions(t *testing.T) {
	opts1 := GeneratePKCEOptions()
	if opts1 == nil {
		t.Fatal("GeneratePKCEOptions() = nil, want non-nil")
	}
	if opts1.ChallengeMethod != "S256" {
		t.Errorf("ChallengeMethod = %q, want %q", opts1.ChallengeMethod, "S256")
	}
	if _, err := uuid.Parse(opts1.Verifier); err != nil {
		t.Errorf("Verifier %q is not a valid UUID: %v", opts1.Verifier, err)
	}

	sha := sha256.Sum256([]byte(opts1.Verifier))
	wantChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
	if opts1.Challenge != wantChallenge {
		t.Errorf("Challenge = %q, want %q", opts1.Challenge, wantChallenge)
	}

	opts2 := GeneratePKCEOptions()
	if opts1.Verifier == opts2.Verifier {
		t.Errorf("consecutive GeneratePKCEOptions() calls returned identical Verifier %q", opts1.Verifier)
	}
}

func TestGeneratePKCEParams(t *testing.T) {
	params := GeneratePKCEParams()
	if params == nil {
		t.Fatal("GeneratePKCEParams() = nil, want non-nil")
	}
	if params.ChallengeMethod != "S256" {
		t.Errorf("ChallengeMethod = %q, want %q", params.ChallengeMethod, "S256")
	}
	if params.Verifier == "" {
		t.Error("Verifier is empty, want non-empty")
	}
	if params.Challenge == "" {
		t.Error("Challenge is empty, want non-empty")
	}
}
