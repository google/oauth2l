//
// Copyright 2022 Google Inc.
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

	"github.com/google/uuid"
	"golang.org/x/oauth2/authhandler"
)

// GeneratePKCEParams generates a unique PKCE challenge and verifier combination,
// using UUID, SHA256 encryption, and base64 URL encoding with no padding.
func GeneratePKCEParams() *authhandler.PKCEParams {
	verifier := uuid.New().String()
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])

	return &authhandler.PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}
