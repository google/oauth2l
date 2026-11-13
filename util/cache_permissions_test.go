package util

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

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// The token cache stores OAuth credentials (access/refresh tokens) and embeds the
// full credentials JSON (including service account private keys) in its cache keys.
// It must therefore be written with owner-only permissions (0600), matching the
// convention used by other credential CLIs (gcloud, gh, aws).
const fakeCredentialsJSON = `{"type":"service_account","project_id":"poc","private_key_id":"k1","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQPOCFAKEKEYMATERIALPOCPOCPOCPOCPOC=\n-----END PRIVATE KEY-----\n","client_email":"poc@poc.iam.gserviceaccount.com","client_id":"123"}`

func writeCacheTo(t *testing.T, dir string) string {
	t.Helper()
	CacheLocation = dir + "/.oauth2l"
	settings := &Settings{CredentialsJSON: fakeCredentialsJSON, Scope: "https://www.googleapis.com/auth/cloud-platform"}
	tok := &oauth2.Token{AccessToken: "ya29.poc", RefreshToken: "1//poc", TokenType: "Bearer"}
	if err := InsertCache(settings, tok); err != nil {
		t.Fatalf("InsertCache: %v", err)
	}
	return CacheLocation
}

// TestInsertCacheOwnerOnlyPermissions verifies the cache file is not readable by
// other users on the machine, regardless of umask.
func TestInsertCacheOwnerOnlyPermissions(t *testing.T) {
	dir, err := os.MkdirTemp("", "oauth2l-cache-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p := writeCacheTo(t, dir)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	perm := fi.Mode().Perm()
	if perm != 0600 {
		t.Errorf("cache file permissions = %o, want 0600 (owner-only); cache contains tokens and the credentials JSON", perm)
	}
}

// TestInsertCacheNotWorldReadable verifies a second unprivileged user cannot read
// the cache. Runs the check as `nobody` when executed under root (CI/sudo);
// skipped otherwise.
func TestInsertCacheNotWorldReadable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to drop privileges (run with sudo for this check)")
	}
	dir, err := os.MkdirTemp("/tmp", "oauth2l-cache-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	os.Chmod(dir, 0755) // world-traversable parent, as on shared hosts
	p := writeCacheTo(t, dir)

	out, err := exec.Command("sudo", "-u", "nobody", "cat", p).CombinedOutput()
	if err == nil {
		var cache map[string]string
		leaked := strings.Contains(string(out), "BEGIN PRIVATE KEY")
		if json.Unmarshal(out, &cache) == nil {
			for _, v := range cache {
				if dec, derr := base64.StdEncoding.DecodeString(v); derr == nil && strings.Contains(string(dec), "ya29.poc") {
					leaked = true
				}
			}
		}
		if leaked {
			t.Fatal("FAIL: unprivileged user (nobody) read service account private key / OAuth tokens from the cache")
		}
	}
	// err != nil (permission denied) is the expected, passing outcome.
}

// TestCreateKeyDoesNotStripKeyMaterial documents that the cache key embeds the
// credentials JSON verbatim (only redirect_uris are stripped), which is why the
// cache file must remain owner-only.
func TestCreateKeyDoesNotStripKeyMaterial(t *testing.T) {
	k := createKey(&Settings{CredentialsJSON: fakeCredentialsJSON})
	if !strings.Contains(k.CredentialsJSON, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected credentials JSON to be embedded in cache key for this test to be meaningful")
	}
}
