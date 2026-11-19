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
	"net/http"
	"strings"
	"testing"
	"time"
)

func startLocalhost(t *testing.T, timeout time.Duration) *AuthorizationCodeLocalhost {
	t.Helper()
	lh := &AuthorizationCodeLocalhost{
		ConsentPageSettings: ConsentPageSettings{InteractionTimeout: timeout},
		AuthCodeReqStatus: AuthorizationCodeStatus{
			Status: WAITING, Details: "Authorization code not yet set."},
	}
	if _, err := lh.ListenAndServe("http://localhost"); err != nil {
		t.Fatalf("ListenAndServe() failed: %v", err)
	}
	t.Cleanup(lh.Close)
	if ok, err := lh.WaitForListeningAndServing(10 * time.Second); !ok {
		t.Fatalf("WaitForListeningAndServing() failed: %v", err)
	}
	return lh
}

// redirect sends the request the consent page would send to the loopback
// server, from another goroutine, like the browser does.
func redirect(t *testing.T, lh *AuthorizationCodeLocalhost, query string) {
	t.Helper()
	url := lh.addr + "/?" + query
	go func() {
		resp, err := http.Get(url)
		if err != nil {
			t.Errorf("http.Get(%q) failed: %v", url, err)
			return
		}
		resp.Body.Close()
	}()
}

func TestWaitForConsentPageToReturnControlGranted(t *testing.T) {
	lh := startLocalhost(t, time.Minute)
	redirect(t, lh, "code=test-code&state=test-state")

	start := time.Now()
	if err := lh.WaitForConsentPageToReturnControl(); err != nil {
		t.Fatalf("WaitForConsentPageToReturnControl() = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("WaitForConsentPageToReturnControl() took %v", elapsed)
	}
	code, err := lh.GetAuthenticationCode()
	if err != nil {
		t.Fatalf("GetAuthenticationCode() failed: %v", err)
	}
	if code.Code != "test-code" || code.State != "test-state" {
		t.Errorf("GetAuthenticationCode() = %+v, want test-code/test-state", code)
	}
}

func TestWaitForConsentPageToReturnControlError(t *testing.T) {
	lh := startLocalhost(t, time.Minute)
	redirect(t, lh, "error=access_denied")

	if err := lh.WaitForConsentPageToReturnControl(); err != nil {
		t.Fatalf("WaitForConsentPageToReturnControl() = %v, want nil", err)
	}
	_, err := lh.GetAuthenticationCode()
	if err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("GetAuthenticationCode() error = %v, want access_denied", err)
	}
}

func TestWaitForConsentPageToReturnControlTimeout(t *testing.T) {
	lh := startLocalhost(t, 100*time.Millisecond)

	err := lh.WaitForConsentPageToReturnControl()
	if err == nil || err.Error() != "Timed out." {
		t.Errorf("WaitForConsentPageToReturnControl() = %v, want Timed out.", err)
	}
	if _, err := lh.GetAuthenticationCode(); err == nil {
		t.Errorf("GetAuthenticationCode() = nil error, want an error")
	}
}
