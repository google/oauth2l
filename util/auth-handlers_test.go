//
// Copyright 2020 Google Inc.
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
	"errors"
	"os"
	"testing"
	"time"
)

type fakeAuthCodeServer struct {
	listening     bool
	authCode      AuthorizationCode
	authErr       error
	waitedConsent bool
}

func (f *fakeAuthCodeServer) ListenAndServe(address string) (string, error) {
	return address, nil
}

func (f *fakeAuthCodeServer) Close() {}

func (f *fakeAuthCodeServer) IsListeningAndServing() bool {
	return f.listening
}

func (f *fakeAuthCodeServer) WaitForListeningAndServing(maxWaitTime time.Duration) (bool, error) {
	return f.listening, nil
}

func (f *fakeAuthCodeServer) GetAuthenticationCode() (AuthorizationCode, error) {
	return f.authCode, f.authErr
}

func (f *fakeAuthCodeServer) WaitForConsentPageToReturnControl() error {
	f.waitedConsent = true
	return nil
}

func TestGet3LOAuthHandlerLoopback(t *testing.T) {
	fakeSrv := &fakeAuthCodeServer{
		listening: true,
		authCode: AuthorizationCode{
			Code:  "loopback-code",
			State: "loopback-state",
		},
	}
	var srv AuthorizationCodeServer = fakeSrv
	consentSettings := ConsentPageSettings{
		DisableAutoOpenConsentPage: true,
		InteractionTimeout:         time.Second,
	}

	handler := Get3LOAuthHandler("unused-oob-state", consentSettings, &srv)
	authURL := "https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080"

	code, state, err := handler(authURL)
	if err != nil {
		t.Fatalf("Get3LOAuthHandler() unexpected error = %v", err)
	}
	if !fakeSrv.waitedConsent {
		t.Error("expected WaitForConsentPageToReturnControl to be called")
	}
	if code != "loopback-code" || state != "loopback-state" {
		t.Errorf("Get3LOAuthHandler() = (%q, %q), want (%q, %q)", code, state, "loopback-code", "loopback-state")
	}
}

func TestGet3LOAuthHandlerLoopbackError(t *testing.T) {
	wantErr := errors.New("consent denied")
	fakeSrv := &fakeAuthCodeServer{
		listening: false,
		authErr:   wantErr,
	}
	var srv AuthorizationCodeServer = fakeSrv
	consentSettings := ConsentPageSettings{
		DisableAutoOpenConsentPage: true,
	}

	handler := Get3LOAuthHandler("state", consentSettings, &srv)
	authURL := "https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080"

	_, _, err := handler(authURL)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Get3LOAuthHandler() error = %v, want %v", err, wantErr)
	}
}

func TestGet3LOAuthHandlerOutOfBand(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		os.Stdin = origStdin
		r.Close()
	}()

	if _, err := w.WriteString("oob-auth-code\n"); err != nil {
		t.Fatalf("WriteString() failed: %v", err)
	}
	w.Close()

	var srv AuthorizationCodeServer
	handler := Get3LOAuthHandler("oob-state", ConsentPageSettings{}, &srv)
	authURL := "https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=urn%3Aietf%3Awg%3Aoauth%3A2.0%3Aoob"

	code, state, err := handler(authURL)
	if err != nil {
		t.Fatalf("Get3LOAuthHandler() unexpected error = %v", err)
	}
	if code != "oob-auth-code" || state != "oob-state" {
		t.Errorf("Get3LOAuthHandler() = (%q, %q), want (%q, %q)", code, state, "oob-auth-code", "oob-state")
	}
}

func TestGet3LOAuthorizationHandlerDelegatesToGet3LOAuthHandler(t *testing.T) {
	fakeSrv := &fakeAuthCodeServer{
		listening: true,
		authCode: AuthorizationCode{
			Code:  "legacy-loopback-code",
			State: "legacy-loopback-state",
		},
	}
	var srv AuthorizationCodeServer = fakeSrv
	consentSettings := ConsentPageSettings{
		DisableAutoOpenConsentPage: true,
		InteractionTimeout:         time.Second,
	}

	handler := Get3LOAuthorizationHandler("state", consentSettings, &srv)
	authURL := "https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=http%3A%2F%2Flocalhost%3A8080"

	code, state, err := handler(authURL)
	if err != nil {
		t.Fatalf("Get3LOAuthorizationHandler() unexpected error = %v", err)
	}
	if code != "legacy-loopback-code" || state != "legacy-loopback-state" {
		t.Errorf("Get3LOAuthorizationHandler() = (%q, %q), want (%q, %q)", code, state, "legacy-loopback-code", "legacy-loopback-state")
	}
}
