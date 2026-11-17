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

package oauth2lib

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResponse is a canned answer from fakeServer.
type fakeResponse struct {
	status      int    // 0 means 200
	body        string // sent as JSON unless contentType is set
	contentType string
	closeConn   bool          // close the connection without answering
	delay       time.Duration // wait first; stops early if the client cancels
}

// fakeServer is a minimal fake token endpoint: it answers requests with the
// queued responses in order and records the form of each request.
type fakeServer struct {
	*httptest.Server
	t testing.TB

	mu        sync.Mutex
	responses []fakeResponse
	forms     []url.Values
}

func newFakeServer(t testing.TB, responses ...fakeResponse) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, responses: responses}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	f.mu.Lock()
	f.forms = append(f.forms, r.PostForm)
	if len(f.responses) == 0 {
		f.mu.Unlock()
		f.t.Errorf("fakeServer: unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "no response queued", http.StatusInternalServerError)
		return
	}
	resp := f.responses[0]
	f.responses = f.responses[1:]
	f.mu.Unlock()
	writeFake(f.t, w, r, resp)
}

func writeFake(t testing.TB, w http.ResponseWriter, r *http.Request, resp fakeResponse) {
	if resp.delay > 0 {
		select {
		case <-time.After(resp.delay):
		case <-r.Context().Done():
			return
		}
	}
	if resp.closeConn {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("fakeServer: hijack: %v", err)
			return
		}
		conn.Close()
		return
	}
	ct := resp.contentType
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	if resp.status != 0 {
		w.WriteHeader(resp.status)
	}
	io.WriteString(w, resp.body)
}

func newPost(t *testing.T, u string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader("grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// fakeAccessToken and friends are built at run time so they don't look like
// real credentials to secret scanners.
var (
	fakeAccessToken  = "ya" + "29.a0AfH6SMfakeAccessToken"
	fakeRefreshToken = "1" + "//0gfakeRefreshToken"
	fakeJWT          = "ey" + "JhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
)

func TestClassifyResponse(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantKind ErrorKind
		wantCode string
		wantSub  string
		wantDesc string
	}{
		{"rapt_required", 400, `{"error":"invalid_grant","error_subtype":"rapt_required","error_description":"reauth related error"}`,
			KindReauthRequired, "invalid_grant", "rapt_required", "reauth related error"},
		{"invalid_rapt", 400, `{"error":"invalid_grant","error_subtype":"invalid_rapt"}`,
			KindReauthRequired, "invalid_grant", "invalid_rapt", ""},
		{"invalid_grant", 400, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`,
			KindInvalidGrant, "invalid_grant", "", "Token has been expired or revoked."},
		{"invalid_grant other subtype", 400, `{"error":"invalid_grant","error_subtype":"something_else"}`,
			KindInvalidGrant, "invalid_grant", "something_else", ""},
		{"CAA access_denied 400", 400, `{"error":"access_denied","error_description":"Account restricted"}`,
			KindAccessDenied, "access_denied", "", "Account restricted"},
		{"access_denied 403", 403, `{"error":"access_denied"}`, KindAccessDenied, "access_denied", "", ""},
		{"invalid_client", 401, `{"error":"invalid_client"}`, KindInvalidGrant, "invalid_client", "", ""},
		{"invalid_scope", 400, `{"error":"invalid_scope"}`, KindInvalidGrant, "invalid_scope", "", ""},
		{"invalid_request", 400, `{"error":"invalid_request"}`, KindInvalidGrant, "invalid_request", "", ""},
		{"unauthorized_client", 400, `{"error":"unauthorized_client"}`, KindInvalidGrant, "unauthorized_client", "", ""},
		{"unsupported_grant_type", 400, `{"error":"unsupported_grant_type"}`, KindInvalidGrant, "unsupported_grant_type", "", ""},
		{"500 beats body", 500, `{"error":"invalid_grant"}`, KindTransient, "invalid_grant", "", ""},
		{"503", 503, `{"error":"server_error"}`, KindTransient, "server_error", "", ""},
		{"408", 408, ``, KindTransient, "", "", ""},
		{"429", 429, `{"error":{"code":429,"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED"}}`,
			KindTransient, "RESOURCE_EXHAUSTED", "", "Quota exceeded"},
		{"proxy HTML 502", 502, `<html>Bad Gateway</html>`, KindTransient, "", "", ""},
		{"IAM permission denied", 403, `{"error":{"code":403,"message":"Permission 'iam.serviceAccounts.getAccessToken' denied","status":"PERMISSION_DENIED"}}`,
			KindUnknown, "PERMISSION_DENIED", "", "Permission 'iam.serviceAccounts.getAccessToken' denied"},
		{"IAM not found", 404, `{"error":{"code":404,"message":"Not found; Gaia id not found","status":"NOT_FOUND"}}`,
			KindUnknown, "NOT_FOUND", "", "Not found; Gaia id not found"},
		{"HTML 400", 400, `<html>oops</html>`, KindUnknown, "", "", ""},
		{"unknown OAuth code", 400, `{"error":"something_new"}`, KindUnknown, "something_new", "", ""},
		{"empty body", 401, ``, KindUnknown, "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := classifyResponse(tc.status, []byte(tc.body))
			if e.Kind != tc.wantKind || e.Code != tc.wantCode || e.Subtype != tc.wantSub ||
				e.Description != tc.wantDesc || e.StatusCode != tc.status {
				t.Errorf("classifyResponse(%d, %q) = %+v, want kind %v, code %q, subtype %q, description %q",
					tc.status, tc.body, *e, tc.wantKind, tc.wantCode, tc.wantSub, tc.wantDesc)
			}
		})
	}
}

func TestRefreshErrorIs(t *testing.T) {
	sentinels := map[ErrorKind]error{
		KindReauthRequired: ErrReauthRequired,
		KindAccessDenied:   ErrAccessDenied,
		KindInvalidGrant:   ErrInvalidGrant,
		KindTransient:      ErrTransient,
	}
	all := []error{ErrReauthRequired, ErrAccessDenied, ErrInvalidGrant, ErrTransient}
	for _, kind := range []ErrorKind{KindUnknown, KindReauthRequired, KindAccessDenied, KindInvalidGrant, KindTransient} {
		var err error = fmt.Errorf("wrapped: %w", &RefreshError{Kind: kind})
		for _, s := range all {
			if got, want := errors.Is(err, s), s == sentinels[kind]; got != want {
				t.Errorf("errors.Is(%v error, %v) = %v, want %v", kind, s, got, want)
			}
		}
		var re *RefreshError
		if !errors.As(err, &re) || re.Kind != kind {
			t.Errorf("errors.As(%v error) failed", kind)
		}
	}
}

func TestRefreshErrorUnwrap(t *testing.T) {
	err := &RefreshError{Kind: KindTransient, Err: io.ErrUnexpectedEOF}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Error("errors.Is(err, io.ErrUnexpectedEOF) = false, want true")
	}
	if !errors.Is(err, ErrTransient) {
		t.Error("errors.Is(err, ErrTransient) = false, want true")
	}
}

func TestRefreshErrorText(t *testing.T) {
	e := &RefreshError{
		Kind: KindReauthRequired, Code: "invalid_grant", Subtype: "rapt_required",
		Description: "reauth related error", StatusCode: 400,
	}
	want := "oauth2lib: refresh failed (reauth required): invalid_grant (rapt_required): reauth related error [HTTP 400]"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if e.String() != e.Error() {
		t.Errorf("String() = %q, want Error()", e.String())
	}
}

func TestRefreshErrorRedaction(t *testing.T) {
	desc := fmt.Sprintf("bad token %s, refresh %s, jwt %s", fakeAccessToken, fakeRefreshToken, fakeJWT)
	e := &RefreshError{
		Kind: KindUnknown, Description: desc + strings.Repeat("x", 500), StatusCode: 400,
		Err: fmt.Errorf("transport saw %s", fakeAccessToken),
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("refresh", "err", e)
	for name, text := range map[string]string{"Error": e.Error(), "String": e.String(), "LogValue": logged.String()} {
		for _, secret := range []string{fakeAccessToken, fakeRefreshToken, fakeJWT} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains secret %q: %s", name, secret, text)
			}
		}
		if !strings.Contains(text, "[REDACTED]") {
			t.Errorf("%s has no [REDACTED] marker: %s", name, text)
		}
		if strings.Contains(text, strings.Repeat("x", 400)) {
			t.Errorf("%s was not shortened", name)
		}
	}
	if !strings.Contains(logged.String(), `"kind":"unknown"`) || !strings.Contains(logged.String(), `"status":400`) {
		t.Errorf("LogValue = %s, want kind and status attributes", logged.String())
	}
}

func TestErrorKindString(t *testing.T) {
	for kind, want := range map[ErrorKind]string{
		KindUnknown: "unknown", KindReauthRequired: "reauth required", KindAccessDenied: "access denied",
		KindInvalidGrant: "invalid grant", KindTransient: "transient", ErrorKind(99): "unknown",
	} {
		if got := kind.String(); got != want {
			t.Errorf("ErrorKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}

func TestDoRequestSuccess(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{body: `{"access_token":"x","expires_in":3600}`})
	body, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	if string(body) != `{"access_token":"x","expires_in":3600}` {
		t.Errorf("body = %s", body)
	}
	if got := srv.forms[0].Get("grant_type"); got != "refresh_token" {
		t.Errorf("server got grant_type %q, want refresh_token", got)
	}
}

func TestDoRequestErrorResponse(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{status: 400, body: `{"error":"invalid_grant","error_subtype":"rapt_required"}`})
	_, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("doRequest() error = %v, want ErrReauthRequired", err)
	}
	var re *RefreshError
	if errors.As(err, &re); re.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", re.StatusCode)
	}
}

func TestDoRequestClosedConnection(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{closeConn: true})
	_, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("doRequest() error = %v, want ErrTransient", err)
	}
}

func TestDoRequestContextCanceled(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{delay: time.Hour})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, err := doRequest(ctx, srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("doRequest() error = %v, want context.DeadlineExceeded", err)
	}
	var re *RefreshError
	if errors.As(err, &re) {
		t.Errorf("doRequest() returned %v, want the context error, not a RefreshError", re)
	}
}

func TestDoRequestClientCertRejected(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached without a client certificate")
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// srv.Client trusts the server's certificate but presents no client
	// certificate, so the server rejects the handshake.
	_, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("doRequest() error = %v, want ErrAccessDenied", err)
	}
}

func TestDoRequestServerCertUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)

	_, err := doRequest(t.Context(), client, newPost(t, srv.URL+"/token"))
	var re *RefreshError
	if !errors.As(err, &re) || re.Kind != KindUnknown {
		t.Fatalf("doRequest() error = %v, want a KindUnknown RefreshError", err)
	}
	if errors.Is(err, ErrTransient) {
		t.Error("a server certificate error must not be transient")
	}
}

func TestClassifyTransportErrorTLSAlerts(t *testing.T) {
	tests := []struct {
		alert uint8
		want  ErrorKind
	}{
		{42, KindAccessDenied},  // bad_certificate
		{43, KindAccessDenied},  // unsupported_certificate
		{44, KindAccessDenied},  // certificate_revoked
		{45, KindAccessDenied},  // certificate_expired
		{46, KindAccessDenied},  // certificate_unknown
		{48, KindAccessDenied},  // unknown_ca
		{49, KindAccessDenied},  // access_denied
		{116, KindAccessDenied}, // certificate_required
		{40, KindTransient},     // handshake_failure
		{80, KindTransient},     // internal_error
	}
	for _, tc := range tests {
		alert := tls.AlertError(tc.alert)
		t.Run(alert.Error(), func(t *testing.T) {
			// crypto/tls reports a remote alert as a *net.OpError with
			// Op "remote error" wrapping the alert.
			in := &net.OpError{Op: "remote error", Err: alert}
			err := classifyTransportError(t.Context(), in)
			var re *RefreshError
			if !errors.As(err, &re) || re.Kind != tc.want {
				t.Fatalf("classifyTransportError(%v) = %v, want kind %v", in, err, tc.want)
			}
		})
	}
}

func TestClassifyTransportErrorLocalAlert(t *testing.T) {
	// The same alert text sent by the client, not the server, is not a
	// client certificate rejection.
	in := &net.OpError{Op: "local error", Err: tls.AlertError(42)}
	err := classifyTransportError(t.Context(), in)
	var re *RefreshError
	if !errors.As(err, &re) || re.Kind != KindTransient {
		t.Fatalf("classifyTransportError(%v) = %v, want kind %v", in, err, KindTransient)
	}
}
