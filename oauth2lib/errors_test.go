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
	"crypto/x509"
	"encoding/json"
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
	"unicode/utf8"
)

// fakeResponse is a canned answer from fakeServer.
type fakeResponse struct {
	status      int    // 0 means 200
	body        string // sent as JSON unless contentType is set
	contentType string
	closeConn   bool          // close the connection without answering
	delay       time.Duration // wait first; stops early if the client cancels
	// arrived, if set, is closed when the request arrives, so a test can
	// act while the request is in flight. Use each response once.
	arrived chan struct{}
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
	if resp.arrived != nil {
		close(resp.arrived)
	}
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
	fakeClientSecret = "GOC" + "SPX-fakeClientSecret"
	fakeEncodedRT    = "1" + "%2F%2F0gfakeRefreshToken"
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
		{"server_error 400", 400, `{"error":"server_error"}`, KindTransient, "server_error", "", ""},
		{"temporarily_unavailable 400", 400, `{"error":"temporarily_unavailable"}`, KindTransient, "temporarily_unavailable", "", ""},
		{"internal_failure 400", 400, `{"error":"internal_failure"}`, KindTransient, "internal_failure", "", ""},
		{"non-string description", 400, `{"error":"invalid_grant","error_description":{"detail":"x"}}`,
			KindInvalidGrant, "invalid_grant", "", ""},
		{"non-string subtype", 400, `{"error":"invalid_grant","error_subtype":7,"error_description":"expired"}`,
			KindInvalidGrant, "invalid_grant", "", "expired"},
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
		if errors.Is(err, ErrCAADenied) {
			t.Errorf("errors.Is(%v error without a CAA description, ErrCAADenied) = true, want false", kind)
		}
	}
}

func TestRefreshErrorIsCAADenied(t *testing.T) {
	tests := []struct {
		name string
		err  *RefreshError
		want bool
	}{
		{"caa", &RefreshError{Kind: KindAccessDenied, Code: "access_denied", Description: "Account restricted"}, true},
		{"caa_longer_description", &RefreshError{Kind: KindAccessDenied, Code: "access_denied", Description: "Account restricted by policy"}, true},
		{"access_denied_other_description", &RefreshError{Kind: KindAccessDenied, Code: "access_denied", Description: "The user denied access"}, false},
		{"client_cert_rejected", &RefreshError{Kind: KindAccessDenied, Err: errors.New("remote error: tls: certificate required")}, false},
		{"invalid_grant_with_text", &RefreshError{Kind: KindInvalidGrant, Code: "invalid_grant", Description: "Account restricted"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped: %w", tc.err)
			if got := errors.Is(err, ErrCAADenied); got != tc.want {
				t.Errorf("errors.Is(err, ErrCAADenied) = %v, want %v", got, tc.want)
			}
			if tc.want && !errors.Is(err, ErrAccessDenied) {
				t.Error("a CAA denial must also match ErrAccessDenied")
			}
		})
	}
}

func TestClassifyResponseCAADenied(t *testing.T) {
	err := classifyResponse(http.StatusBadRequest, []byte(`{"error":"access_denied","error_description":"Account restricted"}`))
	if !errors.Is(err, ErrCAADenied) || !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("classifyResponse() = %v, want an error matching ErrCAADenied and ErrAccessDenied", err)
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
		Kind: KindUnknown, Description: desc + " " + strings.Repeat("x", 500), StatusCode: 400,
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
	status, body, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if err != nil {
		t.Fatalf("doRequest() error = %v", err)
	}
	if status != 200 || string(body) != `{"access_token":"x","expires_in":3600}` {
		t.Errorf("doRequest() = %d, %s; want 200 and the response body", status, body)
	}
	if got := srv.forms[0].Get("grant_type"); got != "refresh_token" {
		t.Errorf("server got grant_type %q, want refresh_token", got)
	}
}

func TestDoRequestErrorResponse(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{status: 400, body: `{"error":"invalid_grant","error_subtype":"rapt_required"}`})
	_, _, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("doRequest() error = %v, want ErrReauthRequired", err)
	}
	var re *RefreshError
	if !errors.As(err, &re) || re.StatusCode != 400 {
		t.Errorf("doRequest() error = %v, want a *RefreshError with StatusCode 400", err)
	}
}

func TestDoRequestClosedConnection(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{closeConn: true})
	_, _, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("doRequest() error = %v, want ErrTransient", err)
	}
}

func TestDoRequestContextCanceled(t *testing.T) {
	srv := newFakeServer(t, fakeResponse{delay: time.Hour})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	_, _, err := doRequest(ctx, srv.Client(), newPost(t, srv.URL+"/token"))
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
	_, _, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("doRequest() error = %v, want ErrAccessDenied", err)
	}
}

func TestDoRequestServerCertUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: &http.Transport{}}
	t.Cleanup(client.CloseIdleConnections)

	_, _, err := doRequest(t.Context(), client, newPost(t, srv.URL+"/token"))
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

func TestRefreshErrorRedactsCodeAndSubtype(t *testing.T) {
	e := &RefreshError{
		Kind: KindUnknown, Code: "code " + fakeAccessToken, Subtype: "sub " + fakeRefreshToken + " " + strings.Repeat("x", 500),
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("refresh", "err", e)
	for name, text := range map[string]string{"Error()": e.Error(), "slog": logged.String()} {
		if strings.Contains(text, fakeAccessToken) || strings.Contains(text, fakeRefreshToken) {
			t.Errorf("%s = %q, contains a token", name, text)
		}
		if strings.Contains(text, strings.Repeat("x", maxDescriptionLen+1)) {
			t.Errorf("%s = %q, want Subtype shortened to %d bytes", name, text, maxDescriptionLen)
		}
	}
}

func TestClassifyTransportErrorTimeouts(t *testing.T) {
	// A timeout set on the client, not the caller's context, is transient.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	client := &http.Client{Timeout: 50 * time.Millisecond}
	t.Cleanup(client.CloseIdleConnections)

	_, _, err := doRequest(t.Context(), client, newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrTransient) {
		t.Fatalf("doRequest() with http.Client.Timeout error = %v, want ErrTransient", err)
	}
	// A client timeout must not look like the caller's context ending.
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("doRequest() error = %v matches context.DeadlineExceeded, want it not to", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("doRequest() error = %v, want a net.Error with Timeout() true", err)
	}

	// The same error with the caller's context done returns the context error.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := classifyTransportError(ctx, err); got != context.Canceled {
		t.Errorf("classifyTransportError(canceled ctx) = %v, want context.Canceled", got)
	}
}

func TestClassifyTransportErrorWrappedAccessDenied(t *testing.T) {
	in := fmt.Errorf("ecp signer: %w", ErrAccessDenied)
	err := classifyTransportError(t.Context(), in)
	var re *RefreshError
	if !errors.As(err, &re) || re.Kind != KindAccessDenied {
		t.Fatalf("classifyTransportError(%v) = %v, want kind %v", in, err, KindAccessDenied)
	}
	if errors.Is(err, ErrTransient) {
		t.Error("an error wrapping ErrAccessDenied must not be transient")
	}
}

func TestDoRequestClientCertCallbackDenied(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached without a client certificate")
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// The client trusts the server, but its certificate callback refuses to
	// provide a certificate, as an Enterprise Certificate Proxy might.
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, fmt.Errorf("device not trusted: %w", ErrAccessDenied)
	}
	client := &http.Client{Transport: tr}
	t.Cleanup(client.CloseIdleConnections)

	_, _, err := doRequest(t.Context(), client, newPost(t, srv.URL+"/token"))
	var re *RefreshError
	if !errors.As(err, &re) || re.Kind != KindAccessDenied {
		t.Fatalf("doRequest() error = %v, want kind %v", err, KindAccessDenied)
	}
	if errors.Is(err, ErrTransient) {
		t.Error("a refused client certificate must not be transient")
	}
}

func TestClassifyResponseRetryableDescription(t *testing.T) {
	for _, body := range []string{
		`{"error_description":"internal_failure"}`,
		`{"error":"invalid_request","error_description":"temporarily_unavailable"}`,
	} {
		e := classifyResponse(400, []byte(body))
		if e.Kind != KindTransient {
			t.Errorf("classifyResponse(400, %s) kind = %v, want %v", body, e.Kind, KindTransient)
		}
	}
	e := classifyResponse(400, []byte(`{"error_subtype":"s","error_description":"something"}`))
	if e.Kind != KindUnknown || e.Subtype != "s" || e.Description != "something" {
		t.Errorf("classifyResponse without error = %+v, want KindUnknown with subtype and description kept", *e)
	}
}

func TestClassifyResponseRedactsFields(t *testing.T) {
	body := fmt.Sprintf(`{"error":"access_denied","error_subtype":"%s","error_description":"Account restricted; secret %s token %s"}`,
		fakeEncodedRT, fakeClientSecret, fakeAccessToken)
	e := classifyResponse(400, []byte(body))
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"Subtype": e.Subtype, "Description": e.Description, "%#v": fmt.Sprintf("%#v", e), "json": string(b),
	} {
		for _, secret := range []string{fakeEncodedRT, fakeClientSecret, fakeAccessToken} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains secret %q: %s", name, secret, text)
			}
		}
	}
	if !errors.Is(e, ErrCAADenied) {
		t.Errorf("classifyResponse() = %v, want it to still match ErrCAADenied after redaction", e)
	}
}

func TestSanitizeNewPatterns(t *testing.T) {
	for _, secret := range []string{fakeClientSecret, fakeEncodedRT, "1" + "%2f%2f0glowercase"} {
		if got := sanitize("value=" + secret + "&x=1"); strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED]") {
			t.Errorf("sanitize(%q) = %q, want the secret redacted", secret, got)
		}
	}
}

func TestDoRequestOversizedBody(t *testing.T) {
	big := strings.Repeat("a", maxResponseBody+1)
	srv := newFakeServer(t,
		fakeResponse{body: big},
		fakeResponse{status: 502, contentType: "text/html", body: big},
	)
	_, _, err := doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	var re *RefreshError
	if !errors.As(err, &re) || re.Kind != KindUnknown || re.StatusCode != 200 ||
		!strings.Contains(err.Error(), "response body exceeded") {
		t.Errorf("oversized 2xx: doRequest() error = %v, want a KindUnknown size-limit error with status 200", err)
	}
	_, _, err = doRequest(t.Context(), srv.Client(), newPost(t, srv.URL+"/token"))
	if !errors.Is(err, ErrTransient) {
		t.Errorf("oversized 502: doRequest() error = %v, want ErrTransient", err)
	}
}

func TestClassifyTransportErrorForeignContextErrors(t *testing.T) {
	// Context errors that did not come from the caller's ctx are transient
	// and no longer match the context sentinels.
	for _, in := range []error{
		fmt.Errorf("Post %q: %w", "https://example.com/token", context.DeadlineExceeded),
		fmt.Errorf("Post %q: %w", "https://example.com/token", context.Canceled),
	} {
		err := classifyTransportError(t.Context(), in)
		if !errors.Is(err, ErrTransient) {
			t.Errorf("classifyTransportError(%v) = %v, want ErrTransient", in, err)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Errorf("classifyTransportError(%v) = %v, still matches a context sentinel", in, err)
		}
		if !strings.Contains(err.Error(), in.Error()) {
			t.Errorf("classifyTransportError(%v).Error() = %q, want the original message kept", in, err.Error())
		}
	}
	var netErr net.Error
	err := classifyTransportError(t.Context(), context.DeadlineExceeded)
	if !errors.As(err, &netErr) || !netErr.Timeout() || !netErr.Temporary() {
		t.Errorf("classifyTransportError(DeadlineExceeded) = %v, want a timeout net.Error", err)
	}
}

func TestSanitizeKeepsUTF8Valid(t *testing.T) {
	s := strings.Repeat("a", maxDescriptionLen-1) + "é" + strings.Repeat("b", 10)
	got := sanitize(s)
	if !utf8.ValidString(got) {
		t.Errorf("sanitize() = %q, not valid UTF-8", got)
	}
	if !strings.HasSuffix(got, "...") || len(got) > maxDescriptionLen+3 {
		t.Errorf("sanitize() = %q, want it shortened to at most %d bytes plus \"...\"", got, maxDescriptionLen)
	}
}

func TestClassifyTransportErrorKindBeforeDetachingContext(t *testing.T) {
	// An error can wrap both a context error that didn't come from the
	// caller's ctx and a reason not to retry. The reason must win.
	for _, tc := range []struct {
		name string
		in   error
		want ErrorKind
	}{
		{"deadline and ErrAccessDenied",
			errors.Join(context.DeadlineExceeded, fmt.Errorf("ecp signer: %w", ErrAccessDenied)), KindAccessDenied},
		{"canceled and ErrAccessDenied",
			fmt.Errorf("signer: %w: %w", context.Canceled, ErrAccessDenied), KindAccessDenied},
		{"deadline and server certificate error",
			errors.Join(context.DeadlineExceeded, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), KindUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyTransportError(t.Context(), tc.in)
			var re *RefreshError
			if !errors.As(err, &re) || re.Kind != tc.want {
				t.Fatalf("classifyTransportError(%v) = %v, want kind %v", tc.in, err, tc.want)
			}
			if errors.Is(err, ErrTransient) {
				t.Errorf("classifyTransportError(%v) = %v, must not be transient", tc.in, err)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Errorf("classifyTransportError(%v) = %v, still matches a context sentinel", tc.in, err)
			}
			if tc.want == KindAccessDenied && !errors.Is(err, ErrAccessDenied) {
				t.Errorf("classifyTransportError(%v) = %v, want it to match ErrAccessDenied", tc.in, err)
			}
			if !strings.Contains(err.Error(), tc.in.Error()) {
				t.Errorf("classifyTransportError(%v).Error() = %q, want the original message kept", tc.in, err.Error())
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Errorf("classifyTransportError(%v) = %v, must not report a timeout", tc.in, err)
			}
		})
	}

	// The certificate error is still there for errors.As.
	in := errors.Join(context.DeadlineExceeded, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}})
	var verifyErr *tls.CertificateVerificationError
	if err := classifyTransportError(t.Context(), in); !errors.As(err, &verifyErr) {
		t.Errorf("classifyTransportError(%v) = %v, want it to keep the *tls.CertificateVerificationError", in, err)
	}
}
