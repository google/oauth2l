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

// The tests in this file run every credential type through the public API
// (BuildCredentials and Impersonate) with the same checks:
//
//   - parallel Token calls on shared and separately built credentials (run
//     with -race), each making its own requests;
//   - no goroutine left running after a successful, failed or canceled call,
//     at the token step or at the IAM step (goleak.VerifyNone, per case, on
//     top of TestMain's check);
//   - a canceled or expired caller context returned as ctx.Err() itself;
//   - a client certificate refused by the caller's certificate callback
//     reported as ErrAccessDenied, with no retry;
//   - no secret in errors, Config.Logger or stderr, with go/auth's debug
//     logging on (GOOGLE_SDK_GO_LOGGING_LEVEL=debug).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"go.uber.org/goleak"
)

// Secrets used by the cases below. Token-like ones are built at run time so
// they don't look like real credentials to secret scanners.
var (
	robustRotatedRT = "1" + "//0grotatedRefreshToken"
	robustIAMToken  = "ya" + "29.c.fakeImpersonatedToken"
	robustRAPT      = "secret-rapt-value"
)

// robustStep is a step of one Token call.
type robustStep int

const (
	stepNone  robustStep = iota
	stepToken            // the token endpoint request
	stepIAM              // the IAM generateAccessToken request
)

func (s robustStep) String() string {
	switch s {
	case stepToken:
		return "token"
	case stepIAM:
		return "iam"
	}
	return "none"
}

// robustTransports are the transports a credKind's requests go through:
// token for the token endpoint (including an impersonation's source), iam
// for IAM. A nil field means srv's own client.
type robustTransports struct{ token, iam http.RoundTripper }

func (tr robustTransports) orDefault(srv *fakeIAM) robustTransports {
	if tr.token == nil {
		tr.token = srv.Client().Transport
	}
	if tr.iam == nil {
		tr.iam = srv.Client().Transport
	}
	return tr
}

// robustRedirect sends requests for iamcredentials.googleapis.com to srv
// through iam, and every other request through token, so that
// impersonated_service_account JSON (which always uses the default IAM
// endpoint) can use separate transports for its two steps.
type robustRedirect struct {
	srv *fakeIAM
	robustTransports
}

func (r robustRedirect) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "iamcredentials.googleapis.com" {
		return r.token.RoundTrip(req)
	}
	u, err := url.Parse(r.srv.URL)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host, req.Host = u.Scheme, u.Host, ""
	return r.iam.RoundTrip(req)
}

// credKind is one way to get credentials from oauth2lib.
type credKind struct {
	name string
	// tokenReqs and iamReqs are how many requests one Token call sends to
	// the fake server's /token endpoint and to its IAM endpoint.
	tokenReqs, iamReqs int
	// build returns credentials whose requests all go to srv, through tr.
	// It calls t.Fatal (through the JSON helpers), so call it only on the
	// test goroutine.
	build func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error)
}

// credKinds returns every credential type oauth2lib supports.
func credKinds(t *testing.T) []credKind {
	t.Helper()
	user := func(srv *fakeIAM) []byte {
		return userJSON(t, map[string]any{
			"token_uri":     srv.URL + "/token",
			"refresh_token": fakeRefreshToken,
			"client_secret": fakeClientSecret,
		})
	}
	sa := func(srv *fakeIAM) []byte { return saJSON(t, map[string]any{"token_uri": srv.URL + "/token"}) }
	saSelfSigned := saJSON(t, nil)
	imp := func(srv *fakeIAM) []byte {
		return impersonatedJSON(t, sa(srv), map[string]any{"scopes": []string{"s1"}})
	}
	rapt := func(context.Context) (string, error) { return robustRAPT, nil }

	return []credKind{
		{
			name:      "authorized_user",
			tokenReqs: 1,
			build: func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error) {
				tr = tr.orDefault(srv)
				return BuildCredentials(ctx, &Config{JSON: user(srv), Client: &http.Client{Transport: tr.token}, Scopes: []string{"s1"}, RAPT: rapt, Logger: logger})
			},
		},
		{
			name:      "service_account",
			tokenReqs: 1,
			build: func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error) {
				tr = tr.orDefault(srv)
				return BuildCredentials(ctx, &Config{JSON: sa(srv), Client: &http.Client{Transport: tr.token}, Scopes: []string{"s1"}, Logger: logger})
			},
		},
		{
			name: "service_account_self_signed_jwt",
			build: func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error) {
				tr = tr.orDefault(srv)
				return BuildCredentials(ctx, &Config{JSON: saSelfSigned, Client: &http.Client{Transport: tr.token}, Scopes: []string{"s1"}, UseSelfSignedJWT: true, Logger: logger})
			},
		},
		{
			name:      "impersonated_service_account_json",
			tokenReqs: 1,
			iamReqs:   1,
			build: func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error) {
				client := &http.Client{Transport: robustRedirect{srv, tr.orDefault(srv)}}
				return BuildCredentials(ctx, &Config{JSON: imp(srv), Client: client, Logger: logger})
			},
		},
		{
			name:      "Impersonate",
			tokenReqs: 1,
			iamReqs:   1,
			build: func(ctx context.Context, srv *fakeIAM, tr robustTransports, logger *slog.Logger) (*auth.Credentials, error) {
				tr = tr.orDefault(srv)
				src, err := BuildCredentials(ctx, &Config{JSON: user(srv), Client: &http.Client{Transport: tr.token}, RAPT: rapt, Logger: logger})
				if err != nil {
					return nil, err
				}
				return Impersonate(ctx, &ImpersonationConfig{
					Source:   src,
					Target:   testTarget,
					Scopes:   []string{"s1"},
					Endpoint: srv.URL + "/",
					Client:   &http.Client{Transport: tr.iam},
					Logger:   logger,
				})
			},
		},
	}
}

// robustTokenBody is a token endpoint answer that works for both user and
// service account grants, with an ID token and a rotated refresh token.
func robustTokenBody() string {
	return fmt.Sprintf(`{"access_token":%q,"expires_in":3600,"id_token":%q,"refresh_token":%q}`,
		fakeAccessToken, fakeJWT, robustRotatedRT)
}

func robustIAMBody() string {
	return fmt.Sprintf(`{"accessToken":%q,"expireTime":%q}`, robustIAMToken, testExpireTime)
}

// queue queues n Token calls' worth of the given responses on srv.
func (k credKind) queue(srv *fakeIAM, n int, tokenResp, iamResp fakeResponse) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for range n * k.tokenReqs {
		srv.tokenResps = append(srv.tokenResps, tokenResp)
	}
	for range n * k.iamReqs {
		srv.iamResps = append(srv.iamResps, iamResp)
	}
}

// hangAt returns the responses for one Token call that hangs at step until
// the client gives up, and a channel closed when that request arrives.
func hangAt(step robustStep) (tokenResp, iamResp fakeResponse, arrived chan struct{}) {
	tokenResp = fakeResponse{body: robustTokenBody()}
	iamResp = fakeResponse{body: robustIAMBody()}
	arrived = make(chan struct{})
	switch step {
	case stepToken:
		tokenResp.delay, tokenResp.arrived = time.Minute, arrived
	case stepIAM:
		iamResp.delay, iamResp.arrived = time.Minute, arrived
	}
	return tokenResp, iamResp, arrived
}

// cancelOnArrival returns a context that is canceled as soon as arrived is
// closed, that is, while that request is in flight.
func cancelOnArrival(parent context.Context, arrived <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		select {
		case <-arrived:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// expiringCtx is a context whose deadline passes when arrived is closed.
// context.WithTimeout can only expire on a timer, which can't promise that
// the request it should interrupt is in flight yet.
type expiringCtx struct {
	context.Context // for Value
	arrived         <-chan struct{}
}

func (c expiringCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c expiringCtx) Done() <-chan struct{}       { return c.arrived }
func (c expiringCtx) Err() error {
	select {
	case <-c.arrived:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// TestTokenParallel calls Token from many goroutines at once, half on one
// shared *auth.Credentials and half on credentials built for each call from
// the same inputs. Every call must succeed and send its own requests: there
// is no caching and no deduplication of concurrent refreshes.
func TestTokenParallel(t *testing.T) {
	const n = 32
	for _, k := range credKinds(t) {
		t.Run(k.name, func(t *testing.T) {
			srv := newFakeIAM(t)
			k.queue(srv, n, fakeResponse{body: robustTokenBody()}, fakeResponse{body: robustIAMBody()})
			shared, err := k.build(t.Context(), srv, robustTransports{}, nil)
			if err != nil {
				t.Fatalf("build() error = %v", err)
			}
			// Built here, not in the goroutines, because build calls t.Fatal.
			creds := make([]*auth.Credentials, n)
			for i := range creds {
				creds[i] = shared
				if i%2 == 1 {
					if creds[i], err = k.build(t.Context(), srv, robustTransports{}, nil); err != nil {
						t.Fatalf("build() for call %d error = %v", i, err)
					}
				}
			}

			start := make(chan struct{})
			var wg sync.WaitGroup
			for i, c := range creds {
				wg.Go(func() {
					<-start
					tok, err := c.Token(t.Context())
					if err != nil {
						t.Errorf("Token() in goroutine %d error = %v", i, err)
						return
					}
					if tok.Value == "" {
						t.Errorf("Token() in goroutine %d returned an empty token", i)
					}
				})
			}
			close(start)
			wg.Wait()

			if got, want := len(srv.forms()), n*k.tokenReqs; got != want {
				t.Errorf("token endpoint got %d requests, want %d (one per Token call)", got, want)
			}
			if got, want := len(srv.requests()), n*k.iamReqs; got != want {
				t.Errorf("IAM got %d requests, want %d (one per Token call)", got, want)
			}
		})
	}
}

// TestTokenNoGoroutineLeak checks, for every credential type, that a Token
// call that succeeds, fails or is canceled mid-request, at the token step or
// at the IAM step, leaves no goroutine behind once the server and its
// connections are closed. TestMain checks the whole package at the end; this
// names the case that leaks.
func TestTokenNoGoroutineLeak(t *testing.T) {
	okTok := fakeResponse{body: robustTokenBody()}
	okIAM := fakeResponse{body: robustIAMBody()}
	scenarios := []struct {
		name               string
		tokenResp, iamResp fakeResponse
		failAt             robustStep // the step that fails; stepNone for success
		cancelAt           robustStep // the step in flight when the context is canceled
	}{
		{name: "success", tokenResp: okTok, iamResp: okIAM},
		{name: "token_error_response", tokenResp: fakeResponse{status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`}, failAt: stepToken},
		{name: "token_connection_closed", tokenResp: fakeResponse{closeConn: true}, failAt: stepToken},
		{name: "canceled_during_token_request", failAt: stepToken, cancelAt: stepToken},
		{name: "iam_error_response", tokenResp: okTok, iamResp: fakeResponse{status: http.StatusForbidden, body: `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`}, failAt: stepIAM},
		{name: "iam_connection_closed", tokenResp: okTok, iamResp: fakeResponse{closeConn: true}, failAt: stepIAM},
		{name: "canceled_during_iam_request", failAt: stepIAM, cancelAt: stepIAM},
	}
	for _, k := range credKinds(t) {
		for _, sc := range scenarios {
			if (sc.failAt == stepToken && k.tokenReqs == 0) || (sc.failAt == stepIAM && k.iamReqs == 0) {
				continue // the credential type has no such step
			}
			t.Run(k.name+"/"+sc.name, func(t *testing.T) {
				ignore := goleak.IgnoreCurrent()
				func() {
					srv := newFakeIAM(t)
					tokenResp, iamResp := sc.tokenResp, sc.iamResp
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					if sc.cancelAt != stepNone {
						var arrived chan struct{}
						tokenResp, iamResp, arrived = hangAt(sc.cancelAt)
						ctx, cancel = cancelOnArrival(t.Context(), arrived)
						defer cancel()
					}
					// A response for each request one Token call sends.
					k.queue(srv, 1, tokenResp, iamResp)
					creds, err := k.build(t.Context(), srv, robustTransports{}, nil)
					if err != nil {
						t.Fatalf("build() error = %v", err)
					}
					_, err = creds.Token(ctx)
					if gotErr, wantErr := err != nil, sc.failAt != stepNone; gotErr != wantErr {
						t.Errorf("Token() error = %v, want error: %v", err, wantErr)
					}
					if sc.cancelAt != stepNone && err != context.Canceled {
						t.Errorf("Token() error = %v, want context.Canceled", err)
					}
					srv.Close()
					srv.Client().CloseIdleConnections()
				}()
				goleak.VerifyNone(t, ignore)
			})
		}
	}
}

// TestTokenReturnsContextError checks that when the caller's context is
// canceled or expires, before or during a request, Token returns ctx.Err()
// itself (not wrapped and not a *RefreshError), and returns promptly. The
// "during" cases end the context only once that request has reached the
// server, so they test the step they name.
func TestTokenReturnsContextError(t *testing.T) {
	cases := []struct {
		name     string
		during   robustStep // stepNone: the context is done before the call
		deadline bool       // the context expires, else it is canceled
	}{
		{name: "canceled_before_call"},
		{name: "deadline_before_call", deadline: true},
		{name: "canceled_during_token_request", during: stepToken},
		{name: "deadline_during_token_request", during: stepToken, deadline: true},
		{name: "canceled_during_iam_request", during: stepIAM},
		{name: "deadline_during_iam_request", during: stepIAM, deadline: true},
	}
	for _, k := range credKinds(t) {
		for _, tc := range cases {
			if (tc.during == stepToken && k.tokenReqs == 0) || (tc.during == stepIAM && k.iamReqs == 0) {
				continue
			}
			t.Run(k.name+"/"+tc.name, func(t *testing.T) {
				srv := newFakeIAM(t)
				var arrived chan struct{}
				if tc.during != stepNone {
					var tokenResp, iamResp fakeResponse
					tokenResp, iamResp, arrived = hangAt(tc.during)
					k.queue(srv, 1, tokenResp, iamResp)
				}
				creds, err := k.build(t.Context(), srv, robustTransports{}, nil)
				if err != nil {
					t.Fatalf("build() error = %v", err)
				}

				var (
					ctx    context.Context
					cancel context.CancelFunc = func() {}
				)
				switch {
				case tc.during == stepNone && tc.deadline:
					ctx, cancel = context.WithTimeout(t.Context(), 0)
					<-ctx.Done()
				case tc.during == stepNone:
					ctx, cancel = context.WithCancel(t.Context())
					cancel()
				case tc.deadline:
					ctx = expiringCtx{Context: t.Context(), arrived: arrived}
				default:
					ctx, cancel = cancelOnArrival(t.Context(), arrived)
				}
				defer cancel()

				begin := time.Now()
				tok, err := creds.Token(ctx)
				elapsed := time.Since(begin)
				if tok != nil {
					t.Errorf("Token() = %v, want nil", tok)
				}
				want := context.Canceled
				if tc.deadline {
					want = context.DeadlineExceeded
				}
				if err != want {
					t.Errorf("Token() error = %#v (%v), want %v itself", err, err, want)
				}
				var re *RefreshError
				if errors.As(err, &re) {
					t.Errorf("Token() error = %v is a *RefreshError, want the context error", err)
				}
				if elapsed > 10*time.Second {
					t.Errorf("Token() took %v, want it to return promptly", elapsed)
				}
				// The context ended while the named request was in flight.
				wantTokenReqs, wantIAMReqs := 0, 0
				switch tc.during {
				case stepToken:
					wantTokenReqs = 1
				case stepIAM:
					wantTokenReqs, wantIAMReqs = 1, 1
				}
				if got := len(srv.forms()); got != wantTokenReqs {
					t.Errorf("token endpoint got %d requests, want %d", got, wantTokenReqs)
				}
				if got := len(srv.requests()); got != wantIAMReqs {
					t.Errorf("IAM got %d requests, want %d", got, wantIAMReqs)
				}
			})
		}
	}
}

// newRobustTLSServer is a fakeIAM served over TLS that asks for (but doesn't
// require) a client certificate.
func newRobustTLSServer(t *testing.T) *fakeIAM {
	t.Helper()
	f := &fakeIAM{t: t}
	f.Server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.Server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	f.Server.StartTLS()
	t.Cleanup(f.Close)
	return f
}

// certCallbackTransport returns a transport to srv whose client certificate
// callback either sends no certificate or, if refuse is set, refuses the way
// Go gcloud's ECP callback does: with an error wrapping ErrAccessDenied. The
// counter counts the callback's calls, one per TLS handshake.
func certCallbackTransport(t *testing.T, srv *fakeIAM, refuse bool) (*http.Transport, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		calls.Add(1)
		if refuse {
			return nil, fmt.Errorf("ecp: device not trusted: %w", ErrAccessDenied)
		}
		return &tls.Certificate{}, nil
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr, &calls
}

// TestTokenClientCertRefused checks, for every credential type and for each
// step of a Token call, that a client certificate refused by the caller's
// certificate callback is a *RefreshError of KindAccessDenied that matches
// ErrAccessDenied (not ErrCAADenied and not ErrTransient), and that the
// refused request is not retried.
func TestTokenClientCertRefused(t *testing.T) {
	for _, k := range credKinds(t) {
		for _, step := range []robustStep{stepToken, stepIAM} {
			if (step == stepToken && k.tokenReqs == 0) || (step == stepIAM && k.iamReqs == 0) {
				continue
			}
			t.Run(k.name+"/refused_at_"+step.String(), func(t *testing.T) {
				srv := newRobustTLSServer(t)
				if step == stepIAM {
					srv.tokenResps = []fakeResponse{{body: robustTokenBody()}}
				}
				good, _ := certCallbackTransport(t, srv, false)
				refusing, handshakes := certCallbackTransport(t, srv, true)
				tr := robustTransports{token: good, iam: good}
				if step == stepToken {
					tr.token = refusing
				} else {
					tr.iam = refusing
				}
				creds, err := k.build(t.Context(), srv, tr, nil)
				if err != nil {
					t.Fatalf("build() error = %v", err)
				}

				_, err = creds.Token(t.Context())
				var re *RefreshError
				if !errors.As(err, &re) || re.Kind != KindAccessDenied {
					t.Fatalf("Token() error = %v, want a *RefreshError of kind %v", err, KindAccessDenied)
				}
				if !errors.Is(err, ErrAccessDenied) {
					t.Errorf("Token() error = %v, want it to match ErrAccessDenied", err)
				}
				for _, s := range []error{ErrCAADenied, ErrTransient} {
					if errors.Is(err, s) {
						t.Errorf("Token() error = %v matches %v, want it not to", err, s)
					}
				}
				if got := handshakes.Load(); got != 1 {
					t.Errorf("refused TLS handshakes = %d, want 1 (no retry)", got)
				}
				wantTokenReqs := 0
				if step == stepIAM {
					wantTokenReqs = 1
				}
				if got := len(srv.forms()); got != wantTokenReqs {
					t.Errorf("token endpoint got %d requests, want %d", got, wantTokenReqs)
				}
				if got := len(srv.requests()); got != 0 {
					t.Errorf("IAM got %d requests, want 0", got)
				}
			})
		}
	}
}

// refusingSigner is a client certificate key whose signer refuses to sign,
// the way an ECP signer does when the device isn't trusted.
type refusingSigner struct{ crypto.Signer }

func (refusingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("ecp signer: %w", ErrAccessDenied)
}

// refusingClientCert returns a self-signed client certificate whose private
// key refuses to sign.
func refusingClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: refusingSigner{key}}
}

// TestClientCertSignerRefusal records how a refusal from the client
// certificate's signer (not the certificate callback) is classified. In TLS
// 1.2, crypto/tls returns the signer's error as is, so it matches
// ErrAccessDenied. In TLS 1.3, crypto/tls turns it into text
// (handshake_client_tls13.go: errors.New("tls: failed to sign handshake: " +
// err.Error())), so oauth2lib can't see ErrAccessDenied and reports a
// transient error, which callers retry.
//
// TODO: agree with Go gcloud how a TLS 1.3 signer refusal reaches oauth2lib
// (for example, its ECP transport checking the signer before the handshake),
// then expect ErrAccessDenied for TLS 1.3 too.
func TestClientCertSignerRefusal(t *testing.T) {
	cases := []struct {
		name             string
		version          uint16
		wantAccessDenied bool
	}{
		{name: "tls12", version: tls.VersionTLS12, wantAccessDenied: true},
		{name: "tls13", version: tls.VersionTLS13, wantAccessDenied: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("handler reached despite the refused signature")
			}))
			srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tc.version, MaxVersion: tc.version}
			srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the server logs the failed handshake
			srv.StartTLS()
			t.Cleanup(srv.Close)
			tr := srv.Client().Transport.(*http.Transport).Clone()
			tr.TLSClientConfig.Certificates = []tls.Certificate{refusingClientCert(t)}
			t.Cleanup(tr.CloseIdleConnections)

			creds, err := BuildCredentials(t.Context(), &Config{
				JSON:   userJSON(t, map[string]any{"token_uri": srv.URL + "/token"}),
				Client: &http.Client{Transport: tr},
			})
			if err != nil {
				t.Fatalf("BuildCredentials() error = %v", err)
			}
			_, err = creds.Token(t.Context())
			var re *RefreshError
			if !errors.As(err, &re) {
				t.Fatalf("Token() error = %v, want a *RefreshError", err)
			}
			if got := errors.Is(err, ErrAccessDenied); got != tc.wantAccessDenied {
				t.Errorf("errors.Is(err, ErrAccessDenied) = %v, want %v (err = %v)", got, tc.wantAccessDenied, err)
			}
			if got := errors.Is(err, ErrTransient); got == tc.wantAccessDenied {
				t.Errorf("errors.Is(err, ErrTransient) = %v, want %v (err = %v)", got, !tc.wantAccessDenied, err)
			}
		})
	}
}

// TestTokenFailuresLeakNoSecrets checks failed Token calls with go/auth's
// debug logging on: the error (in every format), Config.Logger and stderr
// must not contain any secret, even when the server echoes secrets back in
// its error response.
func TestTokenFailuresLeakNoSecrets(t *testing.T) {
	t.Setenv("GOOGLE_SDK_GO_LOGGING_LEVEL", "debug")
	_, keyPEM := testServiceAccountKey(t)
	keyLine := strings.Split(keyPEM, "\n")[1]
	// The server echoes token-shaped secrets, which redact recognizes. It
	// doesn't echo the RAPT: redact matches token patterns only, and a RAPT
	// has no recognizable shape, so an echoed RAPT would not be redacted.
	// TODO: decide whether RefreshError should also scrub the exact RAPT,
	// refresh token and client secret it sent, then echo them here too.
	echoed := strings.Join([]string{fakeAccessToken, fakeRefreshToken, fakeEncodedRT, fakeClientSecret, fakeJWT, robustRotatedRT, robustIAMToken}, " ")
	secrets := []string{fakeAccessToken, fakeRefreshToken, fakeEncodedRT, fakeClientSecret, fakeJWT,
		robustRotatedRT, robustIAMToken, robustRAPT, "PRIVATE KEY", keyLine, "eyJ", "ya29.", "1//", "GOCSPX-"}

	oauthErr := func(status int, code string) fakeResponse {
		return fakeResponse{status: status, body: fmt.Sprintf(`{"error":%q,"error_subtype":%q,"error_description":%q}`, code, echoed, "bad credentials: "+echoed)}
	}
	iamErr := func(status int, rpcStatus string) fakeResponse {
		return fakeResponse{status: status, body: fmt.Sprintf(`{"error":{"code":%d,"message":%q,"status":%q}}`, status, "denied for "+echoed, rpcStatus)}
	}
	plain := func(status int) fakeResponse {
		return fakeResponse{status: status, contentType: "text/plain", body: "upstream said: " + echoed}
	}
	okTok := fakeResponse{body: robustTokenBody()}

	scenarios := []struct {
		name               string
		tokenResp, iamResp fakeResponse
		iamOnly            bool // needs an IAM step
	}{
		{name: "token_invalid_grant", tokenResp: oauthErr(http.StatusBadRequest, "invalid_grant")},
		{name: "token_access_denied", tokenResp: oauthErr(http.StatusForbidden, "access_denied")},
		{name: "token_plain_text_500", tokenResp: plain(http.StatusInternalServerError)},
		{name: "token_success_body_not_json", tokenResp: fakeResponse{contentType: "text/plain", body: echoed}},
		{name: "token_connection_closed", tokenResp: fakeResponse{closeConn: true}},
		{name: "iam_permission_denied", tokenResp: okTok, iamResp: iamErr(http.StatusForbidden, "PERMISSION_DENIED"), iamOnly: true},
		{name: "iam_unauthenticated", tokenResp: okTok, iamResp: iamErr(http.StatusUnauthorized, "UNAUTHENTICATED"), iamOnly: true},
		{name: "iam_plain_text_503", tokenResp: okTok, iamResp: plain(http.StatusServiceUnavailable), iamOnly: true},
		{name: "iam_connection_closed", tokenResp: okTok, iamResp: fakeResponse{closeConn: true}, iamOnly: true},
	}
	for _, k := range credKinds(t) {
		if k.tokenReqs == 0 {
			continue // self-signed JWT makes no request, so it can't fail at Token
		}
		for _, sc := range scenarios {
			if sc.iamOnly && k.iamReqs == 0 {
				continue
			}
			for _, debugLogger := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/debug_logger_%v", k.name, sc.name, debugLogger), func(t *testing.T) {
					srv := newFakeIAM(t)
					k.queue(srv, 1, sc.tokenResp, sc.iamResp)
					var logs bytes.Buffer
					var logger *slog.Logger
					if debugLogger {
						logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
					}
					stderr := captureStderr(t)
					creds, err := k.build(t.Context(), srv, robustTransports{}, logger)
					if err != nil {
						t.Fatalf("build() error = %v", err)
					}
					_, tokErr := creds.Token(t.Context())
					if tokErr == nil {
						t.Fatal("Token() error = nil, want an error")
					}
					// The caller might log the error itself.
					var callerLog bytes.Buffer
					slog.New(slog.NewJSONHandler(&callerLog, nil)).Error("token", "err", tokErr)

					outputs := map[string]string{
						"Error()":       tokErr.Error(),
						"%v":            fmt.Sprintf("%v", tokErr),
						"%+v":           fmt.Sprintf("%+v", tokErr),
						"%#v":           fmt.Sprintf("%#v", tokErr),
						"slog(err)":     callerLog.String(),
						"Config.Logger": logs.String(),
						"stderr":        stderr(),
					}
					var re *RefreshError
					if errors.As(tokErr, &re) {
						outputs["RefreshError fields"] = fmt.Sprintf("%s|%s|%s", re.Code, re.Subtype, re.Description)
					}
					for where, out := range outputs {
						for _, secret := range secrets {
							if strings.Contains(out, secret) {
								t.Errorf("%s contains %q: %s", where, secret, out)
							}
						}
					}
				})
			}
		}
	}
}
