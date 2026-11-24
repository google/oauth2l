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
//   - no goroutine left running after a successful, failed or canceled call
//     (goleak.VerifyNone, per case, on top of TestMain's check);
//   - a canceled or expired caller context returned as ctx.Err() itself;
//   - no secret in errors, Config.Logger or stderr, with go/auth's debug
//     logging on (GOOGLE_SDK_GO_LOGGING_LEVEL=debug).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
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

// credKind is one way to get credentials from oauth2lib.
type credKind struct {
	name string
	// tokenReqs and iamReqs are how many requests one Token call sends to
	// the fake server's /token endpoint and to its IAM endpoint.
	tokenReqs, iamReqs int
	// build returns credentials whose requests all go to srv. It may be
	// called from any goroutine.
	build func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error)
}

// credKinds returns every credential type oauth2lib supports.
func credKinds(t *testing.T) []credKind {
	t.Helper()
	// Built here, on the test goroutine, because the helpers call t.Fatal.
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
			build: func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error) {
				return BuildCredentials(ctx, &Config{JSON: user(srv), Client: srv.Client(), Scopes: []string{"s1"}, RAPT: rapt, Logger: logger})
			},
		},
		{
			name:      "service_account",
			tokenReqs: 1,
			build: func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error) {
				return BuildCredentials(ctx, &Config{JSON: sa(srv), Client: srv.Client(), Scopes: []string{"s1"}, Logger: logger})
			},
		},
		{
			name: "service_account_self_signed_jwt",
			build: func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error) {
				return BuildCredentials(ctx, &Config{JSON: saSelfSigned, Client: srv.Client(), Scopes: []string{"s1"}, UseSelfSignedJWT: true, Logger: logger})
			},
		},
		{
			name:      "impersonated_service_account_json",
			tokenReqs: 1,
			iamReqs:   1,
			build: func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error) {
				return BuildCredentials(ctx, &Config{JSON: imp(srv), Client: &http.Client{Transport: iamRedirect{srv}}, Logger: logger})
			},
		},
		{
			name:      "Impersonate",
			tokenReqs: 1,
			iamReqs:   1,
			build: func(ctx context.Context, srv *fakeIAM, logger *slog.Logger) (*auth.Credentials, error) {
				src, err := BuildCredentials(ctx, &Config{JSON: user(srv), Client: srv.Client(), RAPT: rapt, Logger: logger})
				if err != nil {
					return nil, err
				}
				return Impersonate(ctx, &ImpersonationConfig{
					Source:   src,
					Target:   testTarget,
					Scopes:   []string{"s1"},
					Endpoint: srv.URL + "/",
					Client:   srv.Client(),
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

// TestTokenParallel calls Token from many goroutines at once, half on one
// shared *auth.Credentials and half on credentials each goroutine builds from
// the same inputs. Every call must succeed and send its own requests: there
// is no caching and no deduplication of concurrent refreshes.
func TestTokenParallel(t *testing.T) {
	const n = 32
	for _, k := range credKinds(t) {
		t.Run(k.name, func(t *testing.T) {
			srv := newFakeIAM(t)
			k.queue(srv, n, fakeResponse{body: robustTokenBody()}, fakeResponse{body: robustIAMBody()})
			shared, err := k.build(t.Context(), srv, nil)
			if err != nil {
				t.Fatalf("build() error = %v", err)
			}

			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					<-start
					creds := shared
					if i%2 == 1 {
						var err error
						if creds, err = k.build(t.Context(), srv, nil); err != nil {
							t.Errorf("build() in goroutine %d error = %v", i, err)
							return
						}
					}
					tok, err := creds.Token(t.Context())
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
// call that succeeds, fails or is canceled mid-request leaves no goroutine
// behind once the server and its connections are closed. TestMain checks the
// whole package at the end; this names the case that leaks.
func TestTokenNoGoroutineLeak(t *testing.T) {
	scenarios := []struct {
		name                string
		tokenResp, iamResp  fakeResponse
		timeout             time.Duration
		wantErr, wantCtxErr bool
	}{
		{name: "success", tokenResp: fakeResponse{body: robustTokenBody()}, iamResp: fakeResponse{body: robustIAMBody()}},
		{
			name:      "error_response",
			tokenResp: fakeResponse{status: http.StatusBadRequest, body: `{"error":"invalid_grant"}`},
			iamResp:   fakeResponse{status: http.StatusForbidden, body: `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`},
			wantErr:   true,
		},
		{
			name:      "connection_closed",
			tokenResp: fakeResponse{closeConn: true},
			iamResp:   fakeResponse{closeConn: true},
			wantErr:   true,
		},
		{
			name:       "canceled_in_flight",
			tokenResp:  fakeResponse{body: robustTokenBody(), delay: time.Minute},
			iamResp:    fakeResponse{body: robustIAMBody(), delay: time.Minute},
			timeout:    50 * time.Millisecond,
			wantErr:    true,
			wantCtxErr: true,
		},
	}
	for _, k := range credKinds(t) {
		for _, sc := range scenarios {
			if k.tokenReqs == 0 && sc.wantErr {
				continue // self-signed JWT sends no request, so it can't fail this way
			}
			t.Run(k.name+"/"+sc.name, func(t *testing.T) {
				ignore := goleak.IgnoreCurrent()
				func() {
					srv := newFakeIAM(t)
					// A response for each request one Token call sends.
					k.queue(srv, 1, sc.tokenResp, sc.iamResp)
					creds, err := k.build(t.Context(), srv, nil)
					if err != nil {
						t.Fatalf("build() error = %v", err)
					}
					ctx := t.Context()
					if sc.timeout > 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, sc.timeout)
						defer cancel()
					}
					_, err = creds.Token(ctx)
					if gotErr := err != nil; gotErr != sc.wantErr {
						t.Errorf("Token() error = %v, want error: %v", err, sc.wantErr)
					}
					if sc.wantCtxErr && err != ctx.Err() {
						t.Errorf("Token() error = %v, want ctx.Err() = %v", err, ctx.Err())
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
// itself (not wrapped and not a *RefreshError), and returns promptly.
func TestTokenReturnsContextError(t *testing.T) {
	type stage int
	const (
		before    stage = iota // context already done when Token is called
		tokenStep              // done while the token endpoint request is in flight
		iamStep                // done while the IAM request is in flight
	)
	cases := []struct {
		name     string
		stage    stage
		deadline bool // context.WithTimeout, else context.WithCancel
	}{
		{name: "canceled_before_call", stage: before},
		{name: "deadline_before_call", stage: before, deadline: true},
		{name: "canceled_during_token_request", stage: tokenStep},
		{name: "deadline_during_token_request", stage: tokenStep, deadline: true},
		{name: "canceled_during_iam_request", stage: iamStep},
		{name: "deadline_during_iam_request", stage: iamStep, deadline: true},
	}
	for _, k := range credKinds(t) {
		for _, tc := range cases {
			if (tc.stage == tokenStep && k.tokenReqs == 0) || (tc.stage == iamStep && k.iamReqs == 0) {
				continue
			}
			t.Run(k.name+"/"+tc.name, func(t *testing.T) {
				srv := newFakeIAM(t)
				tokenResp := fakeResponse{body: robustTokenBody()}
				iamResp := fakeResponse{body: robustIAMBody()}
				switch tc.stage {
				case tokenStep:
					tokenResp.delay = time.Minute
				case iamStep:
					iamResp.delay = time.Minute
				}
				if tc.stage != before {
					k.queue(srv, 1, tokenResp, iamResp)
				}
				creds, err := k.build(t.Context(), srv, nil)
				if err != nil {
					t.Fatalf("build() error = %v", err)
				}

				var (
					ctx    context.Context
					cancel context.CancelFunc
				)
				wait := 50 * time.Millisecond
				if tc.stage == before {
					wait = 0
				}
				if tc.deadline {
					ctx, cancel = context.WithTimeout(t.Context(), wait)
				} else {
					ctx, cancel = context.WithCancel(t.Context())
					time.AfterFunc(wait, cancel)
				}
				defer cancel()
				if tc.stage == before {
					<-ctx.Done()
				}

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
					t.Errorf("Token() took %v after the context ended, want it to return promptly", elapsed)
				}
			})
		}
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
					creds, err := k.build(t.Context(), srv, logger)
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
