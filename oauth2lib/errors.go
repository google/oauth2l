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
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrorKind says why a refresh failed.
type ErrorKind int

const (
	// KindUnknown is any failure that matches no other kind, including an
	// error the client got while verifying the server's certificate.
	KindUnknown ErrorKind = iota
	// KindReauthRequired means the token endpoint returned invalid_grant with
	// error_subtype rapt_required or invalid_rapt: the user must complete a
	// reauthentication challenge to get a new RAPT.
	KindReauthRequired
	// KindAccessDenied means the token endpoint returned access_denied
	// (including Context-Aware Access denials), or the server rejected the
	// client certificate during the TLS handshake.
	KindAccessDenied
	// KindInvalidGrant means the grant was revoked or expired, or the token
	// endpoint returned another OAuth error that retrying won't fix.
	KindInvalidGrant
	// KindTransient means a network error, or HTTP 5xx, 408 or 429.
	KindTransient
)

// String returns a short name for the kind, such as "reauth required".
func (k ErrorKind) String() string {
	switch k {
	case KindReauthRequired:
		return "reauth required"
	case KindAccessDenied:
		return "access denied"
	case KindInvalidGrant:
		return "invalid grant"
	case KindTransient:
		return "transient"
	default:
		return "unknown"
	}
}

// Sentinel errors. A *RefreshError matches (errors.Is) the sentinel for its
// Kind. KindUnknown has no sentinel.
var (
	ErrReauthRequired = errors.New("oauth2lib: reauthentication required")
	// ErrAccessDenied also lets a caller mark local client-certificate
	// failures as access denied: if the client's certificate callback
	// (tls.Config.GetClientCertificate) or signer returns an error that
	// wraps ErrAccessDenied, the request fails with KindAccessDenied
	// instead of KindTransient, so it is not retried.
	ErrAccessDenied = errors.New("oauth2lib: access denied")
	// ErrCAADenied matches a *RefreshError whose token endpoint response was
	// access_denied with "Account restricted" in the description, which is
	// how Context-Aware Access reports a blocked request. Such an error also
	// matches ErrAccessDenied. A rejected client certificate does not match
	// ErrCAADenied.
	ErrCAADenied    = errors.New("oauth2lib: denied by context-aware access")
	ErrInvalidGrant = errors.New("oauth2lib: invalid grant")
	ErrTransient    = errors.New("oauth2lib: transient error")
)

// caaDeniedDescription is the text Python gcloud looks for to detect a
// Context-Aware Access denial
// (context_aware.CONTEXT_AWARE_ACCESS_DENIED_ERROR_DESCRIPTION).
const caaDeniedDescription = "Account restricted"

// RefreshError carries the token endpoint's or IAM's answer to a failed
// request, or the network error that stopped it.
//
// In errors that oauth2lib returns, Code, Subtype and Description hold the
// server's text with token-like strings (access tokens, refresh tokens,
// client secrets, JWTs) replaced with "[REDACTED]", so they are safe to show
// or log as they are. Error, String and LogValue also redact Err's text and
// shorten long fields.
//
// Only a canceled or expired caller context is returned as the context's
// error rather than a *RefreshError. To tell whether the caller's own
// context ended, check ctx.Err(), not errors.Is(err, context.DeadlineExceeded).
type RefreshError struct {
	Kind ErrorKind
	// Code is the OAuth "error" field, or the google.rpc.Status "status"
	// field (for example "PERMISSION_DENIED") for IAM errors.
	Code string
	// Subtype is the OAuth "error_subtype" field.
	Subtype string
	// Description is the OAuth "error_description" field, or the
	// google.rpc.Status "message" field.
	Description string
	// StatusCode is the HTTP status code, or 0 if no response was received.
	StatusCode int
	// Err is the underlying transport error, such as a network error or a
	// timeout, if any. It is not redacted, but it never holds response
	// bodies, and Error and LogValue redact its text.
	Err error
}

// Error implements the error interface.
func (e *RefreshError) Error() string {
	var b strings.Builder
	b.WriteString("oauth2lib: refresh failed (")
	b.WriteString(e.Kind.String())
	b.WriteString(")")
	if c := sanitize(e.Code); c != "" {
		b.WriteString(": ")
		b.WriteString(c)
		if st := sanitize(e.Subtype); st != "" {
			b.WriteString(" (" + st + ")")
		}
	}
	if d := sanitize(e.Description); d != "" {
		b.WriteString(": ")
		b.WriteString(d)
	}
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, " [HTTP %d]", e.StatusCode)
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(sanitize(e.Err.Error()))
	}
	return b.String()
}

// String returns the same text as Error.
func (e *RefreshError) String() string { return e.Error() }

// Unwrap returns Err.
func (e *RefreshError) Unwrap() error { return e.Err }

// Is reports whether target is the sentinel error for e.Kind.
func (e *RefreshError) Is(target error) bool {
	switch e.Kind {
	case KindReauthRequired:
		return target == ErrReauthRequired
	case KindAccessDenied:
		return target == ErrAccessDenied || (target == ErrCAADenied && e.isCAADenied())
	case KindInvalidGrant:
		return target == ErrInvalidGrant
	case KindTransient:
		return target == ErrTransient
	}
	return false
}

// isCAADenied reports whether e is a Context-Aware Access denial, using the
// same check as Python gcloud's IsContextAwareAccessDeniedError.
func (e *RefreshError) isCAADenied() bool {
	return e.Code == "access_denied" && strings.Contains(e.Description, caaDeniedDescription)
}

// LogValue implements slog.LogValuer, with the same redaction as Error.
func (e *RefreshError) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("kind", e.Kind.String())}
	if c := sanitize(e.Code); c != "" {
		attrs = append(attrs, slog.String("code", c))
	}
	if st := sanitize(e.Subtype); st != "" {
		attrs = append(attrs, slog.String("subtype", st))
	}
	if d := sanitize(e.Description); d != "" {
		attrs = append(attrs, slog.String("description", d))
	}
	if e.StatusCode != 0 {
		attrs = append(attrs, slog.Int("status", e.StatusCode))
	}
	if e.Err != nil {
		attrs = append(attrs, slog.String("err", sanitize(e.Err.Error())))
	}
	return slog.GroupValue(attrs...)
}

const maxDescriptionLen = 300

// secretPatterns match strings that look like Google credentials.
var secretPatterns = []string{
	`ya29\.[0-9A-Za-z._-]+`,                             // OAuth 2.0 access token
	`1//[0-9A-Za-z._-]+`,                                // refresh token
	`1%2[Ff]%2[Ff][0-9A-Za-z.%_-]+`,                     // URL-encoded refresh token (form or query value)
	`GOCSPX-[0-9A-Za-z._-]+`,                            // OAuth client secret
	`eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]*`, // JWT (ID token or signed assertion)
}

var secretPattern = regexp.MustCompile(strings.Join(secretPatterns, "|"))

// redact replaces token-like strings in s with "[REDACTED]".
func redact(s string) string {
	return secretPattern.ReplaceAllString(s, "[REDACTED]")
}

// sanitize redacts s and shortens it.
func sanitize(s string) string {
	s = redact(s)
	if len(s) > maxDescriptionLen {
		n := maxDescriptionLen
		for n > 0 && !utf8.RuneStart(s[n]) {
			n-- // don't cut a multi-byte character in half
		}
		s = s[:n] + "..."
	}
	return s
}

// nonRetryableOAuthErrors are the OAuth error codes that mean retrying the
// same request will fail again (Python gcloud's _NON_RETRYABLE_OAUTH_ERRORS).
var nonRetryableOAuthErrors = map[string]bool{
	"invalid_grant":          true,
	"invalid_client":         true,
	"invalid_scope":          true,
	"invalid_request":        true,
	"unauthorized_client":    true,
	"unsupported_grant_type": true,
}

// retryableOAuthErrors are the OAuth error codes that report a temporary
// server-side problem, whatever the HTTP status (google-auth's _can_retry).
var retryableOAuthErrors = map[string]bool{
	"internal_failure":        true,
	"server_error":            true,
	"temporarily_unavailable": true,
}

// classifyResponse turns a non-2xx response from the token endpoint or IAM
// into a *RefreshError. It checks the status code before parsing the body,
// so a 5xx, 408 or 429 is transient whatever the body says. The OAuth codes
// internal_failure, server_error and temporarily_unavailable are transient
// too, in either the "error" or the "error_description" field, as in
// google-auth. Code, Subtype and Description are redacted. The body may be
// an RFC 6749 error ({"error": "...", "error_subtype": ..., "error_description": ...})
// or a google.rpc.Status error ({"error": {"code", "message", "status"}}).
func classifyResponse(statusCode int, body []byte) *RefreshError {
	e := &RefreshError{Kind: KindUnknown, StatusCode: statusCode}
	parseErrorBody(body, e)
	e.Code, e.Subtype, e.Description = redact(e.Code), redact(e.Subtype), redact(e.Description)
	switch {
	case statusCode >= 500, statusCode == http.StatusRequestTimeout, statusCode == http.StatusTooManyRequests,
		retryableOAuthErrors[e.Code], retryableOAuthErrors[e.Description]:
		e.Kind = KindTransient
	case e.Code == "invalid_grant" && (e.Subtype == "rapt_required" || e.Subtype == "invalid_rapt"):
		e.Kind = KindReauthRequired
	case e.Code == "access_denied":
		e.Kind = KindAccessDenied
	case nonRetryableOAuthErrors[e.Code]:
		e.Kind = KindInvalidGrant
	}
	return e
}

// parseErrorBody fills e's Code, Subtype and Description from either error
// body form. A body that is not JSON (for example a proxy's HTML page) leaves
// them empty. A field of an unexpected type is ignored without losing the
// other fields, and error_subtype and error_description are read even when
// "error" is missing.
func parseErrorBody(body []byte, e *RefreshError) {
	var raw struct {
		Error            json.RawMessage `json:"error"`
		ErrorSubtype     json.RawMessage `json:"error_subtype"`
		ErrorDescription json.RawMessage `json:"error_description"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return
	}
	e.Subtype = jsonString(raw.ErrorSubtype)
	e.Description = jsonString(raw.ErrorDescription)
	if len(raw.Error) == 0 {
		return
	}
	var code string
	if json.Unmarshal(raw.Error, &code) == nil {
		e.Code = code
		return
	}
	var status struct {
		Message string `json:"message"`
		Status  string `json:"status"`
	}
	if json.Unmarshal(raw.Error, &status) == nil {
		e.Code, e.Description = status.Status, status.Message
	}
}

// jsonString returns v decoded as a JSON string, or "" if v is missing or not
// a string.
func jsonString(v json.RawMessage) string {
	var s string
	if len(v) == 0 || json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}

// clientCertAlerts are the TLS alerts a server sends when it rejects the
// client certificate (or the lack of one).
// The text comes from tls.AlertError, so it always matches what crypto/tls
// reports for a remote alert (RFC 8446 section 6.2).
var clientCertAlerts = []string{
	tls.AlertError(42).Error(),  // bad_certificate
	tls.AlertError(43).Error(),  // unsupported_certificate
	tls.AlertError(44).Error(),  // certificate_revoked
	tls.AlertError(45).Error(),  // certificate_expired
	tls.AlertError(46).Error(),  // certificate_unknown
	tls.AlertError(48).Error(),  // unknown_ca
	tls.AlertError(49).Error(),  // access_denied
	tls.AlertError(116).Error(), // certificate_required
}

// classifyTransportError turns an error from http.Client.Do into the error
// that Token returns. Only a canceled or expired ctx returns ctx's error
// instead of a *RefreshError. Other timeouts, such as http.Client.Timeout,
// are transient, and their error no longer matches context.DeadlineExceeded
// (or context.Canceled), so a caller can't mistake them for its own context
// ending. An error that wraps ErrAccessDenied (for example from the client's
// certificate callback) is access denied.
func classifyTransportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	kind := KindTransient
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var opErr *net.OpError
	switch {
	case errors.Is(err, ErrAccessDenied):
		// The caller's certificate callback or signer refused to provide a
		// client certificate, for example because the device is not trusted.
		kind = KindAccessDenied
	case errors.As(err, &verifyErr), errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameErr), errors.As(err, &certInvalid):
		// The client rejected the server's certificate, for example behind a
		// TLS-inspecting proxy without the proxy's CA. Retrying won't help.
		kind = KindUnknown
	case errors.As(err, &opErr) && opErr.Op == "remote error" && isClientCertAlert(opErr.Err):
		kind = KindAccessDenied
	}
	// Only now keep context errors that didn't come from ctx out of the
	// chain, so errors.Is(err, context.DeadlineExceeded) or context.Canceled
	// only matches when the caller's own context ended. Doing this after
	// choosing kind means an error that also wraps ErrAccessDenied or a
	// certificate error keeps that classification.
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		err = &timeoutError{msg: err.Error()}
	case errors.Is(err, context.Canceled):
		err = errors.New(err.Error())
	}
	return &RefreshError{Kind: kind, Err: err}
}

// timeoutError is a timeout from the HTTP client or dialer, not from the
// caller's context. It keeps the original message and reports Timeout like a
// net.Error, but it does not unwrap to context.DeadlineExceeded.
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string   { return e.msg }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func isClientCertAlert(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, a := range clientCertAlerts {
		if msg == a {
			return true
		}
	}
	return false
}

// maxResponseBody limits how much of a response body is read. A larger 2xx
// body is an error; a larger error body is cut to this size and classified
// by its status.
const maxResponseBody = 1 << 20

// doRequest sends req with client and returns the status code and body of a
// 2xx response. Any failure is returned as classifyTransportError or
// classifyResponse describes.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) (int, []byte, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, classifyTransportError(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return 0, nil, classifyTransportError(ctx, err)
	}
	ok := resp.StatusCode >= 200 && resp.StatusCode <= 299
	if len(body) > maxResponseBody {
		if ok {
			return 0, nil, &RefreshError{
				Kind:       KindUnknown,
				StatusCode: resp.StatusCode,
				Err:        fmt.Errorf("response body exceeded %d bytes", maxResponseBody),
			}
		}
		body = body[:maxResponseBody]
	}
	if !ok {
		return 0, nil, classifyResponse(resp.StatusCode, body)
	}
	return resp.StatusCode, body, nil
}
