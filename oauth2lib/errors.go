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
	ErrAccessDenied   = errors.New("oauth2lib: access denied")
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
// Error, String and LogValue never include tokens or other secrets: the
// server's description is shortened and token-like strings in it are
// replaced with "[REDACTED]".
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
	// Err is the underlying error, such as a network error, if any.
	Err error
}

// Error implements the error interface.
func (e *RefreshError) Error() string {
	var b strings.Builder
	b.WriteString("oauth2lib: refresh failed (")
	b.WriteString(e.Kind.String())
	b.WriteString(")")
	if e.Code != "" {
		b.WriteString(": ")
		b.WriteString(e.Code)
		if e.Subtype != "" {
			b.WriteString(" (" + e.Subtype + ")")
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
	if e.Code != "" {
		attrs = append(attrs, slog.String("code", e.Code))
	}
	if e.Subtype != "" {
		attrs = append(attrs, slog.String("subtype", e.Subtype))
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

// secretPattern matches strings that look like Google access tokens, refresh
// tokens or JWTs (such as ID tokens or signed assertions).
var secretPattern = regexp.MustCompile(
	`ya29\.[0-9A-Za-z._-]+` +
		`|1//[0-9A-Za-z._-]+` +
		`|eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]*`)

// sanitize replaces token-like strings with "[REDACTED]" and shortens s.
func sanitize(s string) string {
	s = secretPattern.ReplaceAllString(s, "[REDACTED]")
	if len(s) > maxDescriptionLen {
		s = s[:maxDescriptionLen] + "..."
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

// classifyResponse turns a non-2xx response from the token endpoint or IAM
// into a *RefreshError. It checks the status code before parsing the body,
// so a 5xx, 408 or 429 is transient whatever the body says. The body may be
// an RFC 6749 error ({"error": "...", "error_subtype": ..., "error_description": ...})
// or a google.rpc.Status error ({"error": {"code", "message", "status"}}).
func classifyResponse(statusCode int, body []byte) *RefreshError {
	e := &RefreshError{Kind: KindUnknown, StatusCode: statusCode}
	parseErrorBody(body, e)
	switch {
	case statusCode >= 500, statusCode == http.StatusRequestTimeout, statusCode == http.StatusTooManyRequests:
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
// them empty.
func parseErrorBody(body []byte, e *RefreshError) {
	var raw struct {
		Error            json.RawMessage `json:"error"`
		ErrorSubtype     string          `json:"error_subtype"`
		ErrorDescription string          `json:"error_description"`
	}
	if json.Unmarshal(body, &raw) != nil || len(raw.Error) == 0 {
		return
	}
	var code string
	if json.Unmarshal(raw.Error, &code) == nil {
		e.Code, e.Subtype, e.Description = code, raw.ErrorSubtype, raw.ErrorDescription
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
// that Token returns. A canceled or expired ctx returns ctx's error, not a
// *RefreshError.
func classifyTransportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	kind := KindTransient
	var verifyErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	var opErr *net.OpError
	switch {
	case errors.As(err, &verifyErr), errors.As(err, &unknownAuthority),
		errors.As(err, &hostnameErr), errors.As(err, &certInvalid):
		// The client rejected the server's certificate, for example behind a
		// TLS-inspecting proxy without the proxy's CA. Retrying won't help.
		kind = KindUnknown
	case errors.As(err, &opErr) && opErr.Op == "remote error" && isClientCertAlert(opErr.Err):
		kind = KindAccessDenied
	}
	return &RefreshError{Kind: kind, Err: err}
}

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

// maxResponseBody limits how much of a response body is read.
const maxResponseBody = 1 << 20

// doRequest sends req with client and returns the body of a 2xx response.
// Any failure is returned as classifyTransportError or classifyResponse
// describes.
func doRequest(ctx context.Context, client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, classifyTransportError(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, classifyTransportError(ctx, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, classifyResponse(resp.StatusCode, body)
	}
	return body, nil
}
