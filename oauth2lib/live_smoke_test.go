// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build smoke

// Live smoke tests for oauth2lib against Google's real token and IAM
// endpoints. They are excluded from normal builds and CI by the smoke build
// tag. Run them from this directory with:
//
//	go test -tags=smoke -race -count=1 -v -run TestSmoke_ .
//
// Each case skips cleanly when its inputs are unset, so set only what you
// have. Only TestSmoke_MTLSAndClientCertRefusal/refusal needs no credentials
// or network: it runs against a local httptest TLS server.
//
// Environment variables (paths point to credential JSON files; keep them
// outside the repository and delete them after the run):
//
//	OAUTH2LIB_SMOKE_USER_JSON                 authorized_user JSON for TestSmoke_AuthorizedUserRefresh
//	OAUTH2LIB_SMOKE_RAPT                      RAPT sent on every authorized_user refresh, including
//	                                          impersonation sources and the live mTLS user
//	OAUTH2LIB_SMOKE_SCOPES                    comma-separated scopes for user and service account refreshes
//	OAUTH2LIB_SMOKE_API_URL                   optional URL for one authenticated GET with each minted token
//	OAUTH2LIB_SMOKE_REAUTH_USER_JSON          authorized_user JSON for an account with a reauth policy
//	OAUTH2LIB_SMOKE_EXPIRED_RAPT              expired RAPT for TestSmoke_ReauthRequired/invalid_rapt
//	OAUTH2LIB_SMOKE_REVOKED_USER_JSON         authorized_user JSON whose refresh token was revoked
//	OAUTH2LIB_SMOKE_SA_JSON                   service_account key JSON (2LO and self-signed JWT)
//	OAUTH2LIB_SMOKE_IMPERSONATE_SOURCE_JSON   source credential JSON (authorized_user or service_account)
//	OAUTH2LIB_SMOKE_IMPERSONATE_TARGET        target service account email
//	OAUTH2LIB_SMOKE_IMPERSONATE_DELEGATES     comma-separated delegate chain for TestSmoke_Impersonate/two_hop
//	OAUTH2LIB_SMOKE_IMPERSONATE_ENDPOINT      IAM Credentials base URL for TestSmoke_Impersonate/custom_endpoint
//	OAUTH2LIB_SMOKE_IMPERSONATE_LIFETIME      optional Go duration, whole seconds from 1s to 12h
//	OAUTH2LIB_SMOKE_IMPERSONATE_SCOPES        comma-separated target scopes, or "gcloud" for gcloud's
//	                                          default scopes; default cloud-platform
//	OAUTH2LIB_SMOKE_IMPERSONATED_SA_JSON      impersonated_service_account JSON
//	OAUTH2LIB_SMOKE_MTLS_USER_JSON            authorized_user JSON for the live mTLS token endpoint
//	OAUTH2LIB_SMOKE_MTLS_CERT_PEM, _KEY_PEM   client certificate and key for the live mTLS case
//
// Do not wrap oauth2lib credentials in cloud.google.com/go/auth/httptransport
// or grpctransport: those packages inject GOOGLE_CLOUD_QUOTA_PROJECT and wrap
// providers in NewCachedTokenProvider. Use an explicit uncached RoundTripper
// (like bearerTransport below) so live smoke tests match gocloud's transport.
package oauth2lib_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth"
	"github.com/google/oauth2l/oauth2lib"
)

const defaultCloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// gcloudDefaultScopes are Python gcloud's CLOUDSDK_SCOPES
// (googlecloudsdk/core/config.py), which Go gcloud passes as
// ImpersonationConfig.Scopes.
var gcloudDefaultScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	defaultCloudPlatformScope,
	"https://www.googleapis.com/auth/appengine.admin",
	"https://www.googleapis.com/auth/sqlservice.login",
	"https://www.googleapis.com/auth/compute",
}

// impersonationScopes returns the target scopes from
// OAUTH2LIB_SMOKE_IMPERSONATE_SCOPES: "gcloud" means gcloudDefaultScopes,
// anything else is a comma-separated list, and unset means cloud-platform.
func impersonationScopes() []string {
	raw := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_IMPERSONATE_SCOPES"))
	switch {
	case raw == "":
		return []string{defaultCloudPlatformScope}
	case strings.EqualFold(raw, "gcloud"):
		return append([]string(nil), gcloudDefaultScopes...)
	default:
		return splitCSVEnv("OAUTH2LIB_SMOKE_IMPERSONATE_SCOPES")
	}
}

// bearerTransport attaches an uncached oauth2lib token to each outbound request
// without introducing cloud.google.com/go/auth's NewCachedTokenProvider or ambient quota headers.
type bearerTransport struct {
	base  http.RoundTripper
	creds *auth.Credentials
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := t.creds.Token(req.Context())
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	tokType := tok.Type
	if tokType == "" {
		tokType = "Bearer"
	}
	r.Header.Set("Authorization", tokType+" "+tok.Value)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

// newSmokeTransport returns a transport owned by t. Its idle keep-alive
// connections are closed when t finishes; otherwise their read loops outlive
// the tests and goleak.VerifyTestMain (main_test.go) fails the package.
func newSmokeTransport(t *testing.T) *http.Transport {
	t.Helper()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func newSmokeHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Timeout: 30 * time.Second, Transport: newSmokeTransport(t)}
}

func readEnvFileOrSkip(t *testing.T, envVar string) []byte {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(envVar))
	if path == "" {
		t.Skipf("set %s to a credential JSON path to run this live smoke test", envVar)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (%q): %v", envVar, path, err)
	}
	return b
}

func splitCSVEnv(envVar string) []string {
	raw := strings.TrimSpace(os.Getenv(envVar))
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// credentialType returns the "type" field of a credential JSON, or "" if it
// can't be read.
func credentialType(b []byte) string {
	var meta struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(b, &meta)
	return meta.Type
}

// withSmokeRAPT sets cfg.RAPT to return OAUTH2LIB_SMOKE_RAPT when cfg builds an
// authorized_user credential, the way Go gcloud passes the stored RAPT on
// every user refresh, including the refresh of an impersonation source.
// Without it, sources on accounts with a reauth policy fail with
// ErrReauthRequired. oauth2lib never forwards a RAPT on its own (see
// ImpersonatedServiceAccount.SourceConfig).
func withSmokeRAPT(cfg *oauth2lib.Config) *oauth2lib.Config {
	if credentialType(cfg.JSON) != "authorized_user" {
		return cfg
	}
	rapt := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_RAPT"))
	cfg.RAPT = func(context.Context) (string, error) { return rapt, nil }
	return cfg
}

func verifyOptionalLiveGET(t *testing.T, ctx context.Context, creds *auth.Credentials, base http.RoundTripper) {
	t.Helper()
	apiURL := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_API_URL"))
	if apiURL == "" {
		return
	}
	if base == nil {
		base = newSmokeTransport(t)
	}
	hc := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &bearerTransport{base: base, creds: creds},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		t.Fatalf("building live API request: %v", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("live API GET %q failed: %v", apiURL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("live API GET %q returned HTTP %d, want 2xx", apiURL, resp.StatusCode)
	}
}

func TestSmoke_AuthorizedUserRefresh(t *testing.T) {
	rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_USER_JSON")
	rapt := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_RAPT"))
	scopes := splitCSVEnv("OAUTH2LIB_SMOKE_SCOPES")

	ctx := t.Context()
	creds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
		JSON:   rawJSON,
		Scopes: scopes,
		Client: newSmokeHTTPClient(t),
		RAPT: func(context.Context) (string, error) {
			return rapt, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildCredentials(authorized_user) failed: %v", err)
	}

	tok, err := creds.Token(ctx)
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if tok == nil || tok.Value == "" {
		t.Fatalf("Token() returned empty access token")
	}
	if tok.Expiry.IsZero() {
		t.Errorf("Token().Expiry is zero, want non-zero expiry")
	}
	if rapt != "" {
		gotRAPT, ok := tok.Metadata[oauth2lib.MetadataRAPT].(string)
		if !ok || gotRAPT != rapt {
			t.Errorf("Metadata[%q] present=%v, want echoed RAPT", oauth2lib.MetadataRAPT, ok)
		}
	}
	if rawID, present := tok.Metadata[oauth2lib.MetadataIDToken]; present {
		if _, ok := rawID.(string); !ok {
			t.Errorf("Metadata[%q] has type %T, want string", oauth2lib.MetadataIDToken, rawID)
		}
	}
	if rawRT, present := tok.Metadata[oauth2lib.MetadataRefreshToken]; present {
		if _, ok := rawRT.(string); !ok {
			t.Errorf("Metadata[%q] has type %T, want string", oauth2lib.MetadataRefreshToken, rawRT)
		}
	}
	t.Logf("authorized_user refresh succeeded (token_type=%q, expires_in=%s, has_id_token=%v, rotated_rt=%v)",
		tok.Type, time.Until(tok.Expiry).Round(time.Second),
		tok.Metadata[oauth2lib.MetadataIDToken] != nil,
		tok.Metadata[oauth2lib.MetadataRefreshToken] != nil)

	verifyOptionalLiveGET(t, ctx, creds, nil)
}

// checkReauthRequired builds rawJSON with rapt as the RAPT and checks that
// Token() fails with KindReauthRequired and the wanted OAuth error_subtype.
func checkReauthRequired(t *testing.T, rawJSON []byte, rapt, wantSubtype string) {
	t.Helper()
	ctx := t.Context()
	creds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
		JSON:   rawJSON,
		Client: newSmokeHTTPClient(t),
		RAPT: func(context.Context) (string, error) {
			return rapt, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildCredentials(reauth user) failed: %v", err)
	}

	_, err = creds.Token(ctx)
	if !errors.Is(err, oauth2lib.ErrReauthRequired) {
		t.Fatalf("Token() err = %v, want errors.Is(ErrReauthRequired)", err)
	}
	if errors.Is(err, oauth2lib.ErrCAADenied) {
		t.Errorf("Token() reauth error unexpectedly matched ErrCAADenied: %v", err)
	}
	if errors.Is(err, oauth2lib.ErrInvalidGrant) {
		t.Errorf("Token() reauth error unexpectedly matched ErrInvalidGrant: %v", err)
	}
	var re *oauth2lib.RefreshError
	if !errors.As(err, &re) || re.Kind != oauth2lib.KindReauthRequired {
		t.Fatalf("Token() err = %v, want *oauth2lib.RefreshError with KindReauthRequired", err)
	}
	if re.Subtype != wantSubtype {
		t.Errorf("RefreshError.Subtype = %q, want %q", re.Subtype, wantSubtype)
	}
}

// TestSmoke_ReauthRequired covers both reauth rows of the error table: no RAPT
// (rapt_required) and an expired RAPT (invalid_rapt), on an account with a
// reauth policy.
func TestSmoke_ReauthRequired(t *testing.T) {
	t.Run("rapt_required", func(t *testing.T) {
		rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_REAUTH_USER_JSON")
		checkReauthRequired(t, rawJSON, "", "rapt_required")
	})

	t.Run("invalid_rapt", func(t *testing.T) {
		rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_REAUTH_USER_JSON")
		expiredRAPT := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_EXPIRED_RAPT"))
		if expiredRAPT == "" {
			t.Skip("set OAUTH2LIB_SMOKE_EXPIRED_RAPT to a RAPT that has expired (older than about 20 hours)")
		}
		checkReauthRequired(t, rawJSON, expiredRAPT, "invalid_rapt")
	})
}

func TestSmoke_RevokedRefreshToken(t *testing.T) {
	rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_REVOKED_USER_JSON")

	ctx := t.Context()
	creds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
		JSON:   rawJSON,
		Client: newSmokeHTTPClient(t),
	})
	if err != nil {
		t.Fatalf("BuildCredentials(revoked user) failed: %v", err)
	}

	_, err = creds.Token(ctx)
	if !errors.Is(err, oauth2lib.ErrInvalidGrant) {
		t.Fatalf("Token() err = %v, want errors.Is(ErrInvalidGrant)", err)
	}
	if errors.Is(err, oauth2lib.ErrReauthRequired) {
		t.Errorf("Token() revoked grant unexpectedly matched ErrReauthRequired: %v", err)
	}
}

func TestSmoke_ServiceAccount(t *testing.T) {
	rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_SA_JSON")
	scopes := splitCSVEnv("OAUTH2LIB_SMOKE_SCOPES")
	if len(scopes) == 0 {
		scopes = []string{defaultCloudPlatformScope}
	}

	for _, selfSigned := range []bool{false, true} {
		mode := "2lo_oauth"
		if selfSigned {
			mode = "self_signed_jwt"
		}
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			creds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
				JSON:             rawJSON,
				Scopes:           scopes,
				UseSelfSignedJWT: selfSigned,
				Client:           newSmokeHTTPClient(t),
			})
			if err != nil {
				t.Fatalf("BuildCredentials(service_account, %s) failed: %v", mode, err)
			}
			tok, err := creds.Token(ctx)
			if err != nil {
				t.Fatalf("Token(%s) failed: %v", mode, err)
			}
			if tok == nil || tok.Value == "" || tok.Expiry.IsZero() {
				t.Fatalf("Token(%s) returned incomplete token (empty=%v, zero_expiry=%v)",
					mode, tok == nil || tok.Value == "", tok == nil || tok.Expiry.IsZero())
			}
			t.Logf("service_account (%s) succeeded (token_type=%q, expires_in=%s)",
				mode, tok.Type, time.Until(tok.Expiry).Round(time.Second))
			verifyOptionalLiveGET(t, ctx, creds, nil)
		})
	}
}

// runDirectImpersonation builds the source from
// OAUTH2LIB_SMOKE_IMPERSONATE_SOURCE_JSON, impersonates
// OAUTH2LIB_SMOKE_IMPERSONATE_TARGET through delegates and endpoint, and checks
// that the impersonated credentials mint a token.
func runDirectImpersonation(t *testing.T, delegates []string, endpoint string) {
	t.Helper()
	srcJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_IMPERSONATE_SOURCE_JSON")
	target := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_IMPERSONATE_TARGET"))
	if target == "" {
		t.Skip("set OAUTH2LIB_SMOKE_IMPERSONATE_TARGET to a service account email")
	}
	var lifetime time.Duration
	if rawLT := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_IMPERSONATE_LIFETIME")); rawLT != "" {
		d, err := time.ParseDuration(rawLT)
		if err != nil {
			t.Fatalf("parsing OAUTH2LIB_SMOKE_IMPERSONATE_LIFETIME %q: %v", rawLT, err)
		}
		lifetime = d
	}

	// Service account sources need IAMScope (or cloud-platform) to call IAM.
	var srcScopes []string
	if credentialType(srcJSON) == "service_account" {
		srcScopes = []string{oauth2lib.IAMScope}
	}

	ctx := t.Context()
	hc := newSmokeHTTPClient(t)
	srcCreds, err := oauth2lib.BuildCredentials(ctx, withSmokeRAPT(&oauth2lib.Config{
		JSON:   srcJSON,
		Scopes: srcScopes,
		Client: hc,
	}))
	if err != nil {
		t.Fatalf("BuildCredentials(source) failed: %v", err)
	}
	impCreds, err := oauth2lib.Impersonate(ctx, &oauth2lib.ImpersonationConfig{
		Source:    srcCreds,
		Target:    target,
		Delegates: delegates,
		Scopes:    impersonationScopes(),
		Lifetime:  lifetime,
		Endpoint:  endpoint,
		Client:    hc,
	})
	if err != nil {
		t.Fatalf("Impersonate() failed: %v", err)
	}
	tok, err := impCreds.Token(ctx)
	if err != nil {
		t.Fatalf("Impersonate().Token() failed: %v", err)
	}
	if tok == nil || tok.Value == "" || tok.Expiry.IsZero() {
		t.Fatalf("Impersonate().Token() returned incomplete token")
	}
	t.Logf("impersonate succeeded (delegates=%d, custom_endpoint=%v, expires_in=%s)",
		len(delegates), endpoint != "", time.Until(tok.Expiry).Round(time.Second))
	verifyOptionalLiveGET(t, ctx, impCreds, nil)
}

func TestSmoke_Impersonate(t *testing.T) {
	// One hop: source -> target, default IAM endpoint built from the source's
	// universe domain.
	t.Run("one_hop", func(t *testing.T) {
		runDirectImpersonation(t, nil, "")
	})

	// Two hops: source -> delegate -> target. The source needs
	// roles/iam.serviceAccountTokenCreator on the delegate, and the delegate
	// needs it on the target.
	t.Run("two_hop", func(t *testing.T) {
		delegates := splitCSVEnv("OAUTH2LIB_SMOKE_IMPERSONATE_DELEGATES")
		if len(delegates) == 0 {
			t.Skip("set OAUTH2LIB_SMOKE_IMPERSONATE_DELEGATES to a comma-separated list of delegate service accounts")
		}
		runDirectImpersonation(t, delegates, "")
	})

	// Custom IAM endpoint: ImpersonationConfig.Endpoint is used as given.
	t.Run("custom_endpoint", func(t *testing.T) {
		endpoint := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_IMPERSONATE_ENDPOINT"))
		if endpoint == "" {
			t.Skip("set OAUTH2LIB_SMOKE_IMPERSONATE_ENDPOINT to an IAM Credentials base URL, e.g. https://iamcredentials.googleapis.com/")
		}
		runDirectImpersonation(t, nil, endpoint)
	})

	t.Run("impersonated_service_account_json", func(t *testing.T) {
		rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_IMPERSONATED_SA_JSON")

		// Path A: BuildCredentials directly on impersonated_service_account JSON.
		// This path can't carry a RAPT for the source (by design), so a user
		// source on an account with a reauth policy gets ErrReauthRequired.
		t.Run("build_credentials", func(t *testing.T) {
			ctx := t.Context()
			directCreds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
				JSON:   rawJSON,
				Scopes: impersonationScopes(),
				Client: newSmokeHTTPClient(t),
			})
			if err != nil {
				t.Fatalf("BuildCredentials(impersonated_service_account) failed: %v", err)
			}
			tok, err := directCreds.Token(ctx)
			if errors.Is(err, oauth2lib.ErrReauthRequired) {
				t.Skipf("source needs a RAPT, which impersonated_service_account JSON can't carry; Go gcloud uses the parse_then_impersonate path: %v", err)
			}
			if err != nil {
				t.Fatalf("BuildCredentials(impersonated_service_account).Token() failed: %v", err)
			}
			if tok == nil || tok.Value == "" {
				t.Fatalf("direct impersonated Token() returned empty value")
			}
		})

		// Path B: ParseImpersonatedServiceAccountJSON + SourceConfig + Impersonate
		// (the pattern gocloud uses so Tier 2 can cache the source credential).
		// SourceConfig doesn't copy RAPT, so the caller sets it on the result.
		t.Run("parse_then_impersonate", func(t *testing.T) {
			ctx := t.Context()
			hc := newSmokeHTTPClient(t)
			parsed, err := oauth2lib.ParseImpersonatedServiceAccountJSON(rawJSON)
			if err != nil {
				t.Fatalf("ParseImpersonatedServiceAccountJSON() failed: %v", err)
			}
			srcCreds, err := oauth2lib.BuildCredentials(ctx, withSmokeRAPT(parsed.SourceConfig(&oauth2lib.Config{Client: hc})))
			if err != nil {
				t.Fatalf("BuildCredentials(SourceConfig) failed: %v", err)
			}
			// The JSON's "scopes" win, as in Python gcloud; otherwise use the
			// OAUTH2LIB_SMOKE_IMPERSONATE_SCOPES choice.
			scopes := parsed.Scopes
			if len(scopes) == 0 {
				scopes = impersonationScopes()
			}
			splitCreds, err := oauth2lib.Impersonate(ctx, &oauth2lib.ImpersonationConfig{
				Source:    srcCreds,
				Target:    parsed.Target,
				Delegates: parsed.Delegates,
				Scopes:    scopes,
				Client:    hc,
			})
			if err != nil {
				t.Fatalf("Impersonate(parsed) failed: %v", err)
			}
			tok, err := splitCreds.Token(ctx)
			if err != nil {
				t.Fatalf("Impersonate(parsed).Token() failed: %v", err)
			}
			if tok == nil || tok.Value == "" {
				t.Fatalf("split impersonated Token() returned empty value")
			}
		})
	})
}

func TestSmoke_MTLSAndClientCertRefusal(t *testing.T) {
	// Hermetic verification of the ECP client-certificate refusal contract:
	// when GetClientCertificate (or a signer) returns an error wrapping
	// oauth2lib.ErrAccessDenied, Token() must return KindAccessDenied and must
	// not match ErrCAADenied or ErrTransient.
	t.Run("refusal", func(t *testing.T) {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		srv.TLS = &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
		}
		srv.StartTLS()
		defer srv.Close()

		baseTransport := srv.Client().Transport.(*http.Transport).Clone()
		t.Cleanup(baseTransport.CloseIdleConnections)
		baseTransport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return nil, fmt.Errorf("ecp signer refused certificate: %w", oauth2lib.ErrAccessDenied)
		}
		hc := &http.Client{
			Timeout:   10 * time.Second,
			Transport: baseTransport,
		}

		ctx := t.Context()
		creds, err := oauth2lib.BuildCredentials(ctx, &oauth2lib.Config{
			JSON:     []byte(`{"type":"authorized_user","client_id":"cid","client_secret":"csec","refresh_token":"1//fake"}`),
			TokenURL: srv.URL + "/token",
			Client:   hc,
		})
		if err != nil {
			t.Fatalf("BuildCredentials() failed: %v", err)
		}

		_, err = creds.Token(ctx)
		if !errors.Is(err, oauth2lib.ErrAccessDenied) {
			t.Fatalf("Token() err = %v, want errors.Is(ErrAccessDenied)", err)
		}
		if errors.Is(err, oauth2lib.ErrCAADenied) {
			t.Errorf("client-cert refusal unexpectedly matched ErrCAADenied: %v", err)
		}
		if errors.Is(err, oauth2lib.ErrTransient) {
			t.Errorf("client-cert refusal unexpectedly matched ErrTransient: %v", err)
		}
		var re *oauth2lib.RefreshError
		if !errors.As(err, &re) || re.Kind != oauth2lib.KindAccessDenied {
			t.Errorf("Token() err = %v, want *oauth2lib.RefreshError with KindAccessDenied", err)
		}
	})

	// Optional live mTLS smoke check against oauth2.mtls.googleapis.com/token.
	// Swap tls.LoadX509KeyPair for ecpclient.Cred when testing against a live
	// Enterprise Certificate Proxy signer.
	t.Run("live_mtls_token_endpoint", func(t *testing.T) {
		rawJSON := readEnvFileOrSkip(t, "OAUTH2LIB_SMOKE_MTLS_USER_JSON")
		certPath := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_MTLS_CERT_PEM"))
		keyPath := strings.TrimSpace(os.Getenv("OAUTH2LIB_SMOKE_MTLS_KEY_PEM"))
		if certPath == "" || keyPath == "" {
			t.Skip("set OAUTH2LIB_SMOKE_MTLS_CERT_PEM and OAUTH2LIB_SMOKE_MTLS_KEY_PEM to test live mTLS refresh")
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatalf("tls.LoadX509KeyPair() failed: %v", err)
		}
		tr := newSmokeTransport(t)
		tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		}
		hc := &http.Client{Timeout: 30 * time.Second, Transport: tr}

		ctx := t.Context()
		creds, err := oauth2lib.BuildCredentials(ctx, withSmokeRAPT(&oauth2lib.Config{
			JSON:     rawJSON,
			TokenURL: "https://oauth2.mtls.googleapis.com/token",
			Client:   hc,
		}))
		if err != nil {
			t.Fatalf("BuildCredentials(mTLS) failed: %v", err)
		}
		tok, err := creds.Token(ctx)
		if err != nil {
			t.Fatalf("Token(mTLS) failed: %v", err)
		}
		if tok == nil || tok.Value == "" {
			t.Fatalf("Token(mTLS) returned empty access token")
		}
		t.Logf("live mTLS token refresh succeeded (expires_in=%s)", time.Until(tok.Expiry).Round(time.Second))
	})
}
