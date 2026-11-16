# oauth2lib

`oauth2lib` is a pure-Go library that builds refreshable Google credentials
from inputs the caller has already resolved. It never caches, prompts, or reads
configuration. Its first user is the Go version of `gcloud`, which passes in the
credential JSON, scopes, token URL, IAM endpoint and RAPT, and gets back
`*auth.Credentials` from
[cloud.google.com/go/auth](https://github.com/googleapis/google-cloud-go/tree/main/auth).

It is a separate Go module (`github.com/google/oauth2l/oauth2lib`) inside the
oauth2l repository, released with its own tags (`oauth2lib/vX.Y.Z`). The
library is under development.

## Scope of v0.1.0

- `BuildCredentials` for `authorized_user`, `service_account` (OAuth and
  self-signed JWT) and `impersonated_service_account` JSON.
- User refreshes that send the same request as Python gcloud, including
  `scope` and the RAPT.
- `Impersonate` (IAM `generateAccessToken` with delegates, scopes and lifetime)
  and `ParseImpersonatedServiceAccountJSON`.
- `RefreshError` with a kind (reauth required, access denied, invalid grant,
  transient, unknown) and an `errors.Is` sentinel for each kind except unknown.

Not in v0.1.0: `external_account` and `external_account_authorized_user`
credentials, login flows, token caching, and token revocation.

## Behavior

- Each `Token()` call blocks until it has a new token. oauth2lib holds no
  access tokens between calls and makes no retries.
- It never reads gcloud properties, Application Default Credentials or Google
  environment variables.
- Every request uses the `*http.Client` the caller passes in, never
  `http.DefaultClient`.
- It is headless (no prompts, terminal I/O, browser or subprocesses) and safe
  for concurrent use.
- Refresh tokens, client secrets, RAPTs and access tokens are never logged or
  included in errors.
- It sets no quota project. Use the credentials with your own HTTP transport,
  not with go/auth's `httptransport` or `grpctransport`.

## Dependency rules

Go gcloud builds this module both in google3 and with the standard Go
toolchain, so the module has to stay within the versions Go gcloud already
uses. The `oauth2lib` job in
[integration-test.yml](../.github/workflows/integration-test.yml) runs
[oauth2lib_compat.py](../.github/scripts/oauth2lib_compat.py) to check that:

- Every requirement in `go.mod` is at or below the version in Go gcloud's
  `go.mod`, a copy of which is kept in
  [.github/oauth2lib/gocloud.go.mod](../.github/oauth2lib/gocloud.go.mod)
  (for example `cloud.google.com/go/auth` v0.23.0). Modules that Go gcloud does not
  use yet are allowed only if they are listed in the script as test-only.
  `replace` directives are not allowed.
- The `go` line is at or below the `go` line in Go gcloud's `go.mod` (Go 1.27.3).
- Non-test code does not call APIs that google3 patches with an extra `ctx`
  parameter (`cloud.google.com/go/auth/httptransport`,
  `impersonate.NewCredentials`, `impersonate.NewIDTokenCredentials`,
  `idtoken.NewCredentials`), and does not import the crypto packages that
  google3 blocks (`crypto/rsa`, `crypto/sha1`, `crypto/md5`, `crypto/cipher`,
  `crypto/des`, `crypto/dsa`, `crypto/elliptic`, `crypto/ed25519`,
  `crypto/rc4`, and `golang.org/x/crypto`'s `blowfish`, `bn256`, `cast5`,
  `ed25519`, `md4`, `otr`, `ripemd160`, `tea`, `twofish`, `xtea` and `xts`).

Keep everything the module needs, including test data, inside `oauth2lib/`,
and do not add a `vendor/` directory.
