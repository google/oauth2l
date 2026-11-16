# oauth2lib

`oauth2lib` is a pure-Go library, under development, that will build
refreshable Google credentials from inputs the caller has already resolved. It
is designed never to cache, prompt, or read configuration. Its first user is
the Go version of `gcloud`, which will pass in the credential JSON, scopes,
token URL, IAM endpoint and RAPT, and get back `*auth.Credentials` from
[cloud.google.com/go/auth](https://github.com/googleapis/google-cloud-go/tree/main/auth).

It is a separate Go module (`github.com/google/oauth2l/oauth2lib`) inside the
oauth2l repository, released with its own tags (`oauth2lib/vX.Y.Z`).

## Planned scope of v0.1.0

- `BuildCredentials` for `authorized_user`, `service_account` (OAuth and
  self-signed JWT) and `impersonated_service_account` JSON.
- User refreshes that send the same request as Python gcloud, including
  `scope` and the RAPT.
- `Impersonate` (IAM `generateAccessToken` with delegates, scopes and lifetime)
  and `ParseImpersonatedServiceAccountJSON`.
- `RefreshError` with a kind (reauth required, access denied, invalid grant,
  transient, unknown) and an `errors.Is` sentinel for each kind except unknown.

Not planned for v0.1.0: `external_account` and
`external_account_authorized_user` credentials, login flows, token caching, and
token revocation.

## Planned behavior

- Each `Token()` call blocks until it has a new token. oauth2lib holds no
  access tokens between calls and makes no retries.
- It never reads gcloud properties, Application Default Credentials or Google
  environment variables.
- Every request uses the `*http.Client` the caller passes in, never
  `http.DefaultClient`.
- It is headless (no prompts, terminal I/O, browser or subprocesses), starts no
  background goroutines, and is safe for concurrent use.
- Refresh tokens, client secrets, RAPTs and access tokens are never logged or
  included in errors.
- It sets no quota project. Use the credentials with your own HTTP transport,
  not with go/auth's `httptransport` or `grpctransport`.

## Dependency rules

Go gcloud builds this module both in google3 and with the standard Go
toolchain, so the module has to stay within the versions Go gcloud already
uses. Those versions are listed in
[.github/oauth2lib/gocloud.go.mod](../.github/oauth2lib/gocloud.go.mod). The
`oauth2lib` job in
[integration-test.yml](../.github/workflows/integration-test.yml) builds and
tests the module with its declared Go version and with Go gcloud's, and runs
[oauth2lib_compat.py](../.github/scripts/oauth2lib_compat.py) to check that:

- The `go` line and every requirement in `go.mod` are at or below the versions
  in `gocloud.go.mod`. Modules that Go gcloud does not use are allowed only if
  the script lists them as test-only, and non-test code must not depend on
  them. `replace` directives are not allowed.
- Non-test code does not import `cloud.google.com/go/auth/httptransport`, which
  google3 patches with an extra `ctx` parameter, or the crypto packages that
  google3 blocks (`crypto/cipher`, `crypto/des`, `crypto/dsa`,
  `crypto/elliptic`, `crypto/ed25519`, `crypto/md5`, `crypto/rc4`,
  `crypto/rsa`, `crypto/sha1`, and `golang.org/x/crypto`'s `blowfish`,
  `bn256`, `cast5`, `ed25519`, `md4`, `otr`, `ripemd160`, `tea`, `twofish`,
  `xtea` and `xts`). Imports are read with `go list`, so aliases and comments
  do not matter.
- Non-test code does not call `impersonate.NewCredentials`,
  `impersonate.NewIDTokenCredentials` or `idtoken.NewCredentials`, which google3
  also patches. This rule matches the source text, so it does not catch calls
  through an aliased import.

Keep everything the module needs, including test data, inside `oauth2lib/`,
and do not add a `vendor/` directory.
