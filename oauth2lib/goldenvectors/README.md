# oauth2lib golden vectors

Each `*.json` file in this directory is one test vector: an input to
`oauth2lib.BuildCredentials` or `oauth2lib.Impersonate`, the HTTP requests a
single `Token` call must send (in order), the response to give each one, and
the token or `*oauth2lib.RefreshError` that `Token` must return.

The files are embedded in package `goldenvectors` (`//go:embed *.json`), so
tests in other modules, such as Go gcloud's, read them with
`goldenvectors.All()` and need no Blaze runfiles or file paths. The package
imports only the standard library.

oauth2lib's `TestGoldenVectors` (`../goldenvectors_test.go`) runs every vector.
It is also a reference for how to run them elsewhere. It runs each
`impersonated_service_account` vector twice: once with `BuildCredentials`, and
once as `<name>/parse_and_impersonate` with
`ParseImpersonatedServiceAccountJSON`, `SourceConfig`, `BuildCredentials` and
`Impersonate`. Both must send the same requests and give the same result.

`All()` rejects a file that doesn't parse, has unknown fields or data after
the vector, has a `name` other than its file name, or fails
`Vector.Validate`. `Validate` checks the shape described below (for example
exactly one of `config` and `impersonation`), not oauth2lib's behavior.

## Format

```jsonc
{
  "name": "user_refresh_scopes_rapt",          // the file name without .json
  "description": "...",
  "python": "...",                              // Python code that sends the same requests
  "input": {
    // Exactly one of "config" and "impersonation".
    "config": {                                 // oauth2lib.Config, without Client and Logger
      "credentials_json": { "type": "authorized_user", ... },
      "scopes": ["..."],
      "token_url": "",
      "universe_domain": "",
      "use_self_signed_jwt": false,
      "rapt": "..."                             // what Config.RAPT returns
    },
    "impersonation": {                          // oauth2lib.ImpersonationConfig
      "source": { /* a config, built with BuildCredentials */ },
      "target": "...", "delegates": ["..."], "scopes": ["..."],
      "lifetime_seconds": 600, "endpoint": ""
    }
  },
  "exchanges": [                                // every request, in order
    {
      "request": {
        "method": "POST",
        "url": "https://oauth2.googleapis.com/token",
        "headers": { "Content-Type": "..." },   // must be present with these values
        "form": { "grant_type": "..." },        // exact form fields...
        "assertion": { /* JWT */ },             // ...except "assertion", checked as a JWT
        "json": { }                             // or a JSON body, compared as JSON
      },
      "response": {
        "status": 400,                          // 0 or absent means 200
        "body": { },                            // sent as application/json
        "body_text": "",                        // or sent as text/plain
        "transport_error": {                    // or the client gets this error
          "message": "...", "type": ""          // (only on the last exchange)
        }
      }
    }
  ],
  "expected": {
    "universe_domain": "googleapis.com",
    // Exactly one of "token" and "error".
    "token": {
      "value": "...",                           // or "jwt" for a self-signed JWT
      "type": "Bearer",
      "expires_in_seconds": 3600,               // or "expiry" (RFC 3339); neither: zero
      "metadata": { "rapt_token": "..." }       // exact Metadata (oauth2lib.Metadata* keys)
    },
    "error": {
      "kind": "reauth_required",                // a stable kind id, see below
      "code": "invalid_grant", "subtype": "invalid_rapt",
      "description": "...", "status_code": 400,
      "is": ["ErrReauthRequired"]               // sentinels it matches; no others
    }
  }
}
```

A JWT (`assertion`, or `token.jwt`) is signed with the test's key. Its
`header` and `claims` list fields it must have with those values;
`absent_claims` must not be there; `lifetime_seconds` is `exp - iat`.

### Error kinds

`error.kind` is a stable id for the `oauth2lib.ErrorKind`, not its `String()`
text. The ids are constants in package `goldenvectors`:

| `kind`            | `oauth2lib.ErrorKind` |
| ----------------- | --------------------- |
| `unknown`         | `KindUnknown`         |
| `reauth_required` | `KindReauthRequired`  |
| `access_denied`   | `KindAccessDenied`    |
| `invalid_grant`   | `KindInvalidGrant`    |
| `transient`       | `KindTransient`       |

A test that runs the vectors should map each kind with an explicit switch and
fail on a kind it doesn't know.

### Transport errors

`transport_error.type` says which error the client gets instead of a
response. The types are `TransportError*` constants in package
`goldenvectors`:

- `""` or absent: a plain network error, `errors.New(message)`.
- `client_cert_refused`: the client's certificate callback or signer (for
  example the enterprise certificate proxy) refused. The error wraps
  `oauth2lib.ErrAccessDenied`, as in
  `fmt.Errorf("%s: %w", message, oauth2lib.ErrAccessDenied)`.
- `client_timeout`: `http.Client.Timeout` expired. Give the vector's client a
  short `Timeout` (oauth2lib uses 200ms), and have the transport wait for the
  request's context and return its error, so net/http builds its real
  timeout error. `message` only describes it.
- `server_cert_untrusted`: the client rejected the server's certificate. The
  error wraps `&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}`.

No vector cancels the caller's context, so no expected error may match
`context.DeadlineExceeded` or `context.Canceled`, even after a client timeout.

## Known differences from Python

- An `impersonated_service_account` file with `"delegates": []` (as gcloud
  writes it) is sent to IAM as `"delegates": null`; Python sends `[]`. IAM
  treats them the same. The vectors record `null`.

No private key is checked in. A `"private_key"` of `"TEST_PRIVATE_KEY_PEM"`
(`goldenvectors.PrivateKeyPlaceholder`) is replaced by a PEM RSA key that the
test generates; use `Config.JSON(pem)` to get the credential bytes. Tokens and
secrets in the vectors are obviously fake strings.

## Adding a vector

Add a file whose `name` matches its file name and run
`go test ./...` in `oauth2lib/`. When a vector describes a request body, check
it against Python gcloud or google-auth (named in `"python"`).
