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
It is also a reference for how to run them elsewhere.

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
        "transport_error": ""                   // or the client gets this error
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
      "kind": "reauth required",                // ErrorKind.String()
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

No private key is checked in. A `"private_key"` of `"TEST_PRIVATE_KEY_PEM"`
(`goldenvectors.PrivateKeyPlaceholder`) is replaced by a PEM RSA key that the
test generates; use `Config.JSON(pem)` to get the credential bytes. Tokens and
secrets in the vectors are obviously fake strings.

## Adding a vector

Add a file whose `name` matches its file name and run
`go test ./...` in `oauth2lib/`. When a vector describes a request body, check
it against Python gcloud or google-auth (named in `"python"`).
