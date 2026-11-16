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

// Package oauth2llib builds refreshable Google credentials from inputs the
// caller has already resolved. It never caches, prompts, or reads
// configuration.
//
// The caller (first, the Go version of gcloud) passes in the credential JSON,
// scopes, token URL, IAM endpoint and RAPT, and gets back *auth.Credentials
// from cloud.google.com/go/auth.
//
// Version v0.1.0 covers:
//
//   - BuildCredentials for authorized_user, service_account (OAuth and
//     self-signed JWT) and impersonated_service_account JSON.
//   - User refreshes that send the same request as Python gcloud, including
//     scope and the RAPT.
//   - Impersonate (IAM generateAccessToken) and
//     ParseImpersonatedServiceAccountJSON.
//   - RefreshError, with a kind and an errors.Is sentinel for each kind
//     except unknown.
//
// Behavior:
//
//   - Each Token call blocks until it has a new token. No access tokens are
//     held between calls, and no retries are made.
//   - gcloud properties, Application Default Credentials and Google
//     environment variables are never read.
//   - Every request uses the *http.Client the caller passes in.
//   - The package is headless (no prompts, terminal I/O, browser or
//     subprocesses), starts no background goroutines, and is safe for
//     concurrent use.
//   - Secrets are never logged or included in errors.
//   - No quota project is set. Use the credentials with your own HTTP
//     transport, not with go/auth's httptransport or grpctransport.
//
// oauth2llib is a separate Go module so that it can follow the dependency
// versions used by Go gcloud and google3 (for example
// cloud.google.com/go/auth v0.23.0) independently of the oauth2l command.
package oauth2llib
