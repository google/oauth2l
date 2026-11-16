// Copy of Go gcloud's go.mod (google3: //third_party/gcloud_cli/external/gcloud/go.mod).
// .github/scripts/oauth2lib_compat.py reads the go line and requirements below:
// oauth2lib must not require any module at a newer version than listed here.
// Update this file by copying the current Go gcloud go.mod over it, unchanged
// below this header. In google3, oauth2lib's check_tests also compare its
// go.mod with Go gcloud's, so this copy is an early check, not the source of truth.
//
// Module manifest for the Copybara export of this directory (GoB
// gcloud-cli/gcloud). Blaze ignores it; the Kokoro release build uses it
// read-only (cloud/sdk/component_build/kokoro/gcloud/lib/build_go_binary.sh).
//
// Keep the direct requirements at the versions in //third_party/golang
// (the METADATA of each package mapped in copy.bara.sky), so the shipped
// binary links what google3 tests. Exceptions forced upward by minimum
// version selection: golang.org/x/net carries security fixes that
// //third_party/golang/go_net lacks, and its requirements raise
// golang.org/x/sys, golang.org/x/text, and (through x/text) golang.org/x/tools
// above their //third_party/golang versions.
//
// To update: edit the direct requirements, then run `go mod tidy` in an
// export (or a GoB checkout) and copy go.mod and go.sum back here. Do not
// hand-edit go.sum or the indirect block. The Kokoro build fails if
// `go mod tidy -diff` is non-empty.
// LINT.IfChange(module_path)
module cloud.google.com/gcloud

// LINT.ThenChange(//depot/google3/third_party/gcloud_cli/external/gcloud/internal/tools/lint/pkgpath/pkgpath.go:module_path)

// The Kokoro build installs exactly this Go version and verifies it against a
// pinned SHA-256; add the new version's checksum when changing it.
// LINT.IfChange(go_version)
go 1.27.3

// LINT.ThenChange(//depot/google3/cloud/sdk/component_build/kokoro/gcloud/lib/go_toolchain_sha256.txt)

require (
	cloud.google.com/go/run v1.22.0
	github.com/ebitengine/purego v0.11.0
	github.com/gofrs/flock v0.13.1
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.24.0
	github.com/urfave/cli/v3 v3.12.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	golang.org/x/text v0.43.0
	golang.org/x/tools v0.51.0
	google.golang.org/api v0.292.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.59.0
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.23.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.12.0 // indirect
	cloud.google.com/go/longrunning v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.19 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.67.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.44.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/trace v1.44.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto v0.0.0-20260715232425-e75dac1f907d // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260715232425-e75dac1f907d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	modernc.org/libc v1.75.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
