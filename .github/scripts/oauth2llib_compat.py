#!/usr/bin/env python3
#
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Checks that the oauth2llib module stays compatible with Go gcloud and google3.

Go gcloud builds oauth2llib in two ways: in google3, against google3's copies
of its dependencies, and with the standard Go toolchain from Go gcloud's
go.mod. For both builds to link the same code, oauth2llib must not require a
newer version of any module than Go gcloud uses, must build with Go gcloud's
Go version, and must avoid APIs that google3 changes or blocks.

Run from the repository root:

    python3 .github/scripts/oauth2llib_compat.py
"""

import json
import os
import re
import subprocess
import sys

MODULE_DIR = "oauth2llib"

# Highest Go version that Go gcloud's release build uses.
MAX_GO_VERSION = "1.27.3"

# Module versions from Go gcloud's go.mod. oauth2llib may require these modules
# at the listed version or lower. Update this list when Go gcloud upgrades.
GO_GCLOUD_PINS = {
    "cloud.google.com/go": "v0.123.0",
    "cloud.google.com/go/auth": "v0.23.0",
    "cloud.google.com/go/auth/oauth2adapt": "v0.2.8",
    "cloud.google.com/go/compute/metadata": "v0.9.0",
    "cloud.google.com/go/iam": "v1.12.0",
    "cloud.google.com/go/longrunning": "v1.2.0",
    "github.com/cespare/xxhash/v2": "v2.3.0",
    "github.com/felixge/httpsnoop": "v1.0.4",
    "github.com/go-logr/logr": "v1.4.3",
    "github.com/go-logr/stdr": "v1.2.2",
    "github.com/google/go-cmp": "v0.7.0",
    "github.com/google/s2a-go": "v0.1.9",
    "github.com/google/uuid": "v1.6.0",
    "github.com/googleapis/enterprise-certificate-proxy": "v0.3.19",
    "github.com/googleapis/gax-go/v2": "v2.24.0",
    "go.opentelemetry.io/auto/sdk": "v1.2.1",
    "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc": "v0.67.0",
    "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp": "v0.67.0",
    "go.opentelemetry.io/otel": "v1.44.0",
    "go.opentelemetry.io/otel/metric": "v1.44.0",
    "go.opentelemetry.io/otel/trace": "v1.44.0",
    "golang.org/x/crypto": "v0.58.0",
    "golang.org/x/mod": "v0.41.0",
    "golang.org/x/net": "v0.62.0",
    "golang.org/x/oauth2": "v0.36.0",
    "golang.org/x/sync": "v0.24.0",
    "golang.org/x/sys": "v0.49.0",
    "golang.org/x/text": "v0.43.0",
    "golang.org/x/time": "v0.15.0",
    "golang.org/x/tools": "v0.51.0",
    "google.golang.org/api": "v0.292.0",
    "google.golang.org/genproto": "v0.0.0-20260715232425-e75dac1f907d",
    "google.golang.org/genproto/googleapis/api": "v0.0.0-20260715232425-e75dac1f907d",
    "google.golang.org/genproto/googleapis/rpc": "v0.0.0-20260803160001-6ac0973c030d",
    "google.golang.org/grpc": "v1.83.2",
    "google.golang.org/protobuf": "v1.36.11",
}

# Modules that Go gcloud does not use but oauth2llib may require because only
# oauth2llib's own tests import them. The version is the highest allowed (the
# version in google3).
TEST_ONLY_MODULES = {
    "go.uber.org/goleak": "v1.3.0",
}

# APIs that google3's copy of cloud.google.com/go/auth changes (it adds a ctx
# parameter), so code that uses them does not compile in google3, and crypto
# packages that google3's nogo check blocks.
FORBIDDEN_PATTERNS = [
    (re.compile(r'"cloud\.google\.com/go/auth/httptransport"'),
     "imports cloud.google.com/go/auth/httptransport, which google3 patches"),
    (re.compile(r"\bimpersonate\.NewCredentials\b"),
     "calls impersonate.NewCredentials, which google3 patches"),
    (re.compile(r"\bimpersonate\.NewIDTokenCredentials\b"),
     "calls impersonate.NewIDTokenCredentials, which google3 patches"),
    (re.compile(r"\bidtoken\.NewCredentials\b"),
     "calls idtoken.NewCredentials, which google3 patches"),
    (re.compile(r'"crypto/(cipher|des|dsa|elliptic|ed25519|md5|rc4|rsa|sha1)"'),
     "imports a crypto package that google3 blocks"),
    (re.compile(r'"golang\.org/x/crypto/(blowfish|bn256|cast5|ed25519|md4|otr|ripemd160|tea|twofish|xtea|xts)"'),
     "imports a golang.org/x/crypto package that google3 blocks"),
]


def parse_version(version):
    """Returns a sortable key for a Go module version such as v1.2.3 or v1.2.3-rc.1."""
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?", version)
    if not match:
        raise ValueError(f"unrecognized version {version!r}")
    major, minor, patch, pre = match.groups()
    # A release sorts after any pre-release (including pseudo-versions) of the
    # same version.
    pre_key = (1,) if pre is None else (0,) + tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return (int(major), int(minor), int(patch), pre_key)


def go_version_key(version):
    return tuple(int(part) for part in re.findall(r"\d+", version))


def check_requirements(go_mod):
    errors = []
    go_version = go_mod.get("Go", "")
    if go_version_key(go_version) > go_version_key(MAX_GO_VERSION):
        errors.append(f"go.mod: go {go_version} is newer than Go gcloud's Go {MAX_GO_VERSION}")
    for req in go_mod.get("Require") or []:
        path, version = req["Path"], req["Version"]
        limit = GO_GCLOUD_PINS.get(path) or TEST_ONLY_MODULES.get(path)
        if limit is None:
            errors.append(
                f"go.mod: {path} {version} is not used by Go gcloud. Adding it needs a google3 "
                "import and Go gcloud review; if only tests use it, add it to TEST_ONLY_MODULES")
        elif parse_version(version) > parse_version(limit):
            errors.append(f"go.mod: {path} {version} is newer than the allowed {limit}")
    for rep in go_mod.get("Replace") or []:
        errors.append(f"go.mod: replace directive for {rep['Old']['Path']} is not allowed")
    return errors


def check_sources():
    errors = []
    for root, dirs, files in os.walk(MODULE_DIR):
        if "vendor" in dirs:
            errors.append(f"{os.path.join(root, 'vendor')}: vendor directories are not allowed")
            dirs.remove("vendor")
        for name in files:
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    for pattern, reason in FORBIDDEN_PATTERNS:
                        if pattern.search(line):
                            errors.append(f"{path}:{lineno}: {reason}")
    return errors


def main():
    out = subprocess.run(["go", "mod", "edit", "-json"], cwd=MODULE_DIR,
                         check=True, capture_output=True, text=True).stdout
    errors = check_requirements(json.loads(out)) + check_sources()
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"{len(errors)} compatibility problem(s) found.")
        return 1
    print("oauth2llib is compatible with Go gcloud and google3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
