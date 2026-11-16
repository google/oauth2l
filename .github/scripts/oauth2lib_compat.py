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
"""Checks that the oauth2lib module stays compatible with Go gcloud and google3.

Go gcloud builds oauth2lib in two ways: in google3, against google3's copies
of its dependencies, and with the standard Go toolchain from Go gcloud's
go.mod. For both builds to link the same code, oauth2lib must not require a
newer version of any module than Go gcloud uses, must build with Go gcloud's
Go version, and must avoid APIs that google3 changes or blocks.

Run from the repository root:

    python3 .github/scripts/oauth2lib_compat.py
"""

import json
import os
import re
import subprocess
import sys

MODULE_DIR = "oauth2lib"

# Copy of Go gcloud's go.mod. Its go line is the highest Go version oauth2lib
# may declare, and its requirements are the highest module versions oauth2lib
# may require. Update it by copying Go gcloud's go.mod over it.
GO_GCLOUD_GO_MOD = ".github/oauth2lib/gocloud.go.mod"

# Modules that Go gcloud does not use but oauth2lib may require because only
# oauth2lib's own tests import them. The version is the highest allowed (the
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


def go_mod_json(path, cwd=None):
    """Returns `go mod edit -json` output for the go.mod file at path."""
    out = subprocess.run(["go", "mod", "edit", "-json", path], cwd=cwd,
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def check_requirements(go_mod, gocloud_go_mod):
    errors = []
    max_go = gocloud_go_mod["Go"]
    pins = {req["Path"]: req["Version"] for req in gocloud_go_mod.get("Require") or []}
    go_version = go_mod.get("Go", "")
    if go_version_key(go_version) > go_version_key(max_go):
        errors.append(f"go.mod: go {go_version} is newer than Go gcloud's Go {max_go}")
    for req in go_mod.get("Require") or []:
        path, version = req["Path"], req["Version"]
        limit = pins.get(path) or TEST_ONLY_MODULES.get(path)
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
    errors = check_requirements(go_mod_json("go.mod", cwd=MODULE_DIR),
                                go_mod_json(GO_GCLOUD_GO_MOD)) + check_sources()
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"{len(errors)} compatibility problem(s) found.")
        return 1
    print("oauth2lib is compatible with Go gcloud and google3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
