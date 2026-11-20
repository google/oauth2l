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
of its dependencies, and with the standard Go toolchain from Go gcloud's own
module requirements. For both builds to link the same code, oauth2lib must not
require a newer version of any module than Go gcloud uses, must build with Go
gcloud's Go version, and must avoid APIs that google3 changes or blocks.

Run from the repository root:

    python3 .github/scripts/oauth2lib_compat.py
"""

import json
import os
import re
import subprocess
import sys

MODULE_DIR = "oauth2lib"

# The module versions Go gcloud uses. Its go line is the highest Go version
# oauth2lib may declare, and its requirements are the highest module versions
# oauth2lib may require.
GO_GCLOUD_GO_MOD = ".github/oauth2lib/gocloud.go.mod"

# Modules that Go gcloud does not use but oauth2lib may require because only
# oauth2lib's own tests import them. The version is the highest allowed (the
# version in google3). check_test_only_modules makes sure non-test code does
# not depend on them.
TEST_ONLY_MODULES = {
    "go.uber.org/goleak": "v1.3.0",
}

# Packages that non-test code must not import: google3's copy of
# cloud.google.com/go/auth changes httptransport and every constructor in
# credentials/impersonate (it adds a ctx parameter), and google3's nogo check
# blocks these crypto packages.
FORBIDDEN_IMPORTS = [
    (re.compile(r"cloud\.google\.com/go/auth/httptransport"),
     "google3 patches this package"),
    (re.compile(r"cloud\.google\.com/go/auth/credentials/impersonate"),
     "google3 patches this package"),
    (re.compile(r"crypto/(cipher|des|dsa|elliptic|ed25519|md5|rc4|rsa|sha1)"),
     "google3 blocks this crypto package"),
    (re.compile(r"golang\.org/x/crypto/(blowfish|bn256|cast5|ed25519|md4|otr|ripemd160|tea|twofish|xtea|xts)"),
     "google3 blocks this crypto package"),
]

# Functions that google3's copy of cloud.google.com/go/auth changes (it adds a
# ctx parameter). These are matched in the source text, so calls through an
# aliased import are not caught; google3's build still rejects them.
PATCHED_CALLS = [
    "impersonate.NewCredentials",
    "impersonate.NewIDTokenCredentials",
    "idtoken.NewCredentials",
]
_PATCHED_CALL_RE = re.compile(r"\b(" + "|".join(re.escape(c) for c in PATCHED_CALLS) + r")\b")


def parse_version(version):
    """Returns a sortable key for a Go module version such as v1.2.3 or v1.2.3-rc.1."""
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", version)
    if not match:
        raise ValueError(f"unrecognized version {version!r}")
    major, minor, patch, pre = match.groups()
    # A release sorts after any pre-release (including pseudo-versions) of the
    # same version. Numeric identifiers sort before alphanumeric ones.
    pre_key = (1,) if pre is None else (0,) + tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return (int(major), int(minor), int(patch), pre_key)


def go_version_key(version):
    """Returns a sortable key for a Go version such as 1.26 or 1.26.0."""
    match = re.fullmatch(r"(?:go)?(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not match:
        raise ValueError(f"unrecognized Go version {version!r}")
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


def run_go(args, cwd=MODULE_DIR):
    return subprocess.run(["go"] + args, cwd=cwd, check=True, capture_output=True,
                          text=True).stdout


def go_mod_json(path, cwd=None):
    """Returns `go mod edit -json` output for the go.mod file at path."""
    return json.loads(run_go(["mod", "edit", "-json", path], cwd=cwd))


def check_requirements(go_mod, gocloud_go_mod):
    """Reports requirements and go lines in go_mod that Go gcloud does not allow."""
    errors = []
    max_go = gocloud_go_mod["Go"]
    pins = {req["Path"]: req["Version"] for req in gocloud_go_mod.get("Require") or []}
    go_version = go_mod.get("Go", "")
    if go_version_key(go_version) > go_version_key(max_go):
        errors.append(f"go.mod: go {go_version} is newer than Go gcloud's Go {max_go}")
    toolchain = go_mod.get("Toolchain")
    if toolchain and go_version_key(toolchain) > go_version_key(max_go):
        errors.append(f"go.mod: toolchain {toolchain} is newer than Go gcloud's Go {max_go}")
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


def check_imports(imports):
    """Reports forbidden imports. imports maps each package to its non-test imports."""
    errors = []
    for pkg, deps in sorted(imports.items()):
        for dep in deps:
            for pattern, reason in FORBIDDEN_IMPORTS:
                if pattern.fullmatch(dep):
                    errors.append(f"{pkg}: imports {dep}, which is not allowed: {reason}")
    return errors


def check_test_only_modules(dep_modules):
    """Reports test-only modules that non-test code depends on."""
    return [f"go.mod: {path} is listed as test-only, but non-test code depends on it"
            for path in sorted(TEST_ONLY_MODULES) if path in dep_modules]


def check_sources(root=MODULE_DIR):
    """Reports vendor directories and calls to patched functions in non-test files."""
    errors = []
    for dirpath, dirs, files in os.walk(root):
        if "vendor" in dirs:
            errors.append(f"{os.path.join(dirpath, 'vendor')}: vendor directories are not allowed")
            dirs.remove("vendor")
        for name in sorted(files):
            if not name.endswith(".go") or name.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    if line.lstrip().startswith("//"):
                        continue
                    for call in _PATCHED_CALL_RE.findall(line):
                        errors.append(f"{path}:{lineno}: calls {call}, which google3 patches")
    return errors


def list_imports():
    """Returns each package's non-test imports (go list leaves out _test.go files)."""
    out = run_go(["list", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./..."])
    imports = {}
    for line in out.splitlines():
        if line.strip():
            pkg, *deps = line.split()
            imports[pkg] = deps
    return imports


def list_dep_modules():
    """Returns the modules that non-test code depends on, directly or indirectly."""
    out = run_go(["list", "-deps", "-f", "{{with .Module}}{{.Path}}{{end}}", "./..."])
    return set(out.split())


def main():
    errors = check_requirements(go_mod_json("go.mod", cwd=MODULE_DIR),
                                go_mod_json(GO_GCLOUD_GO_MOD))
    errors += check_imports(list_imports())
    errors += check_test_only_modules(list_dep_modules())
    errors += check_sources()
    for error in errors:
        print(f"::error::{error}")
    if errors:
        print(f"{len(errors)} compatibility problem(s) found.")
        return 1
    print("oauth2lib is compatible with Go gcloud and google3.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
