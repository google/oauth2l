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
"""Tests for oauth2lib_compat.py.

Run from the repository root:

    python3 -m unittest discover -s .github/scripts -p '*_test.py'
"""

import os
import tempfile
import unittest

import oauth2lib_compat as compat

GOCLOUD = {
    "Go": "1.27.3",
    "Require": [
        {"Path": "cloud.google.com/go/auth", "Version": "v0.23.0"},
        {"Path": "google.golang.org/genproto", "Version": "v0.0.0-20260715232425-e75dac1f907d"},
    ],
}


def mod(requires=None, go="1.26.0", replace=None):
    if requires is None:
        requires = {"cloud.google.com/go/auth": "v0.23.0"}
    return {
        "Go": go,
        "Require": [{"Path": p, "Version": v} for p, v in requires.items()],
        "Replace": replace,
    }


class CheckRequirementsTest(unittest.TestCase):

    def test_allowed(self):
        self.assertEqual(compat.check_requirements(mod(), GOCLOUD), [])

    def test_older_version_allowed(self):
        self.assertEqual(
            compat.check_requirements(mod({"cloud.google.com/go/auth": "v0.22.0"}), GOCLOUD), [])

    def test_newer_version_rejected(self):
        errors = compat.check_requirements(mod({"cloud.google.com/go/auth": "v0.24.1"}), GOCLOUD)
        self.assertEqual(len(errors), 1)
        self.assertIn("newer than the allowed v0.23.0", errors[0])

    def test_newer_pseudo_version_rejected(self):
        errors = compat.check_requirements(
            mod({"google.golang.org/genproto": "v0.0.0-20260801000000-aaaaaaaaaaaa"}), GOCLOUD)
        self.assertEqual(len(errors), 1)

    def test_newer_go_rejected(self):
        self.assertEqual(len(compat.check_requirements(mod(go="1.28"), GOCLOUD)), 1)

    def test_same_go_allowed(self):
        self.assertEqual(compat.check_requirements(mod(go="1.27.3"), GOCLOUD), [])

    def test_unknown_module_rejected(self):
        errors = compat.check_requirements(mod({"example.com/new": "v1.0.0"}), GOCLOUD)
        self.assertEqual(len(errors), 1)
        self.assertIn("not used by Go gcloud", errors[0])

    def test_test_only_module_allowed(self):
        self.assertEqual(compat.check_requirements(mod({"go.uber.org/goleak": "v1.3.0"}), GOCLOUD), [])

    def test_test_only_module_newer_rejected(self):
        self.assertEqual(
            len(compat.check_requirements(mod({"go.uber.org/goleak": "v1.4.0"}), GOCLOUD)), 1)

    def test_replace_rejected(self):
        errors = compat.check_requirements(
            mod(replace=[{"Old": {"Path": "cloud.google.com/go/auth"}}]), GOCLOUD)
        self.assertEqual(len(errors), 1)
        self.assertIn("replace directive", errors[0])


class ParseVersionTest(unittest.TestCase):

    def assertOrdered(self, *versions):
        keys = [compat.parse_version(v) for v in versions]
        self.assertEqual(keys, sorted(keys), versions)
        self.assertEqual(len(set(keys)), len(keys), versions)

    def test_releases(self):
        self.assertOrdered("v0.9.0", "v0.10.0", "v0.23.0", "v1.0.0")

    def test_prerelease_before_release(self):
        self.assertOrdered("v0.1.0-rc.1", "v0.1.0-rc.2", "v0.1.0-rc.10", "v0.1.0")

    def test_pseudo_version_before_release(self):
        self.assertOrdered("v1.2.3-0.20260101000000-abcdef123456", "v1.2.3")

    def test_pseudo_versions_by_time(self):
        self.assertOrdered("v0.0.0-20260715232425-e75dac1f907d",
                           "v0.0.0-20260803160001-6ac0973c030d")

    def test_incompatible_ignored(self):
        self.assertEqual(compat.parse_version("v2.0.0+incompatible"),
                         compat.parse_version("v2.0.0"))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            compat.parse_version("1.2.3")


class CheckImportsTest(unittest.TestCase):

    def test_allowed(self):
        imports = {"m/p": ["context", "crypto/sha256", "crypto/x509", "cloud.google.com/go/auth"]}
        self.assertEqual(compat.check_imports(imports), [])

    def test_blocked_crypto(self):
        errors = compat.check_imports({"m/p": ["crypto/rsa", "golang.org/x/crypto/md4"]})
        self.assertEqual(len(errors), 2)

    def test_patched_package(self):
        errors = compat.check_imports({"m/p": ["cloud.google.com/go/auth/httptransport"]})
        self.assertEqual(len(errors), 1)

    def test_prefix_not_matched(self):
        self.assertEqual(compat.check_imports({"m/p": ["crypto/rsa2", "example.com/crypto/rsa"]}), [])


class CheckTestOnlyModulesTest(unittest.TestCase):

    def test_not_used(self):
        self.assertEqual(compat.check_test_only_modules({"cloud.google.com/go/auth"}), [])

    def test_used_by_non_test_code(self):
        self.assertEqual(len(compat.check_test_only_modules({"go.uber.org/goleak"})), 1)


class CheckSourcesTest(unittest.TestCase):

    def write(self, root, name, text):
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_patched_call(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "a.go", "package a\nvar _ = impersonate.NewCredentials\n")
            errors = compat.check_sources(root)
            self.assertEqual(len(errors), 1)
            self.assertIn("impersonate.NewCredentials", errors[0])

    def test_comment_and_test_file_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "a.go", "package a\n// Unlike idtoken.NewCredentials, this ...\n")
            self.write(root, "a_test.go", "package a\nvar _ = idtoken.NewCredentials\n")
            self.assertEqual(compat.check_sources(root), [])

    def test_vendor_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "vendor/x/x.go", "package x\n")
            self.assertEqual(len(compat.check_sources(root)), 1)


if __name__ == "__main__":
    unittest.main()
