#!/usr/bin/env python3
"""Stdlib-only static CI release-gate contract checks (not a CI execution)."""
import pathlib
import re
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml'

class NativeGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = WORKFLOW.read_text(encoding='utf-8')
        match = re.search(r'(?ms)^  native:\n(.*?)(?=^  [a-zA-Z_-]+:\n|\Z)', cls.ci)
        assert match, 'native job missing'
        cls.native = match.group(1)

    def test_three_target_platforms(self):
        targets = {
            'ubuntu-24.04-arm': ('linux', 'arm64'),
            'macos-15': ('darwin', 'arm64'),
            'windows-2025': ('windows', 'amd64'),
        }
        found = re.findall(r'- os:\s*([\w.\-]+)\s*\n\s*expected_os:\s*(\w+)\s*\n\s*expected_arch:\s*(\w+)', self.native)
        self.assertEqual(set(found), {(os_name, pair[0], pair[1]) for os_name, pair in targets.items()})

    def test_full_go_native_gates(self):
        for check in ('go test -count=1 ./...', 'go test -race -count=1 ./...',
                      'go test -shuffle=on -count=2 ./...', 'go vet ./...',
                      'go build ./...', 'go mod verify', 'go run ./cmd/proofgraph version'):
            with self.subTest(command=check):
                self.assertIn(check, self.native)

    def test_native_release_gate_has_no_fail_open(self):
        self.assertIn("github.event_name == 'workflow_dispatch'", self.native)
        self.assertIn('refs/tags/v1.', self.native)
        self.assertIn('EXPECTED_OS', self.native)
        self.assertIn('EXPECTED_ARCH', self.native)
        self.assertIn('go env GOOS', self.native)
        self.assertIn('go env GOARCH', self.native)
        self.assertNotIn('continue-on-error: true', self.native)
        self.assertNotIn('|| true', self.native)

    def test_exact_supported_toolchain(self):
        self.assertRegex(self.native, r"go-version:\s*'1[.]27[.]2'")
        self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', self.native)
        self.assertIn('actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e', self.native)

if __name__ == '__main__':
    unittest.main(verbosity=2)
