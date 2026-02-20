#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from pathlib import Path
import sys

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from check_desktop_network_policy import (  # noqa: E402
    check_css_policy,
    check_tauri_csp_policy,
)


class CheckDesktopNetworkPolicyTests(unittest.TestCase):
    def make_file(self, name: str, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        path = Path(temp_dir.name) / name
        path.write_text(content, encoding="utf-8")
        self.addCleanup(temp_dir.cleanup)
        return path

    def make_tauri_conf(self, csp: str) -> Path:
        payload = {"app": {"security": {"csp": csp}}}
        return self.make_file("tauri.conf.json", json.dumps(payload))

    def test_css_rejects_external_https_import(self) -> None:
        css_path = self.make_file(
            "styles.css",
            '@import url("https://fonts.googleapis.com/css2?family=Space+Grotesk");',
        )
        errors = check_css_policy(css_path)
        self.assertTrue(any("external @import over http/https is forbidden" in error for error in errors))

    def test_css_allows_local_import(self) -> None:
        css_path = self.make_file(
            "styles.css",
            textwrap.dedent(
                """
                @import "./tokens.css";
                body { font-family: "Segoe UI", sans-serif; }
                """
            ).strip(),
        )
        self.assertEqual(check_css_policy(css_path), [])

    def test_connect_src_rejects_https_scheme(self) -> None:
        conf_path = self.make_tauri_conf("default-src 'self'; connect-src 'self' https:;")
        errors = check_tauri_csp_policy(conf_path)
        self.assertTrue(any("forbidden broad source(s): https:" in error for error in errors))

    def test_connect_src_rejects_http_and_wildcard(self) -> None:
        conf_path = self.make_tauri_conf("default-src 'self'; connect-src http: *;")
        errors = check_tauri_csp_policy(conf_path)
        self.assertTrue(any("forbidden broad source(s): *, http:" in error for error in errors))

    def test_connect_src_allows_self_only(self) -> None:
        conf_path = self.make_tauri_conf("default-src 'self'; connect-src 'self';")
        self.assertEqual(check_tauri_csp_policy(conf_path), [])


if __name__ == "__main__":
    unittest.main()
