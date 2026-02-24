#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import textwrap
import unittest
from datetime import date
from pathlib import Path
import sys

CURRENT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CURRENT_DIR))

from validate_audit_exceptions import emit_ignore_args, load_ignored_advisories


class ValidateAuditExceptionsTests(unittest.TestCase):
    def make_file(self, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        path = Path(temp_dir.name) / "deny.toml"
        path.write_text(content, encoding="utf-8")
        self.addCleanup(temp_dir.cleanup)
        return path

    def test_valid_entries_parse_and_emit_args(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                [[advisories.ignore]]
                id = "RUSTSEC-2026-0001"
                reason = "expiry: 2026-12-31; rationale: temporary waiver for dependency freeze."

                [[advisories.ignore]]
                id = "RUSTSEC-2027-0002"
                reason = "expiry: 2027-01-15; rationale: third-party backport under review."
                """
            ).strip()
        )
        ids = load_ignored_advisories(path, today=date(2026, 2, 20))
        self.assertEqual(ids, ["RUSTSEC-2026-0001", "RUSTSEC-2027-0002"])
        self.assertEqual(
            emit_ignore_args(ids),
            "--ignore RUSTSEC-2026-0001 --ignore RUSTSEC-2027-0002",
        )

    def test_invalid_advisory_id_is_rejected(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                [[advisories.ignore]]
                id = "BAD-2026-0001"
                reason = "expiry: 2026-12-31; rationale: invalid format test."
                """
            ).strip()
        )
        with self.assertRaises(ValueError):
            load_ignored_advisories(path, today=date(2026, 2, 20))

    def test_expired_entry_is_rejected(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                [[advisories.ignore]]
                id = "RUSTSEC-2026-0001"
                reason = "expiry: 2025-01-01; rationale: expired waiver."
                """
            ).strip()
        )
        with self.assertRaises(ValueError):
            load_ignored_advisories(path, today=date(2026, 2, 20))

    def test_malformed_reason_is_rejected(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                [[advisories.ignore]]
                id = "RUSTSEC-2026-0001"
                reason = "missing-fields"
                """
            ).strip()
        )
        with self.assertRaises(ValueError):
            load_ignored_advisories(path, today=date(2026, 2, 20))

    def test_non_dict_items_are_rejected(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                ignore = ["not-a-table"]
                """
            ).strip()
        )
        with self.assertRaises(ValueError):
            load_ignored_advisories(path, today=date(2026, 2, 20))

    def test_empty_ignore_list_returns_empty_args(self) -> None:
        path = self.make_file(
            textwrap.dedent(
                """
                [advisories]
                """
            ).strip()
        )
        ids = load_ignored_advisories(path, today=date(2026, 2, 20))
        self.assertEqual(ids, [])
        self.assertEqual(emit_ignore_args(ids), "")

    def test_missing_deny_toml_path_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_ignored_advisories(Path("definitely-missing-deny.toml"), today=date(2026, 2, 20))


if __name__ == "__main__":
    unittest.main()
