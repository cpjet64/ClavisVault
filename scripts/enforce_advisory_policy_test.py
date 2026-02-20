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

from enforce_advisory_policy import (  # noqa: E402
    AdvisoryKey,
    BaselineEntry,
    load_baseline,
    parse_deny_json_lines,
    validate_policy,
)


class EnforceAdvisoryPolicyTests(unittest.TestCase):
    def make_baseline_file(self, content: str) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        path = Path(temp_dir.name) / "advisory-baseline.toml"
        path.write_text(content, encoding="utf-8")
        self.addCleanup(temp_dir.cleanup)
        return path

    def make_entry(
        self,
        *,
        kind: str,
        advisory_id: str,
        package: str,
        expiry: date,
    ) -> BaselineEntry:
        key = AdvisoryKey(kind=kind, advisory_id=advisory_id, package=package)
        return BaselineEntry(key=key, expiry=expiry, rationale="tracked dependency risk")

    def test_load_baseline_parses_entries(self) -> None:
        baseline_path = self.make_baseline_file(
            textwrap.dedent(
                """
                version = 1

                [[advisories]]
                id = "RUSTSEC-2024-0415"
                package = "gtk"
                kind = "unmaintained"
                expiry = "2026-12-31"
                rationale = "Tracked transitively."
                """
            ).strip()
        )

        baseline = load_baseline(baseline_path)
        expected_key = AdvisoryKey(
            kind="unmaintained",
            advisory_id="RUSTSEC-2024-0415",
            package="gtk",
        )
        self.assertIn(expected_key, baseline)
        self.assertEqual(baseline[expected_key].expiry, date(2026, 12, 31))

    def test_load_baseline_rejects_invalid_kind(self) -> None:
        baseline_path = self.make_baseline_file(
            textwrap.dedent(
                """
                [[advisories]]
                id = "RUSTSEC-2024-0415"
                package = "gtk"
                kind = "notice"
                expiry = "2026-12-31"
                rationale = "Invalid kind for baseline."
                """
            ).strip()
        )

        with self.assertRaises(ValueError):
            load_baseline(baseline_path)

    def test_parse_deny_json_lines_extracts_supported_kinds(self) -> None:
        raw = "\n".join(
            [
                (
                    '{"type":"diagnostic","fields":{"code":"vulnerability","advisory":'
                    '{"id":"RUSTSEC-2026-0001","package":"openssl"}}}'
                ),
                (
                    '{"type":"diagnostic","fields":{"code":"unmaintained","advisory":'
                    '{"id":"RUSTSEC-2024-0415","package":"gtk","informational":"unmaintained"}}}'
                ),
                '{"type":"summary","fields":{"advisories":{"errors":1}}}',
                "not-json",
            ]
        )

        observed = parse_deny_json_lines(raw)
        self.assertEqual(
            observed,
            {
                AdvisoryKey(
                    kind="vulnerability",
                    advisory_id="RUSTSEC-2026-0001",
                    package="openssl",
                ),
                AdvisoryKey(
                    kind="unmaintained",
                    advisory_id="RUSTSEC-2024-0415",
                    package="gtk",
                ),
            },
        )

    def test_validate_policy_rejects_vulnerability(self) -> None:
        observed = {
            AdvisoryKey(
                kind="vulnerability",
                advisory_id="RUSTSEC-2026-0001",
                package="openssl",
            )
        }
        errors = validate_policy(observed, {}, today=date(2026, 2, 20))
        self.assertTrue(any("vulnerability advisories are forbidden" in e for e in errors))

    def test_validate_policy_rejects_unexpected_unmaintained(self) -> None:
        observed = {
            AdvisoryKey(
                kind="unmaintained",
                advisory_id="RUSTSEC-2024-0415",
                package="gtk",
            )
        }
        errors = validate_policy(observed, {}, today=date(2026, 2, 20))
        self.assertTrue(any("must be added to baseline" in e for e in errors))

    def test_validate_policy_rejects_stale_baseline_entries(self) -> None:
        entry = self.make_entry(
            kind="unmaintained",
            advisory_id="RUSTSEC-2024-0415",
            package="gtk",
            expiry=date(2026, 12, 31),
        )
        errors = validate_policy(set(), {entry.key: entry}, today=date(2026, 2, 20))
        self.assertTrue(any("stale baseline entries found" in e for e in errors))

    def test_validate_policy_rejects_expired_entries(self) -> None:
        entry = self.make_entry(
            kind="unmaintained",
            advisory_id="RUSTSEC-2024-0415",
            package="gtk",
            expiry=date(2026, 1, 1),
        )
        observed = {entry.key}
        errors = validate_policy(observed, {entry.key: entry}, today=date(2026, 2, 20))
        self.assertTrue(any("baseline entries have expired" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
