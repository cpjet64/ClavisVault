#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import tomllib


SUPPORTED_BASELINE_KINDS = frozenset({"unmaintained", "unsound"})
ENFORCED_KINDS = SUPPORTED_BASELINE_KINDS | {"vulnerability"}
ADVISORY_ID_RE = re.compile(r"^[A-Z0-9-]+$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True, order=True)
class AdvisoryKey:
    kind: str
    advisory_id: str
    package: str


@dataclass(frozen=True)
class BaselineEntry:
    key: AdvisoryKey
    expiry: date
    rationale: str


def _require_non_empty_str(value: object, field_name: str, *, entry_index: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"baseline entry #{entry_index} requires non-empty '{field_name}'.")
    return value.strip()


def _parse_iso_date(value: str, field_name: str, *, entry_index: int) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"baseline entry #{entry_index} has invalid {field_name} '{value}'. "
            "Expected YYYY-MM-DD."
        ) from exc


def load_baseline(path: Path) -> dict[AdvisoryKey, BaselineEntry]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)

    raw_entries = data.get("advisories")
    if not isinstance(raw_entries, list):
        raise ValueError("baseline must define [[advisories]] entries.")

    baseline: dict[AdvisoryKey, BaselineEntry] = {}
    for idx, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"baseline entry #{idx} must be a TOML table.")

        advisory_id = _require_non_empty_str(raw.get("id"), "id", entry_index=idx)
        package = _require_non_empty_str(raw.get("package"), "package", entry_index=idx)
        kind = _require_non_empty_str(raw.get("kind"), "kind", entry_index=idx).lower()
        expiry_text = _require_non_empty_str(raw.get("expiry"), "expiry", entry_index=idx)
        rationale = _require_non_empty_str(raw.get("rationale"), "rationale", entry_index=idx)

        if not ADVISORY_ID_RE.fullmatch(advisory_id):
            raise ValueError(f"baseline entry #{idx} has invalid advisory id '{advisory_id}'.")
        if not PACKAGE_RE.fullmatch(package):
            raise ValueError(f"baseline entry #{idx} has invalid package '{package}'.")
        if kind not in SUPPORTED_BASELINE_KINDS:
            raise ValueError(
                f"baseline entry #{idx} has unsupported kind '{kind}'. "
                f"Expected one of: {', '.join(sorted(SUPPORTED_BASELINE_KINDS))}."
            )

        expiry = _parse_iso_date(expiry_text, "expiry", entry_index=idx)
        key = AdvisoryKey(kind=kind, advisory_id=advisory_id, package=package)
        if key in baseline:
            raise ValueError(
                "duplicate baseline advisory entry for "
                f"{key.kind}:{key.advisory_id}:{key.package}."
            )

        baseline[key] = BaselineEntry(key=key, expiry=expiry, rationale=rationale)

    return baseline


def parse_deny_json_lines(raw_output: str) -> set[AdvisoryKey]:
    advisories: set[AdvisoryKey] = set()
    for line in raw_output.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            continue

        if payload.get("type") != "diagnostic":
            continue

        fields = payload.get("fields")
        if not isinstance(fields, dict):
            continue

        advisory = fields.get("advisory")
        if not isinstance(advisory, dict):
            continue

        advisory_id = advisory.get("id")
        package = advisory.get("package")
        if not isinstance(advisory_id, str) or not advisory_id:
            continue
        if not isinstance(package, str) or not package:
            continue

        kind = advisory.get("informational")
        if not isinstance(kind, str) or not kind:
            code = fields.get("code")
            kind = code if isinstance(code, str) else ""
        kind = kind.lower()
        if kind not in ENFORCED_KINDS:
            continue

        advisories.add(AdvisoryKey(kind=kind, advisory_id=advisory_id, package=package))
    return advisories


def validate_policy(
    observed: set[AdvisoryKey],
    baseline: dict[AdvisoryKey, BaselineEntry],
    *,
    today: date | None = None,
) -> list[str]:
    today = today or datetime.now(timezone.utc).date()

    errors: list[str] = []

    vulnerability_entries = sorted(
        key for key in observed if key.kind == "vulnerability"
    )
    if vulnerability_entries:
        errors.append("vulnerability advisories are forbidden:")
        errors.extend(
            f"  - {key.advisory_id} ({key.package})" for key in vulnerability_entries
        )

    baseline_keys = set(baseline)
    observed_managed = {key for key in observed if key.kind in SUPPORTED_BASELINE_KINDS}

    missing_from_baseline = sorted(observed_managed - baseline_keys)
    if missing_from_baseline:
        errors.append("new unmaintained/unsound advisories must be added to baseline:")
        errors.extend(
            f"  - {key.kind}:{key.advisory_id}:{key.package}"
            for key in missing_from_baseline
        )

    stale_baseline_entries = sorted(baseline_keys - observed_managed)
    if stale_baseline_entries:
        errors.append("stale baseline entries found (no longer emitted by cargo deny):")
        errors.extend(
            f"  - {key.kind}:{key.advisory_id}:{key.package}"
            for key in stale_baseline_entries
        )

    expired_entries = sorted(
        (entry for entry in baseline.values() if entry.expiry < today),
        key=lambda entry: entry.key,
    )
    if expired_entries:
        errors.append("baseline entries have expired and must be reviewed:")
        errors.extend(
            f"  - {entry.key.kind}:{entry.key.advisory_id}:{entry.key.package} "
            f"(expired {entry.expiry.isoformat()})"
            for entry in expired_entries
        )

    return errors


def run_cargo_deny_advisories() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["cargo", "deny", "-f", "json", "check", "advisories"],
        check=False,
        capture_output=True,
        text=True,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("security/advisory-baseline.toml"),
        help="Path to advisory baseline TOML file.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        result = run_cargo_deny_advisories()
    except OSError as exc:
        print(f"failed to run cargo deny: {exc}", file=sys.stderr)
        return 1

    combined_output = "\n".join(part for part in (result.stdout, result.stderr) if part)
    observed = parse_deny_json_lines(combined_output)

    errors = validate_policy(observed, baseline)
    if result.returncode not in (0, 1):
        errors.append(f"cargo deny exited with unexpected status {result.returncode}.")
    if result.returncode != 0 and not observed:
        errors.append("cargo deny failed before producing advisory diagnostics.")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
