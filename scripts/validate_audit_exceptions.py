#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, date, timezone
from pathlib import Path
from typing import Iterable

import tomllib


REQUIRED_REASON_RE = re.compile(
    r"^expiry:\s*(\d{4}-\d{2}-\d{2});\s*rationale:\s*(.+)$",
    re.IGNORECASE,
)
ADVISORY_ID_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")


def load_ignored_advisories(deny_toml: Path, *, today: date | None = None) -> list[str]:
    today = today or datetime.now(timezone.utc).date()

    with deny_toml.open("rb") as handle:
        deny_data = tomllib.load(handle)

    ignores = deny_data.get("advisories", {}).get("ignore", [])
    if not isinstance(ignores, list):
        raise ValueError("Use table-form advisory exceptions in deny.toml: "
                         "[[advisories.ignore]] with id and reason.")
    if not ignores:
        return []

    ids: list[str] = []
    for item in ignores:
        if not isinstance(item, dict):
            raise ValueError("Use table-form advisory exceptions in deny.toml: "
                             "[[advisories.ignore]] with id and reason.")

        advisory_id = item.get("id")
        reason = (item.get("reason") or "").strip()

        if not isinstance(advisory_id, str) or not advisory_id:
            raise ValueError("Every [[advisories.ignore]] entry requires a non-empty id.")
        if not ADVISORY_ID_RE.fullmatch(advisory_id):
            raise ValueError(f"Invalid advisory id '{advisory_id}'.")

        if not isinstance(reason, str) or not reason:
            raise ValueError(f"advisory {advisory_id} must include a reason with expiry and rationale.")

        match = REQUIRED_REASON_RE.match(reason)
        if not match:
            raise ValueError(
                f"advisory {advisory_id} reason must match 'expiry: YYYY-MM-DD; rationale: ...'"
            )

        expiry_text, rationale = match.groups()
        if not rationale.strip():
            raise ValueError(f"advisory {advisory_id} reason missing rationale text.")

        try:
            expiry = datetime.strptime(expiry_text, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError(f"advisory {advisory_id} has invalid expiry date '{expiry_text}'.")

        if expiry < today:
            raise ValueError(
                f"advisory {advisory_id} expired on {expiry}. "
                "Update deny.toml before continuing."
            )
        ids.append(advisory_id)
    return ids


def emit_ignore_args(ids: Iterable[str]) -> str:
    return " ".join(f"--ignore {advisory_id}" for advisory_id in ids)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--deny-toml",
        type=Path,
        default=Path("deny.toml"),
        help="Path to deny.toml",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        ids = load_ignored_advisories(args.deny_toml)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if ids:
        print(
            "deny.toml must not include advisory ignores under the new zero-ignore policy.",
            file=sys.stderr,
        )
        print(f"found advisory ignores: {', '.join(ids)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
