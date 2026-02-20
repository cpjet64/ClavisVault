#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXTERNAL_IMPORT_RE = re.compile(
    r"@import\s+(?:url\(\s*)?[\"']?\s*https?://",
    re.IGNORECASE,
)
CONNECT_SRC_RE = re.compile(r"\bconnect-src\b(?P<value>[^;]*)(?:;|$)", re.IGNORECASE)
FORBIDDEN_CONNECT_SRC_TOKENS = frozenset({"https:", "http:", "*"})


def check_css_policy(css_path: Path) -> list[str]:
    try:
        css_text = css_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"failed to read CSS policy file '{css_path}': {exc}"]

    if EXTERNAL_IMPORT_RE.search(css_text):
        return [
            f"{css_path}: external @import over http/https is forbidden; use local/system fonts only."
        ]
    return []


def extract_connect_src_tokens(csp: str) -> list[str]:
    match = CONNECT_SRC_RE.search(csp)
    if not match:
        return []
    return [token for token in match.group("value").strip().split() if token]


def check_tauri_csp_policy(tauri_conf_path: Path) -> list[str]:
    try:
        config = json.loads(tauri_conf_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"failed to read Tauri config '{tauri_conf_path}': {exc}"]

    csp = (((config.get("app") or {}).get("security") or {}).get("csp"))
    if not isinstance(csp, str) or not csp.strip():
        return [f"{tauri_conf_path}: app.security.csp must be a non-empty string."]

    connect_src_tokens = extract_connect_src_tokens(csp)
    if not connect_src_tokens:
        return [f"{tauri_conf_path}: CSP must define a connect-src directive."]

    forbidden = sorted(
        token for token in connect_src_tokens if token.lower() in FORBIDDEN_CONNECT_SRC_TOKENS
    )
    if forbidden:
        return [
            f"{tauri_conf_path}: connect-src contains forbidden broad source(s): {', '.join(forbidden)}."
        ]
    return []


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--css",
        type=Path,
        default=Path("crates/desktop/src/styles.css"),
        help="Path to desktop CSS entry file.",
    )
    parser.add_argument(
        "--tauri-conf",
        type=Path,
        default=Path("crates/desktop/src-tauri/tauri.conf.json"),
        help="Path to desktop tauri.conf.json.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    errors = []
    errors.extend(check_css_policy(args.css))
    errors.extend(check_tauri_csp_policy(args.tauri_conf))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
