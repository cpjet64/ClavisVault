# TODO / Plan

## Task: Upgrade dependencies/tooling (dependency-upgrader workflow)

- [x] Load dependency-upgrader skill references and supporting scripts.
- [x] Re-bootstrap Windows native build environment (`ensure-vcvars.ps1`).
- [x] Record baseline inventory and risk plan in `docs/dependency-upgrade-report.md`.
- [x] Plan and execute conservative upgrade waves (security-first, then patch/minor).
- [x] Validate each wave with required quality/security gates.
- [x] Commit each verified wave locally (no push).
- [x] Finalize report with outcomes, residual risk, and rollback notes.

## Review

- Conservative dependency wave completed without Rust lockfile churn.
- Desktop Node lockfile updated with compatible package refresh (`crates/desktop/package-lock.json`).
- Validation passed:
  - `just ci-fast`
  - `just ci-deep`
- Security gates remained warning-only where previously allowlisted (`cargo audit`), and `npm audit --omit=dev` reported `0 vulnerabilities`.
