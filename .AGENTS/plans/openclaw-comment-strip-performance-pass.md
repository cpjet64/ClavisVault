# Plan: OpenClaw Comment Strip Performance Pass

## Scope
- Keep checklist artifacts synchronized while completing any remaining unchecked items.
- Execute a focused, reversible performance optimization in `crates/core/src/openclaw.rs`.
- Validate correctness and repository quality gates before local commit.

## Steps
1. Validate checklist state in `MASTER-CHECKLIST.md` and `execution-plan.md`.
2. Capture baseline timings for the openclaw comment-strip test path.
3. Apply minimal optimization to remove unnecessary intermediate allocations.
4. Run targeted core tests for `openclaw` parser behavior.
5. Capture post-change timings and document deltas in `docs/optimization-report.md`.
6. Run `just ci-fast` and `just ci-deep`.
7. Commit locally with required message/body format (no push).
