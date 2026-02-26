# TODO / Plan

## Task: Performance optimization pass (openclaw comment stripping)

- [x] Confirm remaining unchecked items in `MASTER-CHECKLIST.md` and `execution-plan.md`.
- [x] Identify hotspot candidate and baseline command.
- [x] Implement low-risk optimization in `crates/core/src/openclaw.rs`.
- [x] Run targeted tests for affected module (`openclaw::tests::*`).
- [x] Run integration quality gates (`just ci-fast`, `just ci-deep`).
- [ ] Commit verified change set locally (no push).

## Review (in progress)

- Current checklist state: no remaining unchecked items in `MASTER-CHECKLIST.md` or `execution-plan.md`.
- Optimization applied to `strip_line_comments`: replaced pre-collected `Vec<char>` scan with streaming `chars().peekable()` scan and preallocated output capacity.
- Benchmark method: `cargo test -q -p clavisvault-core strip_line_comments_remains_accurate_after_multiple_comment_blocks --release -- --exact` (5 runs each, warm-window comparison).
- Warm median changed from `1045.63 ms` (pre) to `927.74 ms` (post), roughly `11.27%` faster on sampled runs.
- Full verification passed:
  - `just ci-fast`
  - `just ci-deep`
