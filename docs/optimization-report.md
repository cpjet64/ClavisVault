# Optimization Report

Date: 2026-02-26  
Branch: `perf-opt-1772069304`  
Scope: `crates/core/src/openclaw.rs` (`strip_line_comments`)

## Objective
Reduce parser overhead in JSONC line-comment stripping without changing behavior.

## Finding 1: Intermediate character vector allocation
- Previous implementation converted the entire input to `Vec<char>` before scanning.
- This adds one full-size intermediate allocation and extra indexing overhead.

## Change
- Replaced index-based `Vec<char>` traversal with streaming `chars().peekable()` traversal.
- Preallocated output with `String::with_capacity(content.len())`.
- Preserved escaping, string-state handling, and newline retention semantics.

## Verification
- Targeted affected module tests:
  - `cargo test -p clavisvault-core openclaw::tests:: -- --nocapture`
  - Result: `37 passed`, `0 failed`.

## Measurements
Command (same for baseline and post-change):

```powershell
cargo test -q -p clavisvault-core strip_line_comments_remains_accurate_after_multiple_comment_blocks --release -- --exact
```

Baseline runs (ms): `32427.69`, `871.57`, `824.33`, `1340.65`, `1219.69`  
Post-change runs (ms): `26944.11`, `2812.97`, `970.98`, `884.49`, `754.08`

Notes:
- First run includes cold-start compile noise.
- Comparison is taken over warm runs.

Warm-window summary:
- Baseline warm median: `1045.63 ms`
- Post-change warm median: `927.74 ms`
- Estimated improvement: `11.27%` faster median in sampled warm runs.

## Full gate verification
- `just ci-fast`: PASSED
- `just ci-deep`: PASSED

Notes:
- `cargo deny check bans licenses sources` emitted duplicate crate-version warnings, but the overall `just ci-deep` recipe completed successfully with exit code `0`.
