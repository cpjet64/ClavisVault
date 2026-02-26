# Plan: Coverage Maximization Pass v2

## Goal
Push coverage beyond the previous pass with additional test-backed gains and updated evidence.

## Steps
- [x] Create branch `coverage-max-20260225-210205`.
- [ ] Run full baseline using `cargo nextest run --all-features && cargo llvm-cov --html`.
- [ ] Extract uncovered lines/functions and classify dead vs uncoverable vs testable.
- [ ] Implement focused tests for the highest-impact testable uncovered paths.
- [ ] Re-run coverage and iterate until no meaningful gain remains.
- [ ] Update `docs/coverage-report.md` and `.AGENTS/todo.md`.
- [ ] Run `just ci-fast` then `just ci-deep`.
- [ ] Commit verified local change set(s) without push.
