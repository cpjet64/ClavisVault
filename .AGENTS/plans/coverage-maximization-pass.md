# Plan: Coverage Maximization Pass

## Goal
Raise measurable coverage in testable uncovered core paths and document evidence.

## Steps
- [x] Reproduce baseline coverage and capture uncovered inventory.
- [x] Classify uncovered lines as testable vs. non-actionable.
- [x] Implement focused unit tests for testable paths.
- [x] Re-run coverage and validate improvement.
- [ ] Run full local gates (`just ci-fast`, `just ci-deep`) before integration.
- [ ] Commit verified change set locally using required commit template.
