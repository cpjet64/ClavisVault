# TODO / Plan

## Task: Complete remaining unchecked execution items

- [x] Classify pre-existing dirty workspace into atomic change sets and clean generated artifacts.
- [x] Audit every unchecked item in `MASTER-CHECKLIST.md` against code/tests and identify real gaps.
- [x] Implement/fix remaining gaps with minimal reversible edits and add/adjust tests as required.
- [x] Update `MASTER-CHECKLIST.md` and `EXECUTION-PLAN.md` with current verified status notes.
- [x] Run `just ci-fast`.
- [x] Run `just ci-deep`.
- [x] Commit each verified change set locally (no push).

## Review

- Verified `just ci-fast` completion.
- Ran `just ci-deep` before integration and resolved local gate blockers (security policy alignment + nextest retries for transient flakes).
- Verified post-fix build/test/docs commands completed successfully.
