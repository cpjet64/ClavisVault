# Plan: Complete Remaining Checklist + Execution Plan Items

## Scope
- Finish all unchecked items in `MASTER-CHECKLIST.md`.
- Keep `EXECUTION-PLAN.md` and `.AGENTS/todo.md` synchronized with verified progress.
- Run `just ci-fast` and `just ci-deep` before final integration.
- Commit locally after each verified change set; do not push.

## Execution batches

1. Preflight and baseline
- Classify existing modified/untracked files into intended changes vs generated artifacts.
- Update `.gitignore` if newly observed generated artifacts are missing.
- Remove generated runtime artifacts from working tree.

2. Gap audit
- Map each unchecked checklist item to implementation evidence (code + tests + commands).
- Record true missing/partial items that still require implementation.

3. Implementation loop
- Apply minimal fixes for each missing item.
- Add/update tests to verify each behavior.
- Re-run targeted checks after each fix.

4. Plan/checklist synchronization
- Mark completed checklist items with evidence-backed confidence.
- Update execution status notes in `EXECUTION-PLAN.md`.
- Keep `.AGENTS/todo.md` checkbox state current.

5. Verification and integration
- Run `just ci-fast`.
- Run `just ci-deep`.
- Final self-review for security invariants and scope conformance.

6. Commit strategy
- Commit each verified change set with `[type][area]: concise summary`.
- Include context, change, risk, tests, and verification in commit body.
- Never run `git push`.
