# CLAUDE.md - ClavisVault AI Instructions

**Critical first step for every task:**

1. Read `AGENTS.md` completely (it is the project-specific rulebook and contains the safe list of all keys/vars).
2. Then read `docs/SPEC.md` (the full technical specification — never deviate).

This project has extremely high security, encryption, and testing standards.  
Any deviation can break the security invariants or file-safety guarantees.

When the user gives you:
- An “Implementation Prompt” → implement exactly, nothing more, nothing less.
- A “Verification Prompt” → run every check and fix until it reports “PASSED”.

Current status: Initial monorepo setup phase (core crate next).

Primary goal: Build the most secure, beautiful, and thoughtful developer key vault ever made.

Good luck! 🗝️