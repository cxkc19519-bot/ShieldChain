# Task 7 Report: Windows Developer Commands and Phase Gate

## Status

Implemented and verified the Phase 1 Windows developer commands and documentation gate without changing product code or starting Phase 2.

## RED / GREEN Evidence

- RED: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\scripts\run-contract-tests.ps1` exited 1 because `scripts\dev.ps1` did not exist.
- GREEN: the same command passed all 17 assertions.
- The first real offline gate exposed PowerShell 5.1 parameter-default behavior; after moving root discovery after parameter binding, contracts remained green and the real gates passed.

## Full Evidence

- `scripts/test.ps1` with inherited `RUN_LIVE_DEEPSEEK_TEST=1`: backend 50 passed, 1 paid live smoke test skipped; frontend 21 passed in 3 files.
- `scripts/verify.ps1` with inherited `RUN_LIVE_DEEPSEEK_TEST=1`: Ruff passed; backend 50 passed/1 skipped; ESLint passed; TypeScript passed; frontend 21 passed; Vite built 45 modules.
- Runtime startup smoke: temporary safe `.env`; backend liveness HTTP 200; frontend HTTP 200; job stopped and `.env` removed.
- Secret scan: no real credential values; matches were safe test/source placeholders and the plan's documented scan expression.
- Future-scope source scan: no matches.
- `git diff --check`: exit 0.
- Generated/local state remained ignored: `.env`, `.venv`, `frontend/node_modules`, `frontend/dist`, and `data`.

## Files

- Created: `scripts/dev.ps1`, `scripts/test.ps1`, `scripts/verify.ps1`, `tests/scripts/run-contract-tests.ps1`, `README.md`.
- Updated: `docs/operations/local-development.md`, `docs/plans/development-roadmap.md`, `development-logs/2026-07-13.md`.

## Commit

- Required message: `docs: complete phase one engineering gate`.
- This report is included in that Task 7 commit.

## Self-review and Concerns

- Developer scripts use process APIs/argument arrays and never use `Invoke-Expression` or read/print `.env`.
- Test and verification scripts remove the inherited paid-live opt-in before spawning any test process, then restore the parent script environment on exit.
- Verification wrappers require explicit `-ContractTest`; normal production mode resolves only the repository Python environment and `npm.cmd`.
- The paid live smoke test was intentionally skipped, so real-provider connectivity is not claimed.
- Runtime job cleanup is smoke-tested; a physical Ctrl+C keystroke remains a manual terminal observation.
- Prior minor Task 3/6 findings were not changed in this scoped task.

## Review Hardening: Script Contract Quality

### Findings Addressed

- The missing-prerequisite fixture now leaves Python, `frontend/node_modules`, and `.env` absent, invokes `dev.ps1 -CheckOnly` once, and asserts exit 1 plus all three actionable paths from that same captured output.
- Static secret-file safety now parses production scripts with the PowerShell AST and rejects file-content reads regardless of whether a path is literal or indirect. Denied constructs include `Get-Content` and aliases `gc`, `type`, and `cat`; `Select-String` aliases; `System.IO.File` read/open methods; and `StreamReader` construction.
- Unsafe-sample self-tests cover literal `.env`, variable-held `.env`, aliases, `ReadAllText`, `OpenText`, and `StreamReader`. No production scripts required changes.

### Review RED / GREEN Evidence

- RED: the hardened contract suite exited 1 because the not-yet-implemented `tests/scripts/contract-safety.ps1` AST helper could not be loaded.
- GREEN: after the minimal AST helper was added, the suite passed all 24 assertions; the retained dynamic secret non-disclosure assertion increases the final suite to 25 assertions.
- Required review-fix commit message: `test: harden developer script contracts`.
