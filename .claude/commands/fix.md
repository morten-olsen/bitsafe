Guided bug fix workflow for Grimoire.

Arguments: $ARGUMENTS

This is a structured but lightweight workflow — fewer phases than `/feature`, same security discipline. Each phase pauses for user review before advancing.

---

## Phase 1: Diagnose

**Goal**: Find the root cause, not just the symptom. Assess security impact.

1. **Understand the bug** from the arguments. Ask clarifying questions if the failure mode is ambiguous.
2. **Trace the code path**: Read the relevant code and reproduce the bug mentally. Follow data from entry point to failure site.
3. **Identify the root cause**: What invariant is violated? What assumption is wrong? Don't stop at "this line crashes" — understand *why*.
4. **Security triage**: Classify the bug's security impact:

   | Classification | Meaning | Example |
   |---------------|---------|---------|
   | **Security bug** | The bug itself is a vulnerability | Input validation bypass, secret leaked in error message, race condition on auth check |
   | **Security-adjacent** | Bug is in security-sensitive code but not directly exploitable | Crash in auth flow, incorrect error code from IPC handler |
   | **Non-security** | Bug has no security implications | Formatting issue in CLI output, incorrect help text |

   For **Security bug** or **Security-adjacent**:
   - Read `docs/security.md` and any relevant specs
   - Assess: could an attacker trigger this deliberately? What's the impact?
   - Note whether the fix needs to be disclosed or changes the threat model

5. **Present diagnosis** to the user:
   ```
   ## Bug: <short description>
   ### Root Cause
   <what's actually wrong and where>
   ### Security Classification
   <security bug / security-adjacent / non-security — with rationale>
   ### Proposed Fix
   <what to change and why this addresses the root cause>
   ### Blast Radius
   <what code paths are affected, risk of regression>
   ```

**STOP. Wait for user to confirm the diagnosis and approach.** The user may have additional context, disagree with the root cause, or want a different fix strategy.

---

## Phase 2: Fix & Test

**Goal**: Minimal, correct fix with a regression test that proves the bug is gone.

1. **Implement the fix**:
   - Fix the root cause, not the symptom
   - Minimal change — don't refactor surrounding code, don't fix adjacent issues
   - For security bugs: verify the fix actually closes the attack vector, not just the specific trigger
   - Follow project principles: no `.unwrap()`, typed errors, secrets never logged

2. **Write a regression test**:
   - The test must fail without the fix and pass with it
   - Name: `test_<function>_<bug_scenario>_<expected_behavior>`
   - For security bugs: the test should exercise the attack vector directly
   - For security-adjacent: test the error path that was broken

3. **Quality gate**:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace -- -D warnings`
   - `cargo test --workspace`

   Fix any failures before proceeding.

**STOP. Present the fix** — what changed, the regression test, and the quality gate results. For security bugs, explicitly state how the attack vector is now closed. Wait for user review.

---

## Phase 3: Verify & Commit

**Goal**: Ensure nothing was missed, update docs, commit.

1. **Security verification** (for security / security-adjacent bugs only):
   - Does the fix introduce any new attack surface?
   - Are there similar patterns elsewhere in the codebase that have the same bug? (Check with grep/search — don't fix them in this commit, but flag them)
   - Does `docs/security.md` need updating? (New known gap closed, or new mitigation added)

2. **Doc updates**:
   - If docs or CLAUDE.md describe behavior that was actually buggy, update them
   - If the bug revealed a gotcha that would surprise a future agent, add it to CLAUDE.md

3. **Commit**: Atomic conventional commit:
   - `fix(scope): description of what was wrong`
   - For security bugs: `security(scope): description` — the `security` type signals this to reviewers
   - Body: brief explanation of root cause and fix
   - If similar patterns were found elsewhere, note them in the commit body as follow-up

4. **Final summary**:
   - What was fixed (one sentence)
   - Root cause
   - Security classification
   - Files changed
   - Similar patterns flagged (if any)

---

## Phase Gate Rules

- **Never skip diagnosis.** Fixing without understanding the root cause creates whack-a-mole bugs.
- **Always write a regression test.** If a bug happened once, it can happen again.
- **Security bugs get extra scrutiny.** Check for similar patterns, verify the vector is closed, update threat docs.
- **Stay focused.** One bug, one fix, one commit. If you find other issues along the way, flag them — don't fix them here.
