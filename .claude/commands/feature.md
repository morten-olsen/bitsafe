End-to-end feature development lifecycle for Grimoire.

Arguments: $ARGUMENTS

This is a guided, multi-phase workflow. Each phase produces a deliverable and **pauses for user review** before proceeding. Do NOT advance to the next phase without explicit user approval.

---

## Phase 1: Brainstorm & Threat Analysis

**Goal**: Understand the feature deeply, map its security surface, and identify attack vectors *before* any design work.

1. **Understand the request**: Parse the feature description from the arguments. Ask clarifying questions if the intent is ambiguous — don't guess.

2. **Research the codebase**: Read all code and docs relevant to the feature area. Understand:
   - What exists today that this feature touches
   - What state transitions, data flows, and trust boundaries are involved
   - How similar features in the codebase were designed (study existing specs for patterns)

3. **Map the security surface**: For this feature, enumerate:
   - **New trust boundaries**: Does this introduce new inputs, outputs, IPC messages, file I/O, or network calls?
   - **Data flow**: Where do secrets or sensitive data flow? Draw the path from entry to exit.
   - **State changes**: Does this affect the service state machine? Add new states or transitions?
   - **Process model**: Does this change who can trigger what? New CLI commands? New IPC methods?

4. **Threat analysis**: Using the project's threat model (`docs/security.md`), analyze:
   - **Attack vectors**: How could an attacker abuse this feature? Consider:
     - Same-user RCE (compromised npm package, browser exploit, malicious extension)
     - Malformed input (IPC, CLI args, server responses, config)
     - Race conditions (TOCTOU on security checks, concurrent state mutations)
     - Information leaks (error messages, logs, timing, file permissions)
     - Privilege escalation (bypassing approval, accessing other users' data)
   - **Existing mitigations**: Which current protections (socket perms, scoped approval, peer UID check) apply?
   - **New mitigations needed**: What defenses does this feature require?
   - **Residual risk**: What attacks remain possible even with mitigations? Are they acceptable?

5. **Present findings** to the user as a structured brief:
   ```
   ## Feature: <name>
   ### What it does
   <1-2 sentences>
   ### Touches
   <crates, files, state transitions affected>
   ### Attack Vectors
   <numbered list with severity>
   ### Proposed Mitigations
   <how each vector is addressed>
   ### Residual Risk
   <what remains and why it's acceptable>
   ### Open Questions
   <anything that needs user input before spec>
   ```

**STOP. Wait for user feedback.** The user may refine the scope, reject attack vectors, add constraints, or ask to explore alternatives. Iterate until they approve moving to Phase 2.

---

## Phase 2: Spec

**Goal**: Produce a complete ADR spec that captures the design and security decisions from Phase 1.

1. Read `docs/development.md` for the full spec template and format conventions.
2. Determine the next spec number from `specs/`.
3. Write `specs/NNN-<slug>.md` following the ADR template:

   ```
   # ADR NNN: <Title>

   ## Status
   Proposed

   ## Context
   Why this change is needed. Problem statement, constraints, prior art.
   What exists today that this feature touches or changes.

   ## Decision
   Concrete design — specific enough that implementation is mechanical.
   Include: data structures, protocol changes, state machine changes,
   code sketches for non-obvious parts, config changes, migration path.

   ## Consequences

   ### Positive
   What this enables. Why the trade-offs are worth it.

   ### Negative
   Costs, complexity added, limitations, things that get harder.

   ## Security Analysis

   ### Threat Model Impact
   How this changes the threat model in docs/security.md.
   New trust boundaries, attack surface, changed assumptions.

   ### Attack Vectors
   | # | Vector | Severity | Description |
   |---|--------|----------|-------------|
   | 1 | ... | Critical/High/Medium/Low | ... |

   ### Planned Mitigations
   | Vector | Mitigation | Mechanism |
   |--------|-----------|-----------|
   | 1 | ... | (code-level detail: where and how) |

   ### Residual Risk
   Attacks that remain possible and why they're acceptable.

   ### Implementation Security Notes
   _Filled during finalization (Phase 6). Leave empty._
   ```

4. The Security Analysis section migrates the full threat analysis from Phase 1. Every attack vector from the brainstorm must appear in the table. Every mitigation must be concrete enough to verify during the Phase 5 audit.
5. Cross-reference: if this spec supersedes or modifies an existing one, note it explicitly.

**STOP. Wait for user review of the spec.** The user may request design changes, challenge security decisions, or ask for alternatives. The spec is mutable at this stage — iterate freely. Do not proceed until the user explicitly approves.

---

## Phase 3: Implement

**Goal**: Translate the approved spec into code, following the spec exactly.

1. **Plan first**: Before writing any code, present the implementation plan:
   - Files to create or modify (with the specific changes for each)
   - New dependencies (if any) and their security posture
   - Test plan: what tests are needed and what they cover
   - Order of operations

   **Wait for user approval of the plan.**

2. **Implement** following project principles:
   - Minimal surface area — only what the spec calls for
   - No `.unwrap()` on fallible operations in non-test code
   - No `unsafe` without spec-level justification + `// SAFETY:` comment
   - `deny_unknown_fields` on new protocol/serde types
   - Secrets never logged, never in error messages, never held longer than needed
   - Error types via `thiserror`, propagated with `?`

3. **Quality gate**: Run and report results:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace -- -D warnings`
   - `cargo test --workspace`

   Fix any failures before proceeding.

**STOP. Present the implementation summary** — files changed, key design choices made during implementation, and any deviations from the spec (there should be none, but if unavoidable, document why). Wait for user review.

---

## Phase 4: Test

**Goal**: Verify the implementation is correct, secure, and handles edge cases.

1. **Review existing test coverage**: What does `cargo test` already exercise for this feature?

2. **Add tests targeting the threat analysis from Phase 1**:
   - Happy path: feature works as designed
   - Error paths: invalid input, missing data, service in wrong state
   - Security edge cases: every attack vector from the threat analysis should have a corresponding test that proves the mitigation works
   - Boundary conditions: empty strings, max-length values, concurrent access
   - State machine: valid and invalid transitions if applicable

3. **Test naming**: `test_<function>_<scenario>_<expected>` (e.g., `test_approve_expired_grant_requires_reprompt`)

4. **Run the full suite**: `cargo test --workspace` — everything must pass.

**STOP. Present the test summary** — what's tested, what attack vectors are covered, any gaps. Wait for user review.

---

## Phase 5: Security Audit

**Goal**: Adversarial review of the implementation against the threat analysis.

This is an independent review — pretend you didn't write the code. Use the security review checklist:

### Input Handling
- [ ] All external input validated before use
- [ ] No path traversal, injection, or unbounded deserialization
- [ ] Protocol types use `deny_unknown_fields`

### Secret Handling
- [ ] Secrets never logged (even at debug/trace)
- [ ] Secrets not in error messages or Display impls
- [ ] Secrets not held in memory longer than needed
- [ ] File permissions correct for sensitive data (0600)

### Concurrency & State
- [ ] Lock ordering consistent (no deadlocks)
- [ ] No TOCTOU on security-critical checks
- [ ] State transitions valid per state machine

### IPC & Network
- [ ] Socket permissions enforced
- [ ] Peer UID validated
- [ ] Server responses treated as untrusted

### Implementation Quality
- [ ] No `unsafe` without justification
- [ ] No `.unwrap()` in non-test code
- [ ] Error paths don't silently swallow failures
- [ ] Code is auditable — a security reviewer can follow every path

### Threat Analysis Verification
- [ ] Every attack vector from Phase 1 has a mitigation in the code
- [ ] Every mitigation from Phase 1 is actually implemented (not just planned)
- [ ] Residual risks documented in the spec match reality

Report findings with severity levels:
- **Critical**: Exploitable vulnerability, must fix before merge
- **High**: Security weakness, should fix before merge
- **Medium**: Defense-in-depth gap, fix soon
- **Low**: Minor issue, fix when convenient
- **Note**: Observation, not a bug (e.g., "correct but hard to audit")

**STOP. Present audit findings.** Fix any Critical/High issues. Discuss Medium findings with the user. Wait for user approval to finalize.

---

## Phase 6: Finalize

**Goal**: Close the loop — update all artifacts to reflect the completed feature. The spec's security section evolves from "planned" to "verified."

1. **Fill in the spec's Implementation Security Notes** section. This bridges the gap between what was planned (Phase 2) and what actually shipped (Phase 5). Write:
   - Deviations from planned mitigations (if any) and why
   - Additional mitigations discovered during implementation that weren't in the original plan
   - Audit findings from Phase 5 and how they were resolved (reference severity + resolution)
   - Which attack vectors have regression tests (map vector numbers to test names)
   - Any new residual risk discovered during implementation

   This section makes the spec a complete security record — a reviewer can read it end-to-end and understand both the intent and the outcome.

2. **Update spec status**: Change Status from `Proposed` to `Implemented`.

3. **Update docs**: For each doc in `docs/` affected by this feature:
   - Update to reflect the new behavior
   - Add new sections if the feature introduces user-facing capabilities
   - Update `docs/security.md` if the threat model changed (new threats, new mitigations, updated assumptions)

4. **Update CLAUDE.md**: If the feature introduces:
   - New gotchas that would surprise a future agent
   - New conventions or patterns
   - Changes to the state machine, protocol, or build

5. **Prepare the commit**: Stage all changes and create an atomic conventional commit:
   - `feat(scope): <concise description>`
   - Body: reference the spec (`Implements ADR NNN`)
   - Include all code, tests, spec update, and doc updates in one commit

6. **Final summary**: Present to the user:
   - What was built (one sentence)
   - Spec reference
   - Files changed
   - Security posture: mitigations implemented, residual risks accepted
   - Any follow-up items for future work

---

## Phase Gate Rules

- **Never skip a phase.** Each phase builds on the previous one.
- **Never auto-advance.** Always wait for explicit user approval at each STOP point.
- **Phase 1 findings feed Phase 2 spec.** The spec's Security Considerations section should be a refined version of the Phase 1 threat analysis.
- **Phase 5 reviews against Phase 1.** The audit checks that every identified attack vector was actually mitigated.
- **If the audit finds Critical/High issues**, return to Phase 3 to fix them, then re-run Phases 4 and 5.
- **The user can abort at any phase.** Partial work (e.g., just the brainstorm or just the spec) is still valuable.
