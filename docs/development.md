# Development

How features move from idea to shipped code in Grimoire. This is a security product — the development process exists to catch security issues before they land, not after.

## Principles

- **Specs before code.** Every feature gets a design document before implementation. Cheap to change a spec; expensive to change shipped code.
- **Security is not a phase.** It's present at every stage — brainstorm, spec, implementation, testing, and audit.
- **Atomic changes.** Each feature is one spec, one implementation, one commit. No half-finished features in the codebase.
- **Docs reflect reality.** Specs are historical records of decisions. Docs describe the system as it is today.

## Feature Lifecycle

Features go through six phases. Each phase has a clear deliverable and a gate — the feature doesn't advance until the gate is passed.

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                                                                  │
  │  1. Brainstorm ──► 2. Spec ──► 3. Implement ──► 4. Test         │
  │       & Threat         │            │                │           │
  │       Analysis         │            │                │           │
  │                        ▼            ▼                ▼           │
  │                    [Review]     [Review]         [Review]        │
  │                                                      │          │
  │                                     5. Security Audit◄┘         │
  │                                          │                      │
  │                              ┌───────────┤                      │
  │                              │           │                      │
  │                        Critical/    [Review]                    │
  │                        High found       │                       │
  │                              │           │                      │
  │                              ▼           ▼                      │
  │                         Back to     6. Finalize                 │
  │                         Phase 3         │                       │
  │                                         ▼                       │
  │                                      Done                       │
  └──────────────────────────────────────────────────────────────────┘
```

### Phase 1: Brainstorm & Threat Analysis

**Input**: Feature idea or request.

**Process**:
1. Understand the problem — what does the user need? What constraints exist?
2. Research the codebase — what exists today that this touches?
3. Map the security surface:
   - New trust boundaries (inputs, outputs, IPC, file I/O, network)
   - Data flow for secrets and sensitive data
   - State machine changes
   - Process model changes (who can trigger what)
4. Threat analysis against `docs/security.md`:
   - Attack vectors (same-user RCE, malformed input, races, info leaks, privilege escalation)
   - Existing mitigations that apply
   - New mitigations needed
   - Residual risk that's accepted

**Deliverable**: Structured brief:
```
## Feature: <name>
### What it does
### Touches (crates, state transitions, trust boundaries)
### Attack Vectors (numbered, with severity)
### Proposed Mitigations
### Residual Risk
### Open Questions
```

**Gate**: User reviews the security surface and approves scope.

### Phase 2: Spec

**Input**: Approved threat analysis from Phase 1.

**Process**: Write an ADR in `specs/NNN-slug.md` following the spec format (see below). The Security Analysis section captures the threat work from Phase 1 in its "Planned" form.

**Deliverable**: Complete spec with all sections filled.

**Gate**: User reviews the design and security decisions. Spec is mutable at this stage — iterate until approved.

### Phase 3: Implement

**Input**: Approved spec.

**Process**:
1. Present implementation plan for approval (files to change, dependencies, test plan)
2. Implement following project principles (see `CLAUDE.md`)
3. Pass quality gates: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --workspace`

**Deliverable**: Working code, all checks passing.

**Gate**: User reviews the implementation.

### Phase 4: Test

**Input**: Implementation from Phase 3 + threat analysis from Phase 1.

**Process**: Write tests targeting:
- Happy paths
- Error paths and edge cases
- Every attack vector from the threat analysis (prove mitigations work)
- State machine transitions (valid and invalid)

**Deliverable**: Passing test suite with coverage of all identified threats.

**Gate**: User reviews test coverage against the threat analysis.

### Phase 5: Security Audit

**Input**: Implementation + tests + original threat analysis.

**Process**: Adversarial review as if reading the code for the first time:
- Input validation, secret handling, concurrency, IPC/network security
- Verify every attack vector from Phase 1 has a working mitigation
- Verify every planned mitigation is actually implemented
- Check code auditability — can a reviewer follow every path?

**Deliverable**: Audit report with findings rated Critical/High/Medium/Low/Note.

**Gate**: Critical/High findings must be fixed (loop back to Phase 3). Medium findings discussed with user. When clean, user approves.

### Phase 6: Finalize

**Input**: Clean audit, all phases passed.

**Process**:
1. Fill in the spec's **Implementation Security Notes** section — this is what bridges "planned" to "verified":
   - Deviations from planned mitigations (if any) and why
   - Additional mitigations discovered during implementation
   - Audit findings from Phase 5 and how they were resolved
   - Which attack vectors have regression tests (map vector numbers to test names)
   - Any new residual risk discovered
2. Update the spec status to `Implemented` — the spec is now frozen
3. Update `docs/` to reflect new behavior
4. Update `docs/security.md` if the threat model changed
5. Update `CLAUDE.md` if new gotchas were discovered
6. Create atomic conventional commit: `feat(scope): description` referencing the spec

**Deliverable**: Everything committed, docs current, spec frozen with complete security record.

## Running the Lifecycle

Use `/feature <description>` to start a guided lifecycle. Each phase pauses for your review.

Individual phases are available as standalone commands for smaller tasks:

| Command | Use for |
|---------|---------|
| `/spec` | Writing a spec outside the full lifecycle |
| `/implement` | Implementing an already-approved spec |
| `/fix` | Bug fixes (smaller scope, still security-conscious) |
| `/refactor` | Simplification for auditability |
| `/test` | Adding test coverage to existing code |
| `/check` | Running the quality pipeline (fmt + clippy + tests) |
| `/security-review` | Security checklist review of recent changes |
| `/audit` | Deep security audit of a crate or module |
| `/sync-docs` | Synchronize docs with current codebase |
| `/upgrade-sdk` | Bitwarden SDK revision bump (see `UPGRADING.md`) |

## Spec Format

Specs live in `specs/` as numbered ADR-style documents. See the next section for the full template.

### Numbering

Sequential: `001`, `002`, etc. Check existing specs for the next number.

### Status Values

| Status | Meaning | Mutable? |
|--------|---------|----------|
| **Proposed** | Under discussion | Yes |
| **Accepted** | Approved for implementation | Yes |
| **Implemented** | Code shipped | No — frozen |
| **Superseded** | Replaced by newer spec | No — link to successor |

### Cross-References

- Specs reference other specs by number: "See ADR 008"
- Specs reference docs: "See `docs/security.md`"
- Docs never reference specs by number (specs are historical; docs reflect current state)

### When to Write a New Spec vs Update

- **Proposed/Accepted**: Edit in place.
- **Implemented**: Create a new spec that supersedes it. Add "Superseded by: ADR NNN" to the old spec.

## Spec Template

```markdown
# ADR NNN: <Title>

## Status

Proposed | Accepted | Implemented | Superseded by ADR NNN

## Context

Why this change is needed. Problem statement, constraints, prior art.
What exists today that this feature touches or changes.

## Decision

The concrete design. Be specific enough that implementation is mechanical.

Include as needed:
- Data structures and types
- Protocol changes (new IPC methods, error codes, message formats)
- State machine changes (new states, transitions, invariants)
- Code sketches for non-obvious parts
- Configuration changes
- Migration path from current behavior

## Consequences

### Positive
What this enables. Why the trade-offs are worth it.

### Negative
Costs, complexity added, limitations, things that get harder.

## Security Analysis

### Threat Model Impact
How this feature changes the threat model in `docs/security.md`.
New trust boundaries, new attack surface, changed assumptions.

### Attack Vectors
Enumerate specific attacks against this feature:

| # | Vector | Severity | Description |
|---|--------|----------|-------------|
| 1 | ... | Critical/High/Medium/Low | ... |

### Planned Mitigations
How each attack vector is addressed in the design:

| Vector | Mitigation | Mechanism |
|--------|-----------|-----------|
| 1 | ... | (code-level detail: where and how) |

### Residual Risk
Attacks that remain possible after mitigations, and why they're acceptable.

### Implementation Security Notes
_Added during finalization (Phase 6). Captures what actually shipped._

- Deviations from planned mitigations (if any) and why
- Additional mitigations discovered during implementation
- Audit findings and how they were resolved
- Test coverage of attack vectors (which vectors have regression tests)
```

## Relationship Between Specs and Docs

```
specs/              docs/                 CLAUDE.md
  │                   │                      │
  │  Historical       │  Current state       │  Gotchas &
  │  decisions        │  of the system       │  conventions
  │                   │                      │
  │  "We decided X    │  "The system does    │  "Watch out
  │   because Y"      │   X like this"       │   for X"
  │                   │                      │
  │  Frozen once      │  Updated when        │  Updated when
  │  implemented      │  code changes        │  surprises found
```

- **Specs** answer "why was this decision made?" — historical, frozen once implemented.
- **Docs** answer "how does the system work right now?" — living, always current.
- **CLAUDE.md** answers "what will surprise me?" — gotchas, traps, non-obvious conventions.
- Don't duplicate. A doc may say "access approval is scoped to session leader PID" without repeating the full rationale from ADR 008.

## Bug Fix Workflow

Bug fixes use `/fix <description>` — a three-phase workflow with the same security discipline as `/feature` but without the spec overhead.

```
  1. Diagnose ──► 2. Fix & Test ──► 3. Verify & Commit
       │                │                    │
       ▼                ▼                    ▼
   [Review]         [Review]             [Done]
```

### Phase 1: Diagnose

Trace the code path, find the root cause, and classify security impact:

| Classification | Meaning | Extra steps |
|---------------|---------|-------------|
| **Security bug** | The bug is a vulnerability | Read threat model, assess exploitability, check for similar patterns |
| **Security-adjacent** | In security code but not exploitable | Read relevant specs, assess blast radius |
| **Non-security** | No security implications | Standard fix process |

Present the diagnosis (root cause, security classification, proposed fix, blast radius) and wait for approval.

### Phase 2: Fix & Test

Minimal fix targeting the root cause, plus a regression test that fails without the fix. Pass the quality gate (fmt, clippy, tests).

For security bugs: verify the fix closes the attack vector, not just the specific trigger.

### Phase 3: Verify & Commit

For security/security-adjacent bugs: check for similar patterns elsewhere (flag, don't fix), update `docs/security.md` if needed.

Commit as `fix(scope): description` or `security(scope): description` for security bugs.

**Key rules:**
- Always diagnose before fixing — understand the root cause, not the symptom
- Always write a regression test — if a bug happened once, it can happen again
- Stay focused — one bug, one fix, one commit; flag adjacent issues for follow-up

## Other Changes

Not everything needs a phased workflow. Use judgment:

| Change | Process |
|--------|---------|
| Refactoring for clarity | `/refactor` — simplify, verify tests pass, commit |
| Adding tests | `/test` — write tests, commit |
| Doc updates | `/sync-docs` — update, commit |
| SDK dependency bump | `/upgrade-sdk` — follow UPGRADING.md exactly |
| New feature or behavior change | `/feature` — full six-phase lifecycle |
| Changing implemented behavior | New spec that supersedes the old one, then `/feature` |

The key distinction: if it changes **what the system does** (new capability, changed behavior), it needs `/feature`. If it fixes something broken, `/fix`. If it changes **how** the system does something it already does (refactor, test, docs), use the appropriate standalone command.
