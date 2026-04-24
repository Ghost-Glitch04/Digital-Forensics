# Authoring Helpers — Mechanical Enforcement of Skill-Development Discipline

This folder contains runnable tooling that enforces the `scripting-standards` skill's own authoring-time invariants — format contracts between grep-anchored patterns and their worked templates — as pre-commit mechanical checks rather than run-when-remembered authorial discipline.

**Invoked when:** git runs a pre-commit hook during skill-authoring commits. Not invoked by reading Claude; this folder is infrastructure for editing the skill itself, not a reference the skill uses to do its job.

**Do not load this folder during normal scripting work.** The scripts here mechanize authoring discipline; they are not consulted while writing user-facing scripts.

---

## Purpose

This folder answers one question:

> "Which worked templates in the skill no longer match the canonical pattern they claim to instantiate?"

The forcing signal: V5.2 Phase 4c hit a CRLF-variant of the L2 grep-test failure mode while authoring its own content. The harness that caught it existed as a temp-file pattern (`/tmp/l2_verify.sh`) rather than shipped tooling — run-when-remembered, not run-automatically. See `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>` for the incident and `<devlog:2026-04-22:v5-2-formal-invariants-over-workflow-guidance>` for the V5.2 decision that made L2 discipline load-bearing for the Grep-First vocabulary. V5.3 moves the harness from temp-file discipline to mechanical pre-commit enforcement.

It does not answer:

- "Did I use the skill's standards correctly in my script?" — that's project-level tooling; use `reference/integration-helpers/verify-integrations.{sh,ps1}` or write a project-specific check.
- "What decisions went into the skill's evolution?" — see `developer_log/log.md`.
- "What patterns have been recognized during skill development?" — see `lessons_learned/lessons.md`.

The separation is deliberate. Memory answers "why" and "what to recognize"; tooling answers "is it drifting right now."

---

## Scope

**In scope:**

- Pre-commit enforcement of the L2 grep-test across the skill's grep-anchored format contracts
- Coverage for the 15 invariants shipped at V5.3: G1–G9 (Grep-First categories) + I1–I6 (Integration Tracking markers)
- Runtime CRLF/LF agnosticism via input pre-normalization
- Exit codes conforming to the skill's own SKILL.md convention (0 / 40 / 99)

**Out of scope:**

- Runtime verification of user-project code against the skill's standards — that belongs in `reference/integration-helpers/` or in project-local tooling
- Coverage of `<devlog:>` / `<lesson:>` anchor patterns in `skill_development/` — these are less formal than G/I invariants; V5.4+ extension if incidents warrant
- CI integration — pre-commit is V5.3's execution surface; CI is a natural V5.4+ extension once (i) proves stable
- PowerShell or Python implementations — compounds the V5.0 unverified-PS-helper residual; see `<devlog:2026-04-23:v5-3-harness-language-bash-only>`

---

## Files

| File | Role |
|---|---|
| `pre-commit` | Git hook wrapper. Invoked by git on `git commit`. Delegates to `verify-l2.sh` and propagates its exit code. ~25 lines. |
| `verify-l2.sh` | L2 verification harness. Contains the inline `L2_CHECKS` array — pipe-delimited entries of (invariant_id, check_name, canonical_pattern, worked_template_file). Invocable standalone for manual runs and regression testing. |
| `test-verify-l2.sh` | Regression test suite for `verify-l2.sh`. 10 scenarios / 19 assertions covering CRLF-blindness, failure paths, exit code convention, output format, and registry iteration. Run manually when the harness or registry changes; not invoked by the pre-commit hook. |
| `README.md` | This file. |

---

## Installation

Two options. Both are idempotent — re-running has no effect.

**Option A — configure git hooks path (recommended):**

```bash
git config core.hooksPath skill_development/authoring-helpers/
```

This tells git to look in `skill_development/authoring-helpers/` for hook files. Every git-for-this-repo now picks up the hook automatically. Contributors cloning the repo need to run this once.

**Option B — symlink individual hooks:**

```bash
ln -sf ../../skill_development/authoring-helpers/pre-commit .git/hooks/pre-commit
```

Installs only the single hook. Preserves other `.git/hooks/` files untouched. Per-repo, not shared across contributors.

**To verify installation:** make a trivial edit to a worked template in `reference/grep_first.md` and attempt a commit. The harness should report either `L2 verification: N/N templates passed` on success or full per-template failure output on failure.

**To bypass (exceptional cases only):**

```bash
git commit --no-verify
```

This is git's standard escape hatch. Use sparingly; the reason for a bypass should be captured in the commit message or a Development Notes entry.

---

## The L2-Covered Invariant Set

V5.3 ships coverage for 15 invariants across two grep-anchored protocol families:

**Grep-First (9 categories, all in `reference/grep_first.md`):**

- G1 Error and exit codes
- G2 Log prefixes
- G3 Configuration keys
- G4 API endpoints and URL patterns
- G5 Environment variable names
- G6 Constants and enum values
- G7 Function and class names
- G8 Type definitions
- G9 File paths referenced across scripts

**Integration Tracking (6 invariants, all in `reference/integration-tracking.md`):**

- I1 `<CONTRACT>` block opening
- I2 `<CONTRACT>` block closing
- I3 `<USES>` marker
- I4 Integration map contract heading
- I5 Integration map CONSUMER entry
- I6 Contract Change Log entry

Each entry in the registry is a tuple: (invariant_id, check_name, canonical_pattern, worked_template_file). The full registry lives inline in `verify-l2.sh` as an indexed bash array named `L2_CHECKS`, with one row per test — several invariants have multiple rows because their worked templates use multiple representative identifiers (e.g., G1's rename example uses both `E_CONN_LOST` and `E_UPSTREAM_UNAVAILABLE`). Registry patterns are copy-exact from the canonical patterns documented in the reference files — any drift between them is the failure mode V5.3 exists to prevent.

---

## Regression Testing

The harness ships with `test-verify-l2.sh` — a maintainer-run suite that exercises `verify-l2.sh` against 10 scenarios. Run it whenever the harness code or registry changes:

```bash
./skill_development/authoring-helpers/test-verify-l2.sh
```

The suite creates an isolated `git init` repo, copies the current harness and reference files into it, and runs scenarios covering:

- **T1 / T2** — Clean pass on CRLF and LF content (CRLF-blindness)
- **T3** — Missing reference file (worst-case file-level drift)
- **T4** — Identifier scrubbed from template (the core "catches drift" assertion)
- **T5** — Harness invoked outside a git repo (environmental error → exit 99)
- **T6** — Idempotence (two runs, byte-identical output)
- **T7** — Failure output format (VERIFY_FAILED prefix + timestamp + summary line)
- **T8** — Exit code convention (0 / 40 / 99 all exercised)
- **T9** — Tmpfile cleanup via EXIT trap
- **T10** — Registry iteration covers all 15 invariants

Exit 0 on all-pass (19 assertions), 1 on any-fail. The suite runs in under a second and has zero side effects outside its `mktemp -d` isolated root.

The suite is NOT invoked by the pre-commit hook. Pre-commit is scoped to L2 enforcement against the two worked-template files; end-to-end validation of the harness itself is a distinct authoring concern invoked deliberately.

---

## Governance

**Adding a new invariant to L2 coverage.** Any new grep-anchored format contract added to `grep_first.md` or `integration-tracking.md` must:

1. Be proposed in a skill_development/developer_log entry with alternatives and rationale.
2. Be added to `verify-l2.sh`'s `L2_CHECKS` array in the same commit that adds the invariant definition and its worked template.
3. Pass the L2 grep-test against its worked template before the commit proceeds — the harness enforces this automatically.
4. Trigger a vocabulary version bump per the Governance Rule in `reference/grep_first.md § Format Contract § Governance Rule for Format Changes`.

**Revising a canonical pattern or worked template.** Changes must update every reference in a single commit: the pattern in `grep_first.md` or `integration-tracking.md`, the matching entry in `verify-l2.sh`'s registry, and every worked template that demonstrates the invariant. Partial revisions — new pattern, old examples — are the exact failure mode `<lesson:2026-04-22:format-drift-in-self-authored-patches>` warns against, and the harness catches them on the next commit.

**Removing an invariant from L2 coverage.** Rare. Requires a skill_development/developer_log entry justifying the removal and confirming the invariant is no longer a grep-anchored format contract. Simply deleting a registry entry without removing the invariant from the reference file leaves the invariant unprotected.

---

## Relationship to `reference/integration-helpers/`

`reference/integration-helpers/verify-integrations.{sh,ps1}` is the V5.0 user-facing drift-detection family. It verifies a user project's `<CONTRACT>` / `<USES>` markers against the project's `.integration-map.md`. It is invoked by script authors working on projects that have adopted Integration Tracking.

`authoring-helpers/` (this folder) is the V5.3+ skill-authoring family. It verifies the `scripting-standards` skill's own worked templates against its own invariant patterns. It is invoked only during commits to the `scripting-standards` skill repository itself.

The two families share:

- Grep-portable implementation (no ripgrep dependency) per V5.0.1 locked invariant
- Bash + grep toolchain
- The skill's logging-format conventions
- Runtime-verification-before-ship discipline per `<lesson:2026-04-22:verification-applies-at-skill-level>`

They do not share code. Concerns are genuinely independent per `<devlog:2026-04-23:v5-3-helpers-independent-zero-shared-code>` — drift between user code and user integration map vs. drift between skill worked templates and skill invariant patterns.

---

## Relationship to Sibling Folders

`skill_development/developer_log/` and `skill_development/lessons_learned/` capture institutional **memory** about how the skill evolves — decisions with alternatives (dev log), patterns recognized from real incidents (lessons). They are read on demand when authoring the skill.

`skill_development/authoring-helpers/` (this folder) captures institutional **tooling** that enforces evolution discipline mechanically. It is invoked by git, not read by Claude.

All three subfolders share the `skill_development/` parent because they all serve the skill's own evolution rather than user script work. None of them load during normal scripting sessions.

---

## How to Add New Authoring Helpers

When a new authoring discipline emerges that would benefit from mechanical enforcement:

1. **Propose in the developer log** with alternatives considered and rationale.
2. **Name the discipline** — what authoring failure mode does the helper catch? Cite the lesson or incident.
3. **Follow the V5.3 precedent** — add the helper as a bash script in this folder, documented in this README, with a header-comment cross-reference map and runtime-verified regression suite before shipping.
4. **Do not consolidate with existing helpers** — concerns should stay independent unless consolidation is justified by a shared failure mode. See `<devlog:2026-04-23:v5-3-helpers-independent-zero-shared-code>` for the precedent.

Version bumps for additions follow the skill's own versioning convention in `SKILL.md § How This Skill Evolves § Versioning convention`.
