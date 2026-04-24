# Developer Log — Skill Development Memory

This folder captures **decisions made** during the development of the `scripting-standards` skill itself. Each entry records a decision with its context, the alternatives considered, and the rationale that selected one over the others.

**Load `log.md` when:** resuming work on the skill and needing prior context; considering a design decision similar to one potentially already made; onboarding to the skill's history; investigating why a current structure exists.

**Do not load during normal scripting work.** This file is institutional memory about the skill's own development, not a reference the skill uses to do its job.

---

## Purpose

Developer log entries answer one question:

> "Why did we choose this approach over the alternatives?"

They do not answer:

- "What pattern should I recognize?" — that's a lesson; use `../lessons_learned/lessons.md`.
- "How does this feature work?" — that's documentation.
- "What changed in this version?" — that's a changelog; git history covers it.

The separation is deliberate. A decision without recorded alternatives is unfalsifiable later. A pattern reframed as a decision loses the recognition cue it exists to provide.

---

## Scope

**In scope:**

- Design decisions made during any version of the skill's development
- Retroactive captures of decisions evidenced in existing skill files
- Version-level decisions (what ships when, what gets deferred, what gets split out)
- Architectural choices that had named alternatives considered and rejected

**Out of scope:**

- Patterns recognized from incidents — those belong in `../lessons_learned/lessons.md`
- Routine design work without genuine alternatives — "I picked X because it's the only option that fits" is not a log entry
- Calibration observations, narratives, and general principles — these dilute the decision record
- Project-level decisions from work using this skill — those are not institutional memory for the skill itself

---

## Format Contract

The grep-stable anchor and four-required-field schema. **Must not drift** — format uniformity is what lets cross-entry audit and format-drift checks work.

### Entry anchor

```
### <devlog:YYYY-MM-DD:slug>
```

**Grep pattern:** `^### <devlog:`

- `devlog` literal (never `dev-log`, `devlogs`, `log_entry`, etc.)
- **Date** — ISO 8601, the date the entry was written. For retroactive entries, today's date; the original decision context goes in Context.
- **Slug** — lowercase, hyphen-separated, content-descriptive. Avoid version prefixes except where the decision is itself version-scoped (e.g., `v5-2-coverage-breadth`). Stable once assigned.

### Entry fields

Four required fields in this order, with two optional fields (Outcome, See also):

```markdown
### <devlog:YYYY-MM-DD:slug>

**Context:** The situation that prompted the decision — what phase, what question, what prior constraint shaped the choice space.

**Decision:** What was chosen. State the choice directly; details and scope qualifiers belong here, not in Rationale.

**Alternatives considered:** At least one real alternative with enough detail that the choice is falsifiable. "Considered and rejected option X because Y" — not "I considered other options."

**Rationale:** Why the chosen option beat the alternatives against the criteria that mattered (effectiveness, reliability, efficiency, honest cost). If the rationale depends on a locked prior decision, cite it.

**Outcome:** *(Optional; added retrospectively)* What the decision produced in practice — confirming evidence, unexpected costs, refinements during implementation, or drift from original intent. Only add when real post-decision information exists.

**See also:** *(Optional)* Cross-references to related dev log entries, lessons, or reference sections. Grep-stable slug format.
```

### Cross-reference format

- Within this file: `<devlog:YYYY-MM-DD:slug>`
- To `../lessons_learned/lessons.md`: `<lesson:YYYY-MM-DD:slug>`
- To reference files: `reference/<file>.md § <Section Name>`
- To SKILL.md: `SKILL.md § <Section Name>`
- To Ghost's general `lessons-learned` skill: `lessons-learned skill § <section>`

---

## Gatekeeping Rules

1. **Decisions with named alternatives only.** An entry without at least one genuine alternative considered is rejected. The log records choice points, not inevitabilities.

2. **Retroactive entries require existing-file evidence.** For decisions captured from V4.7 or earlier, the Context field must cite the sourcing file and section. Memory-only reconstruction is rejected.

3. **Calibration observations, narratives, and general principles are rejected.** "I learned that estimates tend to be high" is not a decision. "We decided to estimate conservatively because prior estimates missed by 40%" is a decision (provided a real alternative was considered).

4. **One decision per entry.** A complex phase that locked multiple independent decisions becomes multiple entries. Bundling obscures the choice points.

5. **Cross-session authoring discipline.** Voice must remain direct, rule-and-why. See `<lesson:2026-04-22:voice-drift-across-session-boundaries>`.

Enforcement: self-enforced at authoring time, with format-drift checks at phase review gates. See the Format-Drift Gate subsection under How to Add a New Entry.

---

## Retroactive Entries

Same convention as `../lessons_learned/`:

- **Date in anchor** = capture date, not original decision date
- **Context field** states the original circumstance and cites existing-file evidence

Retroactive entries land in the "Retroactive entries (pre-V5.0 history)" section of both this Index and `log.md`. Chronological within the section is approximate — the capture is atemporal by definition.

---

## Decision Index

Entries are grouped by version. Within each group, approximate chronological order top-to-bottom. This Index is **authoritative for slug names** — any entry in `log.md` must have a matching bullet here. Format drift between Index and `log.md` is the L2 failure mode this skill guards against.

### V5.0 — Integration Tracking (design phase)

- `<devlog:2026-04-22:contract-block-separate-vs-wrap>` — Separate `<CONTRACT>` block above the Unit header, not wrapping it.
- `<devlog:2026-04-22:integration-grep-protocol-self-contained>` — V5.0's Integration Grep Protocol defined as self-contained, independent of any broader Grep-First concept.
- `<devlog:2026-04-22:illustrative-templates-launch>` — Launch V5.0 with illustrative synthetic Worked Templates and an intentionally-empty Case Studies section.
- `<devlog:2026-04-22:helpers-as-separate-runnable-files>` — Helper scripts as separate runnable files at `reference/integration-helpers/`, not inline in the reference file.
- `<devlog:2026-04-22:v5-major-version-bump>` — V4.7 → V5.0 (major bump), not V4.8; new reference file crosses the major-version threshold.
- `<devlog:2026-04-22:three-drift-directions>` — Recognize three drift directions: code-ahead-of-map, map-ahead-of-code, and version-mismatch.
- `<devlog:2026-04-22:drift-expected-global-scope>` — `DRIFT-EXPECTED` annotation at per-run global scope, not per-contract.

### V5.0 — Integration Tracking (delivery)

- `<devlog:2026-04-22:powershell-helper-ships-unverified>` — Ship `verify-integrations.ps1` in "static-reviewed, not runtime-verified" state with explicit residual documented.

### V5.0 → V5.1 transition

- `<devlog:2026-04-22:dev-log-deferred-to-v5-1>` — Defer `skill_development/` from V5.0 to V5.1 as its own release.
- `<devlog:2026-04-22:v5-0-1-scope-split>` — Three-version split: V5.0.1 ships tactical grep wins, V5.1 ships dev log and lessons, V5.2 ships full Grep-First.

### Retroactive entries (pre-V5.0 history)

- `<devlog:2026-04-22:log-vocabulary-hoist>` — Hoist full log prefix table out of SKILL.md into dedicated `reference/log_vocabulary.md`.
- `<devlog:2026-04-22:end-to-end-verification-discipline>` — Adopt end-to-end execution of scaffolds as part of the authoring protocol.
- `<devlog:2026-04-22:stack-trace-cross-language-substitution>` — Document cross-language asymmetry explicitly (STACK_TRACE in Python/PowerShell, `$LINENO`+`$BASH_COMMAND` substitute in Bash).
- `<devlog:2026-04-22:idempotency-rule-dual-placement>` — Safety-critical rules appear at both decision point (SKILL.md) and implementation site (language reference helpers).

### V5.2 — Grep-First

- `<devlog:2026-04-22:v5-2-coverage-breadth>` — Full 9-category coverage at V5.2 launch.
- `<devlog:2026-04-22:v5-2-rg-preferred-posture>` — rg preferred + grep as portable fallback, V5.2-scoped.
- `<devlog:2026-04-22:v5-2-light-umbrella-framing>` — Light umbrella (Position B); Grep-First named as general protocol, IT literally untouched, cross-reference asymmetry accepted.
- `<devlog:2026-04-22:v5-2-no-helper-at-launch>` — No runnable Grep-First helper at V5.2 launch; copy-paste-friendly reference only.
- `<devlog:2026-04-22:v5-2-templates-only-launch-applies-precedent>` — Apply V5.0 precedent to V5.2: synthetic templates plus empty Case Studies.
- `<devlog:2026-04-22:v5-2-formal-invariants-over-workflow-guidance>` — Formal invariants G1-Gn per category, applying IT-style rigor to Grep-First.
- `<devlog:2026-04-22:v5-2-five-step-numbered-protocol>` — Numbered 5-step protocol (grep → classify → resolve UNCLEAR → change → grep-verify).
- `<devlog:2026-04-22:v5-2-tiered-uniformity-per-category>` — Tiered uniformity: uniform base per category with optional extensions applied per-category as variance warrants.
- `<devlog:2026-04-22:v5-2-section-structure-grouped-by-grep-friendliness>` — 8-section structure; templates folded per-category; grouped by grep-friendliness (high/medium/low).
- `<devlog:2026-04-22:v5-2-skill-md-section-before-integration-tracking>` — Place "Grep-First Protocol" SKILL.md section immediately before "Integration Tracking."
- `<devlog:2026-04-22:v5-2-cross-reference-language-no-meta-commentary>` — Reference files ship architecture; dev log carries design rationale. No meta-commentary in reference files.
- `<devlog:2026-04-22:v5-2-decision-index-placement-and-flat-structure>` — Place V5.2 section between V5.0→V5.1 transition and Retroactive in Decision Index; flat chronological initially.

### V5.3 — Automated L2 Enforcement

- `<devlog:2026-04-23:v5-3-headline-automated-l2-enforcement>` — V5.3 scoped to candidate D (automated L2 enforcement); closes the L2 run-when-remembered failure mode mechanically rather than deferring it.
- `<devlog:2026-04-23:v5-3-coverage-both-protocols>` — Harness covers G1–G9 + I1–I6 (15 invariants across 12 worked templates); uniformity of discipline across both grep-anchored protocol families.
- `<devlog:2026-04-23:v5-3-execution-model-pre-commit>` — Pre-commit git hook as execution surface; `--no-verify` is the explicit opt-out boundary.
- `<devlog:2026-04-23:v5-3-harness-language-bash-only>` — Bash-only implementation; preserves V5.0.1 grep-portability invariant and honors Q5 default (PowerShell residual stays deferred).
- `<devlog:2026-04-23:v5-3-topology-two-files>` — Minimal pre-commit hook wrapper + standalone L2 harness; no inline combination, no premature registry split.
- `<devlog:2026-04-23:v5-3-location-authoring-helpers-subdirectory>` — `skill_development/authoring-helpers/` as canonical home for authoring infrastructure; preserves V5.1 reference/vs/skill_development boundary.
- `<devlog:2026-04-23:v5-3-registry-inline-bash-array>` — Inline bash array registry in harness; Outcome field captures Phase 4b refinement from associative-array-keyed-by-invariant to indexed `L2_CHECKS` array with pipe-delimited rows (accommodates multi-check-per-invariant).
- `<devlog:2026-04-23:v5-3-skill-md-brief-cross-reference>` — Brief bold-lead paragraph in SKILL.md "How This Skill Evolves," not H3 subsection; keeps structural weight proportional to authoring-only concern.
- `<devlog:2026-04-23:v5-3-cross-reference-one-directional>` — V5.3 infrastructure cites reference files; reference files do NOT cite V5.3 infrastructure. Preserves V5.2 IT-untouched lock.
- `<devlog:2026-04-23:v5-3-helpers-independent-zero-shared-code>` — V5.3 helpers fully independent from V5.0's `verify-integrations.{sh,ps1}`; no shared library, no sub-invocation coupling.
- `<devlog:2026-04-23:v5-3-output-format-minimal-on-success-full-on-failure>` — Single-line minimal success output; full skill log format on failure (per-check VERIFY_FAILED lines + summary).
- `<devlog:2026-04-23:v5-3-crlf-pre-normalize>` — `tr -d '\r'` at input boundary before grep; registry patterns stay byte-identical to canonical reference patterns.
- `<devlog:2026-04-23:v5-3-ship-regression-suite>` — Ship `test-verify-l2.sh` (10 scenarios / 19 assertions) as permanent V5.3 artifact, not throwaway Phase 4d scaffolding.

---

## How to Add a New Entry

1. **Identify the decision**, the context that prompted it, at least one genuine alternative that was considered, and the rationale.
2. **Verify no duplicate** — grep `log.md` for keywords from the decision; if an entry already covers it, extend that entry's Outcome field rather than making a new one.
3. **Assign a slug** — lowercase, hyphen-separated, content-descriptive. Avoid version prefixes (those belong in Context). Keep slugs stable once assigned.
4. **Write the entry** using the Format Contract verbatim. All four required fields populated. At least one real alternative.
5. **Add to the Decision Index above** if the entry introduces a new version grouping; otherwise add under the appropriate existing group.
6. **Cross-reference** via `See also:` to related entries or to `../lessons_learned/lessons.md` entries. Grep-stable slug format.
7. **Append to the end of `log.md`**, newest entries at the bottom. Chronological order top-to-bottom within each version grouping.

### Format-Drift Gate

At every phase review gate, verify the Index and `log.md` slug sets match exactly:

```bash
grep -oE '<devlog:[0-9-]+:[a-z0-9-]+>' log.md | sort -u > /tmp/log_slugs
grep -oE '<devlog:[0-9-]+:[a-z0-9-]+>' README.md | sort -u > /tmp/index_slugs
diff /tmp/log_slugs /tmp/index_slugs
```

Non-empty diff output means drift — either the Index or the log has a slug the other doesn't. Resolve before the phase closes. This is the exact failure mode `<lesson:2026-04-22:format-drift-in-self-authored-patches>` warns against; applying it to the skill's own institutional memory is not optional.

---

## Relationship to `lessons_learned/`

| This folder (`developer_log/`) | Sibling (`lessons_learned/`) |
|---|---|
| Captures **decisions** with alternatives and rationale | Captures **patterns** with six-field schema |
| Temporal, chronological | Atemporal, rule-oriented |
| "Why did we choose this approach?" | "What should I recognize next time?" |
| Fields: Context, Decision, Alternatives, Rationale | Fields: Situation, What went wrong, Root cause, What would have caught it, Lesson encoded, Generalizable rule |

A single incident may produce entries in both folders — a decision about how to fix it (dev log) and a pattern recognized from it (lesson). Cross-reference via `See also:` when this happens.

For lessons about *using* this skill on project work — debugging incidents, tool quirks, architectural surprises in the projects the skill supports — see Ghost's general `lessons-learned` skill. The folder here is scoped strictly to the skill's own development.
