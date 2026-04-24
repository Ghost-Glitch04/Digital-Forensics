# Drift Intake Protocol — Lessons Learned V3.5

## What this file is

This file documents how new phase-file variants enter the lessons-learned
system. It is the bounded, prove-first path from *"this reflection doesn't
fit any documented variant"* to *"this is now a canonized variant with a
schema"*.

Read this file:
- When a reflection's natural shape doesn't fit Canonical, Meta-reflection,
  or Case-study (the three currently-documented variants — see
  `templates.md` §"Phase File Variants")
- When Check 16 flags an undocumented variant declaration
- When proposing to canonize a new variant (promoting it from observed
  drift to documented schema)
- When retiring a variant that has fallen out of use

This file is **not** read during normal reflections. Most phase files fit
a documented variant, and the author writes the reflection and moves on.
This file only runs when the default path doesn't fit.

---

## Core principle — drift is the raw material of evolution

The lessons-learned system is built for a field — cybersecurity, incident
response, tooling — where new kinds of work appear continuously. A skill
that rejects drift rejects the future. A skill that accepts drift without
discipline dissolves into inconsistency.

The Drift Intake Protocol is how we reconcile this: **drift is welcomed
as data, canonization requires evidence, and retrieval invariants remain
strict regardless of variant.**

Three rules fall out of this:

1. **Invariants are never bypassed by variant declaration.** Declaring
   a new variant cannot exempt a phase file from retrieval invariants
   (INV-PHASE-01, INV-PHASE-02, INV-PHASE-03, etc. — see
   `reference/invariants.md`). Variants differ in which *optional*
   sections they include and what *presentation* they use. They do not
   differ in what grep-based retrieval depends on.

2. **Recurrence is the canonization prerequisite.** A one-off shape is
   just drift. A shape that appears in 2+ reflections, each serving a
   real purpose the documented variants couldn't serve, is a variant
   candidate. Recurrence proves the shape is answering a real need.

3. **Canonization is a skill version event.** Adding a variant changes
   the contract with future sessions. It requires a skill version bump,
   a `skill_dev_log.md` entry, and an update to `templates.md`
   §"Phase File Variants".

---

## The `**Format:**` Declaration

### Syntax

Every phase file declares its variant on a single line in the header
block:

```
**Format:** {variant-name}
```

- `{variant-name}` is lowercase, hyphenated, single-word or multi-word
  (e.g., `canonical`, `meta-reflection`, `case-study`, or a proposed
  name like `incident-response`, `post-exploitation-walkthrough`).
- The line appears within the first 15 lines of the file, after the H1
  title and any `**Date:**` / `**Scope:**` declarations.
- Exactly one `**Format:**` line per phase file.

### Placement

Canonical placement is after `**Date:**` and `**Scope:**`, before the
first `---` horizontal rule:

```markdown
# Phase 82 — [Short Title]

**Date:** YYYY-MM-DD
**Scope:** Brief description of what this phase covers.
**Format:** canonical

---

## [First section]
```

This placement makes the declaration immediately visible to readers and
to the grep pattern `grep -m1 "^\*\*Format:\*\*" {file}` without
scanning the whole file.

### Retroactive tolerance

Phase files authored before V3.5 do not have `**Format:**` declarations.
Check 16 treats absence of the line as an implicit `**Format:** canonical`
if the file structure matches canonical; otherwise it routes to intake.

This is a one-time grandfathering. Phase files authored from V3.5 forward
must include the declaration. There is no planned migration that
retroactively adds the line to old files — the cost is not worth the
benefit, and the implicit classification handles the old files cleanly.

### What the declaration does NOT do

- It does not exempt the file from retrieval invariants (see Core
  Principle rule 1)
- It does not claim authority — the author can declare any variant name,
  but Check 16 validates the declaration against what's documented
- It does not substitute for correct structure — declaring
  `**Format:** canonical` on a file that has no Applied Lessons table
  and no Bugs section does not make the file canonical; Check 16 will
  flag the mismatch

---

## Check 16 Routing Logic

When verify.md Check 16 runs on a phase file, it follows this logic:

```
Read the **Format:** declaration (or infer canonical if absent).

Case 1: Declaration matches a variant documented in templates.md
    → Load that variant's schema
    → Validate the file against the schema
    → Validate all applicable retrieval invariants
    → PASS or FAIL based on schema conformance

Case 2: Declaration does not match any documented variant
    → Check if any other phase file declares the same variant name
      (i.e., is this a recurring undocumented variant?)
    → If no other file declares it:
          → WARN (not fail): "Undocumented variant '{name}' declared in
            {file}. This is observed drift. If this shape recurs, follow
            the Drift Intake Protocol to propose canonization."
          → Continue by validating retrieval invariants (Check 13)
            against the file regardless — invariants always apply
    → If 1+ other files declare it:
          → FLAG as variant candidate: "Undocumented variant '{name}'
            now appears in N files: [list]. This meets the recurrence
            threshold for canonization. Proposed canonization should be
            the subject of the next skill-development reflection."
          → Continue by validating retrieval invariants (Check 13)

Case 3: Declaration is absent and file structure doesn't match canonical
    → FLAG: "Missing **Format:** declaration and file structure does not
      match canonical. Add a Format declaration and re-run."
    → Validate retrieval invariants (Check 13) regardless
```

**Check 13 is authoritative on invariants.** Check 16 does not override
Check 13. A file can fail Check 13 and still be routed to intake by
Check 16 — the two checks serve different concerns. Check 13 enforces
the retrieval contract; Check 16 manages the variant taxonomy.

---

## The Four-Step Promotion Path

This is the canonical workflow from observed drift to documented variant.

### Step 1 — Flag at reflection time

When an author writes a reflection that doesn't fit any documented
variant, they:

1. Declare a proposed variant name in the `**Format:**` line:
   `**Format:** {proposed-name}`
2. Write the reflection in whatever shape genuinely fits the work
3. Ensure all retrieval invariants hold (Check 13 passes)
4. Ship the phase file

The author does not need to propose canonization at this point. One-off
drift is often just one-off drift — the author may be the only person
who ever writes that shape. Recurrence, not speculation, drives the
next step.

**Important:** The proposed variant name should describe the *kind of
work*, not the specific instance. `incident-response` is a good proposed
name; `phase82-specific-format` is not. The name has to be reusable for
the recurrence test to apply.

### Step 2 — Recurrence detection

Check 16 keeps a running tally of how many files declare each
undocumented variant name. When a second file appears with the same
proposed variant name, Check 16 emits a stronger flag (Case 2 in the
routing logic above).

This flag is the trigger for Step 3. It can appear in the verify output
of the second phase's reflection, or in any subsequent verify run.

**Threshold:** 2 files. Not 3, not 5. The test is whether the shape is
serving a real need that documented variants don't address — two
independent applications demonstrate that; five is overkill.

### Step 3 — Canonization proposal

When the recurrence threshold is met, the next reflection that has
spare cycles (or a dedicated skill-development reflection) proposes
canonization. The proposal includes:

1. **Proposed variant name** (usually the name already in use)
2. **Purpose statement** — what kind of work this variant serves that
   canonical/meta-reflection/case-study don't serve well
3. **Recurrence evidence** — list of the phase files using the variant,
   with brief notes on what each was reflecting on
4. **Proposed schema:**
   - Required invariants (subset of those in `reference/invariants.md`)
   - Required-when-present sections and their formats
   - Typical optional sections
   - Grep-anchor patterns (positive and negative signals)
   - Exemplar phase file
5. **Distinguishing criteria** — how the author chooses this variant
   over the existing documented variants
6. **Skill version impact** — confirmation that canonization requires
   a skill version bump and `skill_dev_log.md` entry

The proposal is discussed (with Ghost, during a skill-development
reflection) and either approved, revised, or rejected.

**Rejection outcomes:** If the shape is judged to be a case of authors
miscasting work that should have fit a documented variant, the existing
phase files are tagged for retrofit to the correct variant. If the shape
is judged to be genuine but duplicative of a documented variant's
flexibility, the documented variant's schema is extended to cover it
(e.g., adding a new optional section) without introducing a new variant.

### Step 4 — Canonization

If the proposal is approved:

1. The variant is added to `templates.md` §"Phase File Variants"
   following the same structural template as Canonical / Meta-reflection
   / Case-study
2. An entry is added to `lessons_learned/meta/skill_dev_log.md`
   recording:
   - Event type: `drift-intake-canonization`
   - The variant's name, purpose, and schema
   - The recurrence evidence
   - The distinguishing criteria from existing variants
   - Any invariants added or relaxed (rare — most new variants only
     introduce new optional sections)
3. Check 16 is updated to include the new variant in its documented-set
4. The skill version is bumped (typically a minor bump — V3.5 → V3.6)
5. The phase files that drove the canonization remain as-is, now
   validating cleanly under the new schema

Retrofitting existing phase files to update their `**Format:**` lines
is not required if they already use the proposed variant name. If they
used a different proposed name that got renamed during canonization,
the author of the canonization updates the declarations in those files
as part of Step 4.

---

## Deprecating and Retiring Variants

Variants can also be retired when they fall out of use.

### Deprecation criteria

A variant is a candidate for deprecation when:
- No new phase files have declared it in 12+ months
- Its purpose has been absorbed by another variant (e.g., an optional
  section was added to Canonical that covered the variant's niche)
- The shape is judged to have been a mistake in retrospect (rare, but
  worth naming as possible)

Deprecation is not urgency — there is no cost to leaving a rarely-used
variant documented. The test is whether the variant is actively
misleading or redundant, not whether it's popular.

### Deprecation workflow

1. A skill-development reflection proposes deprecation with the same
   structure as a canonization proposal (purpose, evidence, criteria)
2. If approved:
   - The variant's section in `templates.md` §"Phase File Variants" is
     marked `**Status:** DEPRECATED in V{X.Y}`
   - The variant remains documented (not removed) — old phase files
     still need to validate against it
   - A `skill_dev_log.md` entry records the deprecation with the event
     type `variant-deprecation`
   - New phase files MUST NOT declare the deprecated variant; Check 16
     fails new declarations after the deprecation is in effect
3. Existing phase files declaring the deprecated variant remain valid —
   deprecation is forward-looking only

### Retirement (full removal)

A deprecated variant can be fully retired when no phase files still
declare it. This typically means all files using it have been
retrofitted to a live variant or archived. Retirement removes the
variant from `templates.md` entirely and records the removal in
`skill_dev_log.md` as event type `variant-retirement`.

Retirement is optional. Most deprecated variants can stay documented
indefinitely — the cost is low and the safety of not breaking old
phase files' validation is high.

---

## Edge Cases

### Edge case 1: Author declares an undocumented variant they are pretty sure is canonical

Happens when the author is uncertain whether canonical fits. Example:
writing a reflection on a bug fix that has no Applied Lessons (nothing
was consulted), no Missed (lookup was clean), no Bugs section (the fix
was trivial), no CF (no debt). The file has Design Decisions, Metrics,
and narrative — but the author isn't sure if that's canonical-minimal
or something different.

**Resolution:** Default to `**Format:** canonical`. Canonical allows all
its required-when-present sections to be omitted when empty. A canonical
reflection with only Design Decisions and Metrics is still canonical.
The test is whether the file *could have* had Applied Lessons if rules
had been consulted — if yes, it's canonical.

### Edge case 2: Two authors propose the same variant with different schemas

Rare but possible. Two phase files declare `**Format:** incident-response`
but structure the content differently — one with a "Timeline" section
as required, one with a "Root Cause Analysis" section as required.

**Resolution:** Both files are valid observed drift. The canonization
proposal (Step 3) is where the schemas get reconciled — the proposal
picks one structure and documents it, the other phase file gets
retrofitted. If the two structures are genuinely different enough to
warrant two variants, the canonization proposes both names (e.g.,
`incident-response` and `incident-timeline`).

### Edge case 3: A documented variant's schema needs extension

Not drift — existing variant needs a new optional section (e.g.,
Canonical adding a new optional section for "Dependencies Encountered").

**Resolution:** This is not a variant change; it's a schema extension.
Handled by a templates.md update and a `skill_dev_log.md` entry with
event type `variant-schema-extension`. No version bump required unless
the new section's format introduces a new invariant.

### Edge case 4: The Format declaration is wrong

Author declares `**Format:** canonical` but the file is missing Applied
Lessons, Bugs, and CF tables that would fit the content. This is not
drift — it's a declaration-content mismatch.

**Resolution:** Check 16 reports the mismatch. The author revises the
declaration (to the correct variant, often `case-study` or
`meta-reflection`) or revises the content (adding the missing canonical
sections). Either resolution is fine; the goal is declaration matching
structure.

### Edge case 5: An old phase file fails Check 16 after V3.5 adoption

Old files without `**Format:**` lines are implicitly canonical per the
retroactive tolerance rule. If an old file does not actually fit
canonical (e.g., phase76 is a meta-reflection but authored pre-V3.5),
Check 16 will flag the implicit classification as mismatching the
structure.

**Resolution:** One-time retrofit. Add the correct `**Format:**` line
to the old phase file. This is a small, bounded operation — the five
sample files Ghost uploaded for V3.5 validation would need three of
them annotated (phase77 and phase78/79 as `canonical` are already
implicit-correct; phase76 needs `meta-reflection`, phase81 needs
`case-study`, phase80 needs `canonical`).

---

## Relationship to Other Files

- `reference/invariants.md` — the retrieval invariants that apply
  regardless of variant. This file does not change them; it operates
  within them.
- `templates.md` §"Phase File Variants" — the canonical registry of
  documented variants. Step 4 of the promotion path updates this
  section.
- `verify.md` Check 16 — the automated validation that uses the
  routing logic documented above.
- `lessons_learned/meta/skill_dev_log.md` — the permanent record of
  canonization, deprecation, and retirement events.

---

## Change Control

Changes to this protocol itself require:

- **Relaxing the recurrence threshold** (e.g., from 2 instances to 1):
  Skill version bump + `skill_dev_log.md` entry. This is a contract
  change — it makes canonization easier and more candidates eligible.
- **Tightening the recurrence threshold** (e.g., from 2 to 3): Same.
  This is also a contract change — it makes canonization harder.
- **Changing the promotion workflow** (e.g., adding a review step):
  Skill version bump.
- **Clarifying existing rules without changing semantics:** No version
  bump; record as a drift-formalization event in `skill_dev_log.md`.

The protocol is designed to be conservative — the default should always
favor observing drift before acting on it. If the protocol becomes too
strict and legitimate variants fail to get canonized, authors will
bypass it (cargo-culting canonical declarations onto ill-fitting files).
If it becomes too loose, variant proliferation makes the taxonomy
useless. The current thresholds reflect the best guess at that balance;
real experience should inform adjustments.
