# Phase File Variants

This section documents the recognized phase-file variants. A phase file
declares its variant in the `**Format:**` header line (INV-PHASE-08). Each
variant is a conforming instance of the invariants defined in
`reference/invariants.md` — no variant may violate an invariant, but
variants differ in which optional sections they typically include and
what purpose they serve.

Three variants are currently documented. New variants emerge through the
Drift Intake Protocol (see `reference/drift_intake.md`, Sub-step 1c) —
recurrence in real use is the prerequisite, not speculation.

---

## How to Use This Section

**When authoring a phase file:** Read the purpose summaries below and
pick the variant that matches the work being reflected on. Write the
declaration `**Format:** {variant-name}` in the header block. Follow
the variant's schema — required invariants and required-when-present
sections. Optional sections are at the author's discretion.

**When validating a phase file (Check 16):** Read the `**Format:**`
declaration. Load the matching variant's schema. Verify:
1. All required invariants hold
2. All required-when-present sections (those that appear) conform to
   their canonical formats
3. The grep-anchor patterns match — i.e., the file looks like what the
   declaration claims

If the declared variant is not documented here, Check 16 routes the
file to the Drift Intake Protocol rather than failing it.

**When reading a phase file for lookup:** The variant tells you what
kind of artifact you're reading. Canonical files have Applied Lessons
tables worth consulting for the lookup protocol; meta-reflection files
don't. Case-study files are reference material for specific recurring
work, not reflections.

---

## Variant 1 — `canonical`

**Declaration:** `**Format:** canonical`

### Purpose

Reflection on a single coherent unit of work — a feature, bug fix,
refactor, testing pass, or incident response. This is the default
variant. Most phase files are canonical. If you're reflecting on one
thing you just finished, this is the right shape.

### Required invariants

All Phase File invariants from `reference/invariants.md`:
- INV-PHASE-01 through INV-PHASE-09

Plus the cross-file invariants that tie phase entries to INDEX and AI
files (INV-X-01 through INV-X-04).

### Required-when-present sections

If any of these sections is included, its structure is strict.

| Section | Format requirement |
|---|---|
| `## Applied Lessons` | Three-column table per INV-PHASE-03; source-column format per INV-PHASE-04; outcomes per INV-PHASE-05 |
| `## Missed` or `## Missed Lessons` | Three-column table per INV-PHASE-06 |
| `## Bugs and Pitfalls` (or `## Bugs`, `## Pitfalls`) | Numbered entries per INV-PHASE-01; Lesson anchor per INV-PHASE-02 |
| `## Design Decisions` (or `## Decisions`) | Numbered entries per INV-PHASE-01; Lesson anchor per INV-PHASE-02 |
| `## Carry-Forward Items` (or `## Carry-Forward`, `## Open Debt`) | Table with CF-N IDs per INV-PHASE-07 |

Section *name* is presentation (any of the listed alternatives is fine).
Section *structure* when present is invariant.

### Typical optional sections

None of these is required; include any that have content.

- `## Overview` or `## Scope` — 2–5 sentences of framing
- `## What Went Well` — approaches that worked; not always numbered
- `## What Went Badly` — judgment failures distinct from technical bugs
- `## What Would Help Me Grow — Tooling Wishlist` — wishlist entries
  using the meta-note sub-type classification (introduced in Phase 3:
  `meta-fix`, `meta-question`, `meta-wish`)
- `## Metrics` — quantitative output measurements

### Grep-anchor patterns

Positive signals (file is probably canonical):
```
grep -c "^## Applied Lessons" {file}      # 1
grep -c "^## Bugs" {file}                 # typically 1
grep -c "^## Design Decisions" {file}     # typically 1
grep -cE "^### [0-9]+\. " {file}          # > 0 (numbered entries)
```

Negative signals (if present, probably NOT canonical):
```
grep -c "^# Meta-Reflection" {file}       # 0 — canonical is single-phase
grep -cE "^## [A-Z][a-z]+ [a-z]" {file}   # low — canonical uses standardized names
```

### Exemplar

`phase77_cf76_1_e2e_fixes.md` — E2E test fixes, one unit of work, all
canonical sections populated.

---

## Variant 2 — `meta-reflection`

**Declaration:** `**Format:** meta-reflection`

### Purpose

Retrospective on a multi-phase arc — reviewing what happened across
several shipped units of work. The author is looking for arc-level
patterns that weren't visible in any single phase. Typical scope: 3–10
consecutive phases, or a thematic slice (e.g., "all UI work this
quarter"). The output is synthesis — not per-phase feedback loops
(those already happened in the constituent phases) but cross-phase
observations about process, discipline, and opportunity.

### Required invariants

A subset of Phase File invariants:
- INV-PHASE-01 and INV-PHASE-02 apply to any numbered entries (when
  entries are actionable enough to need INDEX rows)
- INV-PHASE-08 (`**Format:**` declaration)
- INV-PHASE-09 (superseded rule markers, if any are referenced)

**NOT required** in meta-reflection:
- INV-PHASE-03 (Applied Lessons table) — the constituent phases already
  have their own Applied Lessons; meta-reflection doesn't re-run the
  feedback loop
- INV-PHASE-06 (Missed table) — same reasoning
- INV-PHASE-07 (Carry-Forward Items) — arc-level observations that
  warrant action usually produce Wishlist entries, not CF entries;
  per-phase CFs already exist in individual phase files

Cross-file invariants INV-X-01 through INV-X-04 apply only if the
meta-reflection creates new actionable entries that warrant INDEX rows.
Most meta-reflection observations are process insights that stay at the
phase-file level.

### Required-when-present sections

| Section | Format requirement |
|---|---|
| `## What Went Well` | Numbered entries with Lesson anchors when actionable (per INV-PHASE-01/02) |
| `## What Went Poorly` (or `## What Went Badly`) | Same |
| `## What I Would Like to Improve` or `## What Would Help Me Grow — Tooling Wishlist` | Wishlist entries with typed IDs (`TW-N` or `TW-{phase-range}-N`); when meta-note sub-types are in use, each entry declares its sub-type (`meta-fix`, `meta-question`, `meta-wish`) |

### Typical optional sections

- `## Summary Judgment` — arc-level takeaway (2–5 sentences)
- `## Overview` or `## Scope` — naming the phase range covered and the
  thematic framing

### Grep-anchor patterns

Positive signals (file is probably meta-reflection):
```
grep -m1 "^# Meta-Reflection" {file}                   # H1 contains "Meta"
grep -m1 "^## What Would Like to Improve" {file}       # or "What Would Help Me Grow"
grep -m1 "^\*\*Scope:\*\*.*[Pp]hases [0-9]" {file}     # multi-phase scope declaration
```

Negative signals (if present with content, this is NOT meta-reflection):
```
grep -A 2 "^## Applied Lessons" {file} | grep "^|"    # populated Applied Lessons table
grep -A 2 "^## Carry-Forward" {file} | grep "^| CF-"  # populated CF table
```

If Applied Lessons and CF tables are present with real content, the file
is doing per-phase work, not arc-level synthesis — reclassify as
canonical.

### Exemplar

`phase76_meta_reflection.md` — reflection on UI Enhancement Phases 70–76;
synthesizes patterns (live-test-run value, CSS variable discipline,
incomplete `ts-check` rollout) into wishlist items (TW-1 through TW-5)
without re-running per-phase loops.

### Note on hybrids

A meta-reflection that *also* records new cross-phase lessons worth
indexing should include an `## Applied Lessons` (if any meta-level rules
were consulted) and/or create phase-entry-equivalent numbered blocks
that get INDEX rows. This blurs the line with canonical but is rare;
when it happens, the file declares `**Format:** meta-reflection` and
Check 16 validates the Applied Lessons / numbered entries against
canonical schemas while ignoring the absence of CF/Metrics/Bugs sections.

---

## Variant 3 — `case-study`

**Declaration:** `**Format:** case-study`

### Purpose

Teaching artifact produced during or after a specific kind of recurring
work, capturing *how to do this well next time*. The primary audience
is the future session doing similar work — not the author reflecting.
Examples: tool onboarding documentation, new-integration pattern guide,
migration playbook, "how we wired the new CI gate" walkthrough.

Distinct from canonical because:
- The *audience relationship is inverted* — canonical is "author
  reflecting for future self"; case-study is "author writing directly
  for future session doing the same kind of work"
- Section names are typically descriptive (what the section teaches)
  rather than standardized (Bugs / DD / CF)
- The document is optimized for linear reading by someone starting
  similar work, not for grep retrieval of specific rules

### Required invariants

A subset:
- INV-PHASE-08 (`**Format:**` declaration)
- If the case study records actionable rules intended for INDEX/AI file
  retrieval, those specific entries must conform to INV-PHASE-01
  (numbered headings) and INV-PHASE-02 (Lesson anchor). Otherwise,
  descriptive narrative headings are fine.
- Cross-file invariants INV-X-01 through INV-X-04 apply **only** to
  entries that are explicitly indexed; case studies often aren't indexed
  as discrete rule/bug/pattern rows but instead serve as source pointers
  for AI rules that cite specific sections.

**NOT required:**
- INV-PHASE-03 (Applied Lessons) — case studies capture teaching, not
  reflection
- INV-PHASE-06 (Missed)
- INV-PHASE-07 (Carry-Forward Items) — case studies may recommend
  follow-up work but typically track it as "Followup" or "Next Steps"
  prose rather than CF-N tables

### Required-when-present sections

None of the canonical section names are required. If the case study
includes Applied Lessons or Bugs, those sections use canonical format —
but their absence is normal.

### Typical optional sections

- Descriptive H2 headings that teach specific lessons (e.g., "The real
  N-location rule for tools", "Registry is `tools/__init__.py`, not
  `tools/factory.py`")
- `## Validators that must be green before commit` — checklist of
  verification commands
- `## {Topic} speedup ideas` or `## Followups` — forward-looking
  suggestions

### Grep-anchor patterns

Positive signals (file is probably case-study):
```
grep -cE "^## (Applied Lessons|Bugs|Design Decisions|Carry-Forward|Metrics)" {file}   # 0 or very low
grep -cE "^## [A-Z][a-z].{20,}" {file}                                                # many descriptive H2s
grep -m1 -iE "case study|checklist|onboarding|playbook" {file}                        # H1 or early prose hints
```

Negative signals (if present, probably NOT case-study):
```
grep -c "^## Applied Lessons" {file}          # 1 — case studies usually omit this
grep -cE "^### [0-9]+\. " {file}              # > 5 — case studies use fewer numbered entries
```

### Exemplar

`phase81_tool_onboarding.md` — smbclient onboarding captured as a
reference document for future tool additions. Section headings teach
specific lessons ("The real N-location rule", "Registry is
`tools/__init__.py`, not `tools/factory.py`"); no Applied Lessons,
Bugs, or CF sections. Closes with "Onboarding speedup ideas" —
forward-looking suggestions that function like wishlist items without
being formally tagged.

### Note on indexing

A case study's value to future sessions depends partly on whether the
right portions are reachable via grep on INDEX.md. Two patterns work:

1. **Indexed at the file level** — one INDEX row points to the whole
   case study: `| tags | description | phase81_tool_onboarding | pattern |`.
   This is the simplest route; grep hits send the reader to the document
   as a whole.

2. **Indexed at the section level** — specific teaching sections get
   INDEX rows using the parenthetical-note source-pointer form (one of
   the 9 documented variants): `| tags | description |
   phase81_tool_onboarding (§4-location rule) | rule |`. This is denser
   retrieval but requires care with section-anchor naming.

Either pattern is valid. Choose based on whether specific sections of
the case study warrant direct grep hits or whether the document is
better consumed as a unit.

---

## Worked Validation Against Real Phase Files

The five phase files uploaded during V3.5 Phase 0 validation, classified
against these three variants:

| Phase file | Declared/inferred variant | Reasoning |
|---|---|---|
| `phase77_cf76_1_e2e_fixes.md` | `canonical` | All canonical sections present; single-phase scope; numbered entries with Lesson anchors throughout |
| `phase78_79_cf76_2_3_cleanup.md` | `canonical` | Same structural pattern as phase77; two sub-phases but one coherent work unit |
| `phase80_service_taxonomy.md` | `canonical` | Canonical sections + optional Tooling Wishlist (which is documented as an optional section within canonical) |
| `phase76_meta_reflection.md` | `meta-reflection` | Covers Phases 70–76; no Applied/Missed/Bugs/CF/Metrics; has What Went Well, What Went Poorly, Tooling Wishlist, Summary Judgment; H1 contains "Meta-Reflection" |
| `phase81_tool_onboarding.md` | `case-study` | Zero standardized section names; all H2s are descriptive teaching headings; ends with "Onboarding speedup ideas" |

**Coverage:** 5/5 files classify cleanly against exactly one variant.
No file required a hybrid classification or a new variant proposal.
The three documented variants partition the sample.

**If a phase file does not fit cleanly:** Either it's a genuinely new
shape (→ route through the Drift Intake Protocol in Sub-step 1c) or
it's a drafting error where the author picked the wrong standardized
sections for the kind of work being documented (→ revise to fit a
documented variant).

---

## Variant Selection Quick Reference

Condensed decision guide for authors:

```
Single unit of work, reflecting on what just happened?
  → canonical

Reviewing multiple phases at once, looking for arc-level patterns?
  → meta-reflection

Writing a teaching document for future sessions doing similar work?
  → case-study

None of the above, or something genuinely new?
  → Route through Drift Intake Protocol (reference/drift_intake.md)
```

When in doubt between canonical and meta-reflection: if the file has a
populated Applied Lessons table, it's canonical. When in doubt between
canonical and case-study: if the primary audience is the future session
doing the same work (not the author reflecting on what just happened),
it's case-study.

---

## What Changes in the Variants Require a Skill Version Bump

- **Adding a new variant:** Skill version bump + `skill_dev_log.md`
  entry documenting the Drift Intake Protocol trajectory (first
  appearance, recurrence evidence, canonization decision)
- **Changing a variant's required invariants:** Version bump; this is
  essentially changing the contract
- **Changing a variant's required-when-present section formats:**
  Version bump; existing phase files using that variant may need
  retrofitting or grandfathering
- **Retiring a variant (marking deprecated):** Version bump; variant
  remains documented as deprecated for grep resolution of older phase
  files declaring it

Adding or renaming section-name synonyms (e.g., accepting `## Issues`
as a synonym for `## Bugs`) does not require a version bump — it's a
presentation-level adjustment recorded in `skill_dev_log.md` as a
drift-formalization event.
