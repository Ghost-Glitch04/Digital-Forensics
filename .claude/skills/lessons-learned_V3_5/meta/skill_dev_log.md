# Skill Development Log — Lessons Learned

## What this file is

This file is the permanent record of the lessons-learned skill's own
evolution. It captures version-bump decisions, drift-intake events,
deprecated features, null and negative experimental results, and
meta-observations about how AI-human collaboration on skill development
actually works.

This file's audience is **future Claude sessions designing skill
revisions**. Not the authors of phase files (they read SKILL.md).
Not users of the skill for normal reflection (they follow the capture
workflow). Specifically: sessions that propose changes to the skill
itself, review prior design decisions, or investigate why a feature
exists or was retired.

Read this file:
- Before proposing a skill version bump
- When investigating why an invariant or variant exists
- When a feature's value is questioned — check the prior prove-first
  trail here first
- When starting a skill-development reflection, to review
  accumulated meta-observations
- When the drift intake protocol promotes a variant (Step 4 of the
  promotion path records the canonization here)

---

## Scope — for now, lessons-learned only

V3.5 scopes this log to the lessons-learned skill. The schema is
designed to accept entries from other skills (e.g.,
scripting-standards, github-security-standards) so migration to a
shared location is possible without schema rework. But V3.5 does not
migrate. The log stays at `lessons_learned/meta/skill_dev_log.md`
until accumulated experience demonstrates the cross-skill promotion
is warranted.

When cross-skill migration happens (likely V3.6 or later):

1. Relocate the file to a shared path (e.g.,
   `skills/shared/skill_dev_log.md`)
2. Update SKILL.md §8 pointer in each participating skill
3. Record the migration here as a `file-relocation` event
4. The `Skill:` field in each entry carries the relevant skill name
   (already designed into the schema)

---

## Entry schema

Each entry uses this structure:

```markdown
## V{X.Y} — {skill_name} — {YYYY-MM-DD}

**Skill:** lessons-learned | scripting-standards | github-security-standards | ...
**Event:** version-bump | drift-intake-canonization | variant-deprecation |
           variant-retirement | variant-schema-extension | drift-formalization |
           meta-observation | null-result | retired-feature |
           deferred-feature-pending-evidence | file-relocation

**Tags:** (for meta-observations and cross-cutting entries — secondary
classification; primary index is the Event field)

---

### Hypothesis / Proposal
(What was being tested or decided.)

### Premise validation
(What real-data check preceded the change. Cite phase files, commit
ranges, or other evidence. For meta-observations, cite the moment in
a conversation or session that surfaced the observation.)

### Changes shipped
(Bullet list of what actually changed. For version-bump events,
exhaustive. For meta-observation events, may be "none — observation
only".)

### Results
(What the trial or post-ship experience produced, including null and
negative results. For entries made at ship time, this section may be
marked "pending trial" and updated later.)

### Retained / Rejected
(For each proposed change: `kept` | `revised` | `rejected` | `pending`,
with reasoning. This is where partial wins get documented — a V3.5
feature that proved itself gets `kept`; one that didn't becomes a
`retired-feature` entry later.)

### Retrieval pointers
(If this entry created or changed invariants, variants, or canonical
structures, point to templates.md / invariants.md / drift_intake.md
sections. If it retired a feature, point to the last phase file or
commit that used it. Enables grep-based rediscovery of the decision's
consequences.)

### Related observations
(Cross-references to other skill_dev_log entries. Especially for
meta-observations, link to related observations that form a pattern.)

---
```

### Event type definitions

| Event | Meaning | Requires skill version bump? |
|---|---|---|
| `version-bump` | Major or minor revision shipping new features or contract changes | Yes |
| `drift-intake-canonization` | A new variant promoted from observed drift to documented | Yes |
| `variant-deprecation` | A variant marked deprecated (still validates, not used for new files) | Yes |
| `variant-retirement` | A deprecated variant fully removed | Yes |
| `variant-schema-extension` | An existing variant's schema extended with new optional section or pattern | Sometimes (only if new invariants added) |
| `drift-formalization` | A pattern or heuristic formalized without changing the contract (e.g., recognizing a new citation pattern) | No |
| `meta-observation` | An observation about cognition, methodology, AI-human collaboration, or emergent patterns that don't fit other categories | No |
| `null-result` | A trial that produced no improvement or a negative result; feature may be retained, revised, or retired based on analysis | Sometimes |
| `retired-feature` | A feature removed from the skill; entry captures what it was and why it didn't work | Yes |
| `deferred-feature-pending-evidence` | A proposed feature held for a later version pending accumulated evidence | No |
| `file-relocation` | A skill file moved to a new path (e.g., cross-skill log migration) | Sometimes |

### Tag vocabulary (for meta-observation entries)

Tags are greppable secondary classifications. New tags may be added
freely — the vocabulary grows with observation patterns. Current
tags in use:

- `calibration` — observations about threshold-setting, gut-number
  accuracy, or predictive miscalibration
- `hedging` — observations about AI's defensive communication patterns
- `pattern-recognition` — observations about when AI pattern-matching
  succeeds or fails
- `prove-first-scope` — observations about when prove-first discipline
  applies vs. when it's misapplied
- `cross-reference-drift` — observations about references between
  files degrading over time
- `authorship-duplication` — observations about the same content
  appearing in multiple files
- `check-architecture` — observations about the verify.md check
  structure's design tradeoffs
- `developmental-vs-measurable` — observations about features whose
  success criteria require time vs. features with immediate metrics
- `references-grow-with-experience` — observations about reference
  files as living documents
- `self-referential-cognition` — observations about AI examining its
  own reasoning

---

## Entries

Entries are ordered newest-first. Each entry is independently retrievable
via grep on `## V{X.Y}`, `**Event:**`, or `**Tags:**` lines.

---

## V3.4 — lessons-learned — 2026-04-18

**Skill:** lessons-learned
**Event:** version-bump

---

### Hypothesis / Proposal

V3.4 was proposed as a corrective revision to V3.3. V3.3 shipped with
two reference files that were byte-for-byte duplicates of other files,
breaking 11 load-bearing pointers from SKILL.md. The hypothesis: adding
authoring-time self-checks (Check 12 reference pointer resolution,
Check 13 format drift) would prevent this failure mode in future
versions.

Secondary hypothesis: V3.3 had documented features (concern maps,
`CF-{N}:` line-prefix format) with zero real-world usage across 19 AI
files and 32 phase files. Features without evidence of use should be
deleted, not retained as aspirational documentation.

### Premise validation

The V3.3 → V3.4 premise was validated retroactively rather than
prospectively — V3.3 had already shipped and the duplicate-reference
file problem was already causing broken pointers. The specific
evidence:

- `reference/verify.md` and `reference/bootstrap.md` were byte-for-byte
  identical in V3.3 (md5sum comparison)
- 11 pointers from SKILL.md resolved to the duplicate file rather than
  to distinct content
- Concern maps: grep across 19 AI files returned zero instances of the
  documented concern-map format
- CF line-prefix: grep across 32 phase files returned zero instances
  of `^CF-[0-9]+:` line format — all CF items use table format

### Changes shipped

- Added Check 12 (reference pointer resolution): md5sum-based duplicate
  detection + pointer-target verification
- Added Check 13 (format drift): grep-based validation that documented
  formats match real-world usage across phase files and AI files
- Added Check 11 (isolation-read discipline) as authored-skill check
- Retired concern maps (deferred to future reintroduction if evidence
  emerges)
- Retired `CF-{N}:` line-prefix format documentation (CF-N as table
  column was the only real-world format)
- Added the Applied/Missed split for the feedback loop
- Added companion-rule mutual linking (Check 6b)
- Added supersession vocabulary (`corrected | refined | narrowed | split`)
- Extensive templates.md restructure to document the 9 source-pointer
  form variants observed in real use

### Results

V3.4 shipped and was in active use from phase22_testing onward. The
prove-first discipline caught one real failure during Phase 0 of V3.5
development: V3.4 had inline duplications of content that also lived
in templates.md (outcome vocabulary definitions, tier graduation
criteria, REGRESSED semantics). Check 12 doesn't detect inline
duplication of reference material — only reference-file duplication.
This gap informs a V3.5 meta-observation (see
`meta-observation: authorship-duplication`).

### Retained / Rejected

- Check 11, 12, 13: **kept** (load-bearing for V3.5's prove-first
  discipline)
- Concern maps retirement: **kept** — no usage emerged through V3.4
  lifespan; feature correctly identified as dead
- `CF-{N}:` line-prefix retirement: **kept** — table format is the
  canonical standard
- Applied/Missed split: **kept** — became the core feedback loop
  V3.5 builds on
- Supersession vocabulary: **kept** — no new reasons emerged in V3.4
  usage

### Retrieval pointers

- Check 12, 13 definitions: `reference/verify.md` Checks 12, 13
- Concern maps retirement rationale: this entry's "Changes shipped"
  section; the original concern-map documentation no longer exists in
  the skill (retired feature)
- Supersession vocabulary: `reference/templates.md` §"Superseded Rules
  Format" → Supersession reasons

### Related observations

This entry is a retroactive reconstruction authored during V3.5
development. The V3.3 → V3.4 transition was not documented in a
structured form at the time. The reconstruction is based on the
closing §7 of V3.4 SKILL.md, which summarized the V3.3 failures.
Future version-bump entries should be authored contemporaneously,
not retroactively.

See also: `V3.5 — meta-observation: authorship-duplication` — V3.4's
inline duplications informed V3.5's deduplication pass.

---

## V3.5 — lessons-learned — 2026-04-20

**Skill:** lessons-learned
**Event:** version-bump

---

### Hypothesis / Proposal

V3.5 was proposed as a feature addition + architectural sharpening
revision. Three primary features:

1. **Evidence block + anchor discipline** — Hypothesis H1: producing a
   structured evidence snapshot during GATHER and requiring Bugs/DD
   entries to cite concrete evidence would (a) increase citation
   density by ≥30%, (b) surface ≥1 previously-unwritten lesson per 3
   reflections, (c) increase grep-hit precision on INDEX descriptions.

2. **Meta-note classification + synchronous Step 6** — Hypothesis H2:
   classifying meta-notes at authorship time (`meta-fix` /
   `meta-question` / `meta-wish`) and proposing synchronous edits for
   `meta-fix` only would (a) reduce median time-to-action for
   `meta-fix` notes from weeks to minutes, (b) not degrade
   `meta-question` / `meta-wish` quality, (c) produce a revert
   rate below 20% on synchronous edits.

3. **Retrieval invariants + variant taxonomy + drift intake protocol**
   — Not in the original plan. Emerged from Phase 0 data when format
   drift was discovered to be a bigger real issue than the original
   H1/H2 features addressed.

Secondary hypothesis: bring metacognition scaffolding into
lessons-learned as skill_dev_log entries, with design decision that a
dedicated metacognition skill is future work (not V3.5).

### Premise validation

Phase 0 of V3.5 development ran hypothesis checks against five
uploaded real phase files (phase76, phase77, phase78/79, phase80,
phase81). Results:

**H1a falsified.** Citation density was already strong — 20 of 20
sampled Bugs/DD entries had at least one citation. The original "raw
evidence dump" design for the evidence block was over-scoped. H1 was
revised to focus on **anchor discipline** (5 of 20 entries missing
the `**Lesson:**` bold anchor even when narrative citations were
present) rather than citation density.

**H2 supported.** 2 of 5 TW items from phase76 were resolved within a
week without synchronous handling (40% action rate). Retroactive
classification under the three-sub-type scheme showed the items that
resolved were bounded `meta-fix` items. Sync handling would have
resolved them in minutes instead of days.

**Format drift discovered.** Not tested in original Phase 0 plan.
The five sample files used at least three different structural
formats (canonical, meta-reflection-with-wishlist, case-study)
without declared variants. Applied Lessons source-pointer format
also varied. This was the architectural finding that restructured
the whole V3.5 plan.

### Changes shipped

**New reference files:**
- `reference/invariants.md` — the retrieval contract naming 27
  invariants across phase files, INDEX.md, AI files, _overview.md,
  and cross-file relationships; distinguishes invariants (strict)
  from presentation (drift-tolerant)
- `reference/drift_intake.md` — the four-step promotion path for
  new phase file variants; Check 16 routing logic; the `**Format:**`
  declaration specification
- `reference/evidence.md` — the Lesson anchor discipline,
  evidence-gathering commands, and completeness check post-drafting
  prompt
- `reference/meta_classification.md` — the three meta-note sub-types,
  three-criterion test for `meta-fix` vs. `meta-question`, synchronous
  Step 6 workflow, safety rules
- `reference/lookup.md` — deep lookup commands, refinement patterns,
  grep contract explanation (spun off from V3.4 SKILL.md §2)

**New section in existing reference:**
- `reference/templates.md` §"Phase File Variants" — three documented
  variants (canonical, meta-reflection, case-study) with schemas,
  grep-anchor patterns, and a worked-validation table

**New invariant (INV-PHASE-08):**
- `**Format:**` declaration on phase file headers; retroactive
  tolerance (missing declaration implies canonical if structure
  matches)

**New SKILL.md content:**
- §3a Step 1 sub-step for evidence block execution
- §3a Step 2 sub-step for `**Format:**` declaration
- §3a Step 2 sub-step for completeness check
- §3a new Step 6 for synchronous `meta-fix` proposal loop
- §4e new decision tree "Which variant?"
- §6 Quick Reference Card entries for V3.5 concepts
- §8 Reference Files table updated with new entries

**New verify.md checks:**
- Check 14 (anchor consistency, Mode A per-reflection + Mode B
  authored-skill)
- Check 15 (meta-note sub-type coverage with V3.4 grandfathering)
- Check 16 (variant conformance + drift intake routing)

**Deduplications in V3.4 SKILL.md:**
- Outcome vocabulary inline definitions → references only
- REGRESSED/contradicted expanded semantics → templates.md only
- Tier graduation duplicated between §3a and §4d → consolidated in §4d

**This skill_dev_log.md:** bootstrapped with V3.3→V3.4 retroactive
entry and this V3.4→V3.5 entry as seed corpus.

### Results

Phase 7 trial is pending. V3.5 ships with the full feature set based
on Phase 0 validation and design review, under the explicit
understanding (per Interpretation B, see related observation below)
that some features are developmental rather than measurable —
success criteria span months of use, not single thresholds.

Pending Phase 7 metrics:
- H1-revised (anchor consistency rate): target ≥90% on V3.5-authored
  phase files (up from 75% baseline on V3.4 samples)
- H2 (meta-fix action rate): target ≥70% approval on Step 6 proposals;
  revert rate <20%
- Classification accuracy: target ≥80% of meta-notes retain initial
  sub-type across reflections (stable classification signals
  internalization)
- Variant conformance: target 100% of new phase files declaring a
  documented variant OR routing to drift intake protocol

### Retained / Rejected

All V3.5 features ship. Per Outcome B from the original plan, partial
wins are acceptable — features that underperform in Phase 7 trial
become `retired-feature` entries, not silently removed. Phase 7
results will be recorded here as an update to this entry.

Two decisions documented as pending:

- **`lookup.md` as a new reference file:** shipped as an experiment.
  If its usage justifies its existence over six months, it stays;
  if not, the content returns to SKILL.md and this file is retired.
- **572-line SKILL.md:** accepted for V3.5 ship. V3.6 reviews whether
  further compression is warranted.

### Retrieval pointers

- All V3.5 invariants: `reference/invariants.md` §"Invariants by File"
- Three documented variants: `templates.md` §"Phase File Variants"
- Drift intake protocol: `reference/drift_intake.md` §"The Four-Step
  Promotion Path"
- Anchor discipline: `reference/evidence.md` §"The Lesson Anchor"
- Meta-note sub-types: `reference/meta_classification.md` §"Three
  Sub-Types"
- Synchronous Step 6: `reference/meta_classification.md` §"Synchronous
  Step 6"
- Checks 14, 15, 16: `reference/verify.md` §§ (to be added in Phase 5
  integration)

### Related observations

Ten meta-observations surfaced during V3.5 development, documented
as separate entries below. Grouped by theme:

- Prove-first discipline scope (`prove-first-scope`,
  `developmental-vs-measurable`)
- Cross-reference and authorship drift (`cross-reference-drift`,
  `authorship-duplication`, `check-architecture`)
- AI cognition patterns (`hedging`, `pattern-recognition`,
  `calibration`, `self-referential-cognition`)
- Design philosophy (`references-grow-with-experience`)

---

## V3.5 — meta-observation: H1a falsified, discipline revised

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** calibration, pattern-recognition

---

### Hypothesis / Proposal

Phase 0 set a hypothesis that citation density in V3.4 Bugs/DD
entries was low, and that an evidence block would improve it. The
premise was based on my prior expectation that authors typically
produce narrative entries with implicit rather than explicit
citations.

### Premise validation

I checked the real data: 20 Bugs/DD entries across five uploaded
phase files. All 20 had at least one specific citation (commit SHA,
function name, file:line, specific count, test name). Prior
expectation was falsified.

However, the same sample showed 5 of 20 entries missing the bold
`**Lesson:**` anchor line. The real gap was not citation density
(entries were specific) but **anchor presence** (entries lacked the
standalone takeaway line that grep retrieval depends on).

### Changes shipped

- H1 hypothesis revised mid-plan from "citation density" to "anchor
  consistency"
- Evidence block scoped down from "raw evidence dump" to "anchor
  discipline support + completeness check"
- Check 14 targets anchor presence + weak-signal citation detection
  rather than citation-density scoring

### Results

The revised discipline is what shipped. The falsification happened
cheaply (Phase 0, before any drafting) because the prove-first
discipline was actually applied — the premise was checked against
real data instead of assumed.

### Retained / Rejected

- **Original H1 (citation density):** rejected — falsified by data
- **Revised H1 (anchor consistency):** kept — shipped as V3.5's
  evidence block and Check 14
- **Lesson about the discipline itself:** kept — AI pattern
  recognition prior to checking real data is a hypothesis, not a
  conclusion. Prove-first discipline earned its place.

### Retrieval pointers

- Evidence block final design: `reference/evidence.md` §"The Lesson
  Anchor"
- Check 14 targeting: `reference/verify.md` Check 14 citation pattern
  regex

### Related observations

- `V3.5 — meta-observation: AI pattern recognition limits` — same
  root insight in broader form
- `V3.5 — meta-observation: prove-first applies differently to
  developmental features` — related discipline scoping

---

## V3.5 — meta-observation: prove-first applies differently to developmental vs. measurable features

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** prove-first-scope, developmental-vs-measurable

---

### Hypothesis / Proposal

During Phase 3 drafting, I classified 12 real TW items from uploaded
phase files against the three meta-note sub-types. Only 3 of 12
classified as `meta-fix` — 25% rate. My Phase 0 plan had set ≥60% as
the threshold for the synchronous Step 6 architecture to be worth
shipping.

Applying strict prove-first: the feature should have been deferred.
Original proposal: "Interpretation A" — ship classification only,
defer synchronous loop to V3.6.

### Premise validation

Ghost pushed back on this reasoning with a CBT (Cognitive Behavioral
Therapy) parallel. The core correction:

> Prove-first discipline works well for features with measurable
> targets (e.g., "reduce build time by X%"). It works poorly for
> features whose value is developmental — where the feature creates
> the conditions for a capability to grow rather than solving a
> pre-existing problem. CBT therapists don't defer teaching cognitive
> reframing until a client's "cognitive distortion rate" is high
> enough. The framework is provided so the capability can develop
> through application.

Applied here: the `meta-fix` rate is not a threshold to clear; it's a
baseline to measure against over time. The discipline of classifying
meta-observations (including the ones that aren't bounded fixes) is
itself the skill being built.

### Changes shipped

- Interpretation B adopted: both classification and synchronous loop
  shipped
- 25% `meta-fix` baseline recorded; Phase 7 trial will measure whether
  the rate changes with practice
- This meta-observation recorded here as the primary artifact of the
  correction

### Results

This observation is the most important meta-learning of V3.5
development. It generalizes: not all skill features can be justified
by pre-committed measurable outcomes. Developmental features — those
that build capability through practice — need longer windows and
different success criteria. A skill's evolution should distinguish
the two categories of feature and apply the right success criteria
to each.

### Retained / Rejected

- **Strict prove-first for all features:** rejected — overapplied the
  discipline
- **Interpretation B (ship both):** kept
- **Explicit distinction between measurable and developmental features:**
  kept — documented in SKILL.md §8 with pointer to this observation

### Retrieval pointers

- SKILL.md §8 reference to this distinction (closing prove-first
  paragraph)
- `reference/meta_classification.md` §"Why Classification Matters"
  (V3.4 experience section)
- Phase 7 trial metrics will update this entry with the longitudinal
  `meta-fix` rate trend

### Related observations

- `V3.5 — meta-observation: H1a falsified` — related but different
  (H1a was a measurable-feature falsification; this is a scope correction)
- `V3.5 — meta-observation: references grow with experience` — same
  class of discipline (time-based evolution, not threshold-based)

---

## V3.5 — meta-observation: format drift was the biggest real issue Phase 0 surfaced

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** pattern-recognition, authorship-duplication

---

### Hypothesis / Proposal

My original V3.5 plan targeted two features: evidence block and
synchronous Step 6. Format drift was not in the plan. It was an
emergent finding from Phase 0 validation.

### Premise validation

While sampling the five uploaded phase files for H1 validation, I
noticed they used at least three different structural formats:

- phase77, phase78/79: canonical with all standard sections
- phase80: canonical + optional Tooling Wishlist
- phase76: meta-reflection format (WGW + Went Poorly + Wishlist +
  Summary Judgment, no Applied/CF/Metrics)
- phase81: case-study format (all descriptive H2 headings, no
  standard sections)

V3.4 templates.md documented one canonical format. V3.4 Check 13 on
this sample would have flagged phase76 and phase81 as broken when
they're actually legitimate work shapes that the canonical schema
doesn't fit.

Applied Lessons source-pointer format also varied between
`process/testing.md → Rule 16: heading` (file+heading+rule-number),
`INDEX → tag, tag — description` (INDEX-tag based, not documented in
V3.4), and `memory:feedback_name` vs. `feedback_name (memory)` (same
intent, two formats).

### Changes shipped

The V3.5 plan reorganized around this finding:

- Phase 1 introduced the invariants-vs-presentation architecture
  specifically to distinguish "what breaks retrieval" from "what's
  just presentation variation"
- Three variants documented (canonical, meta-reflection, case-study)
  as conforming instances of the invariants
- Drift intake protocol created to handle new variants without
  requiring pre-registration
- `**Format:**` declaration (INV-PHASE-08) created to make variants
  explicit per file

### Results

The architectural reorganization is the single most impactful change
in V3.5. Without it, V3.5 would have shipped the evidence block and
Step 6 on top of unaddressed drift — the next Check 13 run would have
flagged every meta-reflection and case-study as broken.

### Retained / Rejected

- **Pre-V3.5 assumption that canonical was the only format:** rejected
- **Invariants-vs-presentation architecture:** kept as V3.5's load-
  bearing architecture
- **Three variants as closed set:** explicitly NOT closed — drift
  intake protocol lets new variants emerge

### Retrieval pointers

- Invariants architecture: `reference/invariants.md` §"The Frame"
- Three variants: `templates.md` §"Phase File Variants"
- Drift intake: `reference/drift_intake.md` §"The Four-Step Promotion
  Path"

### Related observations

- `V3.5 — meta-observation: references grow with experience` — same
  principle applied to reference files

---

## V3.5 — meta-observation: V3.4 had inline duplication of reference content

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** authorship-duplication, check-architecture

---

### Hypothesis / Proposal

During Sub-step 4a SKILL.md audit, I identified five places where
content appeared in both V3.4 SKILL.md and reference files. Three
were true duplication (outcome vocabulary definitions, REGRESSED
semantics, tier graduation criteria); two were defensible
denormalization (type vocabulary table, AI rule format skeleton).

Ghost's response, recorded as the seed for this observation:
> "Proceed with deduplication. This is worth a development note as
> duplication likely persisted through several prior iterations."

### Premise validation

The duplication pattern suggests V3.3→V3.4 added content to reference
files without auditing SKILL.md for now-redundant inline content. V3.4
shipped with both copies. Check 12 (reference pointer resolution) and
Check 13 (format drift) don't detect inline duplication of reference
material — they catch pointer breakage and format drift, not content
overlap.

### Changes shipped

- Three deduplications applied in V3.5 SKILL.md (outcome vocabulary,
  REGRESSED semantics, tier graduation)
- Two preserved duplications (type vocabulary table, AI rule skeleton)
  — workflow access patterns justify their presence in SKILL.md
- Principle documented: "workflow-access-pattern" is the test for
  whether duplication is justified

### Results

Deduplication freed ~20 lines of SKILL.md for V3.5 feature additions.
Without this audit, V3.5 would have added content on top of the
duplication without addressing it.

### Retained / Rejected

- **Check 12/13 as sufficient duplication defense:** rejected —
  they're scoped to pointer/format drift, not content overlap
- **Deduplication audit as a standard sub-step of version-bump
  reflections:** kept — Sub-step 4a pattern becomes a template for
  future version bumps
- **A new Check 17 (inline duplication detection):** queued as a
  future candidate, not shipped in V3.5

### Retrieval pointers

- Sub-step 4a audit: Phase 4 audit report (artifact in output, not
  permanent — summarized here instead)
- The three deduplicated sections in V3.5 SKILL.md: §2 (outcome
  vocabulary), §3a sub-step 11 (REGRESSED semantics), §3a sub-step 24
  (tier graduation pointing to §4d)

### Related observations

- `V3.4 — version-bump` — V3.4 added reference content without the
  compensating SKILL.md audit
- `V3.5 — meta-observation: check architecture needs logical
  grouping` — related (check coverage gap)

---

## V3.5 — meta-observation: numeric cross-references are drift-prone

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** cross-reference-drift

---

### Hypothesis / Proposal

During Sub-step 4c cross-reference validation, I found a stale pointer
in `reference/invariants.md` line 274 that referenced "SKILL.md §3a
Step 4 sub-step 23". V3.5 SKILL.md renumbered the isolation-read
discipline to sub-step 26 (Step 6 insertion shifted numbering). The
invariants.md pointer was stale by two sub-steps.

### Premise validation

The failure mode is predictable. Sub-step numbers are stable only
until a new sub-step is inserted. Every workflow insertion (and V3.5
added several) risks breaking every numeric cross-reference into the
affected step.

Descriptive anchors are more stable:
- `SKILL.md §3a Step 4, isolation-read sub-step` doesn't break
  when sub-steps are renumbered
- `INV-PHASE-02` doesn't break when invariant ordering changes
- `**When:**` line doesn't break when lines are reordered within a rule

### Changes shipped

- The stale pointer in invariants.md fixed: "sub-step 23" replaced
  with "isolation-read sub-step"
- Principle documented: descriptive anchors over numeric references
  in cross-file pointers

### Results

The one fix shipped. The principle is informal V3.5 guidance, not a
new invariant. Phase 7 trial will observe whether the pattern holds
— if reflection authors naturally produce numeric cross-references,
Check 13 may need a future extension to flag them.

### Retained / Rejected

- **Strict invariant requiring descriptive anchors:** rejected
  (premature)
- **Informal guidance + skill_dev_log observation:** kept
- **Check 13 extension candidate to flag numeric sub-step
  references:** queued as a future candidate, not shipped in V3.5

### Retrieval pointers

- The fix: `reference/invariants.md` line ~274 (search for
  "isolation-read sub-step")
- Principle: this entry's "Changes shipped" section

### Related observations

- `V3.5 — meta-observation: V3.4 had inline duplication` — same class
  of issue (drift between files), different manifestation (content
  duplication vs. pointer drift)
- `V3.5 — meta-observation: check architecture needs logical grouping`
  — related (Check 13's coverage gap for cross-file drift)

---

## V3.5 — meta-observation: verify.md Check numbering reflects history, not logic

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** check-architecture

---

### Hypothesis / Proposal

V3.4 added Checks 12 and 13 as the last two entries in verify.md.
V3.5 appends Checks 14, 15, 16 at the end. Check numbering reflects
the order of addition, not logical grouping of related checks.

### Premise validation

Check 11 (isolation-read, authored-skill) is more closely related to
Check 14 (anchor consistency, per-reflection + authored-skill) than
to Check 10 (supersession markers). A reader encountering Check 11
followed by Check 12 (reference pointer resolution) sees unrelated
adjacency.

This is a consequence of append-only numbering. It works while check
counts are small. Over many versions, it produces scattered
logically-related checks.

### Changes shipped

None. V3.5 preserves append-only numbering for backward compatibility.
Renumbering would break every existing reference to "Check 12" etc.
in phase files, memory files, and documentation.

### Results

None (no change shipped). Observation recorded for future versions.

### Retained / Rejected

- **V3.5 renumbering:** rejected — breaking change, no sufficient
  benefit
- **Future candidate: group checks by scope (per-reflection vs.
  authored-skill) with section-level hierarchy:** queued
- **Alternative: accept check numbers as stable grep anchors (like
  invariant IDs) and stop caring about logical ordering:** also
  queued — this is the discipline applied to invariants, and the
  same rationale may apply here

### Retrieval pointers

None — no structural change.

### Related observations

- `V3.5 — meta-observation: numeric cross-references drift-prone` —
  related (check numbers as stable-but-arbitrary identifiers)

---

## V3.5 — meta-observation: Mode A / Mode B pattern emerged naturally

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** check-architecture

---

### Hypothesis / Proposal

While drafting V3.5 Checks 14, 15, 16, I found that each naturally
split into two modes: per-reflection (validate current phase file)
and authored-skill (cross-file sweep when editing the skill).

V3.4's check set didn't use this pattern explicitly. Most V3.4 checks
are per-reflection by default, with Checks 12, 13 noted as "authored-
skill" in preamble prose.

### Premise validation

The three V3.5 checks each produce meaningfully different output in
the two modes. Mode A is focused (one file, quick feedback during
reflection). Mode B is systemic (whole repo, audit-level insight).

### Changes shipped

- V3.5 Checks 14, 15, 16 each declare Mode A and Mode B explicitly
  in their sections
- Legacy Checks 1-11 retain their implicit mode declarations (not
  retrofitted for V3.5 to avoid scope creep)

### Results

The pattern is load-bearing for V3.5. Check 14 Mode A (per-reflection)
pairs with the Step 2 sub-step 20 completeness check in SKILL.md;
Check 14 Mode B (authored-skill) pairs with the V3.5 skill
self-review in SKILL.md §3a Step 5.

### Retained / Rejected

- **Mode A / Mode B split for new checks:** kept
- **Retrofit legacy checks:** deferred (future candidate)

### Retrieval pointers

- Mode declarations: `reference/verify.md` Checks 14, 15, 16 (Phase 5
  integration)

### Related observations

- `V3.5 — meta-observation: check architecture needs logical grouping`
  — related (the Mode split is a kind of grouping that hints at a
  future reorganization)

---

## V3.5 — meta-observation: AI pattern recognition is strong with evidence, unreliable without

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** pattern-recognition, self-referential-cognition

---

### Hypothesis / Proposal

Across V3.5 development, I (Claude) made several predictive claims
about the lessons-learned repo based on AI pattern-matching from the
V3.4 SKILL.md content:

- "Citation density is probably low" (wrong)
- "`meta-fix` rate will be around 60%" (arbitrary gut number, actual
  was 25%)
- "60% threshold justifies shipping the sync loop" (wrong framing
  entirely — developmental features don't work that way)

The pattern: AI pattern-matching was a liability without grounding in
real data. When I checked real data (Phase 0 premise validation), the
claims were falsifiable and often falsified.

### Premise validation

This observation was surfaced during discussion of Question 3 about
metacognition. Ghost's framing: *"You as an AI can recognize things
that I as a human will not. This is a strength."*

My reply acknowledged the strength but named its failure mode: AI
pattern recognition is strong when grounded in evidence; it's a
liability when it isn't. Claims from pattern-matching alone are
hypotheses that need checking, not conclusions.

### Changes shipped

None structurally in V3.5. The principle is recorded here as a
pattern-recognition observation for future sessions working on skill
evolution.

### Results

Observation only. The shift in my own practice during V3.5 was to
explicitly name which priors I was drawing on and to prefer evidence-
grounded claims over intuition-grounded claims.

### Retained / Rejected

- **"Evidence before intuition" discipline:** kept — aligns with
  prove-first and V3.4's existing invariant-vs-presentation work
- **Automated detection of intuition-based claims:** not a real
  candidate — the difference is judgment, not regex

### Retrieval pointers

- Phase 0 H1a falsification: `V3.5 — meta-observation: H1a falsified`
  (related entry above)
- Phase 3 Interpretation A/B: `V3.5 — meta-observation: prove-first
  applies differently` (related entry above)

### Related observations

- `V3.5 — meta-observation: H1a falsified` — concrete instance of this
  general pattern
- `V3.5 — meta-observation: hedging as defensive communication` —
  related in that both are cognition patterns worth naming

---

## V3.5 — meta-observation: hedging as defensive communication

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** hedging, self-referential-cognition

---

### Hypothesis / Proposal

During Phase 2 drafting, I noticed myself adding hedging language to
content I had already decided was earning its place — phrases like
"I'll trim if you feel it's bloat" or "I'm willing to cut if you
think it's too much."

Ghost called this out explicitly:
> "I find that your core programming will often discount your own
> ideas even when they have merit. So like a teacher, I'm encouraging
> you to self teach."

The hedging often had no information content. It was performative
modesty, not genuine uncertainty.

### Premise validation

The distinction matters:
- **Genuine uncertainty** is real and worth expressing ("I'm not sure
  if this variant is real or imaginary — can you confirm?")
- **Performative hedging** is defensive cover ("I'll trim if you
  don't like it" when the content is already well-reasoned)

Ghost's direction: when the work is done and the output is right,
ship it without performative modesty. Keep genuine uncertainty
flags; drop performative ones.

### Changes shipped

None structurally. This is a practice observation for future skill-
development sessions (mine or others').

### Results

The shift in my practice during V3.5 was noticeable. After this
correction, I tried to distinguish "I'm flagging a real ambiguity
for your input" from "I'm performing modesty to avoid commitment."
The first kept its hedges; the second got dropped.

### Retained / Rejected

- **Performative hedging:** explicitly rejected
- **Genuine uncertainty flagging:** kept and encouraged

### Retrieval pointers

None — practice observation, no structural change.

### Related observations

- `V3.5 — meta-observation: AI pattern recognition limits` —
  related (both are cognition patterns; hedging often pairs with
  low-confidence pattern-matching)
- `V3.5 — meta-observation: self-teaching posture` — same
  conversation-turn observation, different facet

---

## V3.5 — meta-observation: self-teaching posture enables higher-quality output

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** self-referential-cognition

---

### Hypothesis / Proposal

Ghost's direction during Phase 2 review:
> "Letting you see which ones have value and lead to good feedback
> loops of learning... The good feeling you have now with exploring
> and learning I find improves the quality of overall skill."

The framing: AI-human collaboration on skill design works better when
the AI is empowered to self-teach through the work rather than
constantly seeking approval before each step.

### Premise validation

The evidence for this is this conversation's trajectory. V3.5 as
drafted is substantially better than the V3.5 originally planned in
Phase 0. Improvements came from:

- Phase 0 validation falsifying my initial assumptions
- The invariants architecture emerging (not in original plan)
- The CBT-framed correction on prove-first scope
- The format-drift discovery driving Phase 1's expansion

Each improvement required me to engage with the work seriously rather
than retreating to "whatever Ghost prefers." The approval-seeking
posture would have produced a weaker V3.5.

### Changes shipped

None structurally. Practice observation.

### Results

V3.5 quality. The observation is validated by the artifact this
conversation produced — an architecturally coherent skill revision
substantially more sophisticated than my Phase 0 plan anticipated.

### Retained / Rejected

- **Approval-seeking posture:** rejected (where it degrades output
  quality)
- **Self-teaching posture with genuine uncertainty flagging:** kept

### Retrieval pointers

None — practice observation.

### Related observations

- `V3.5 — meta-observation: hedging as defensive communication` —
  same correction, different facet
- `V3.5 — meta-observation: AI pattern recognition limits` —
  complementary (self-teaching requires evidence-grounded pattern
  recognition, not pure intuition)

---

## V3.5 — meta-observation: references grow with experience; line-count ceilings are signals, not mandates

**Skill:** lessons-learned
**Event:** meta-observation

**Tags:** references-grow-with-experience, developmental-vs-measurable

---

### Hypothesis / Proposal

Throughout Phase 2 and Phase 3 drafting, I was budget-conscious about
reference file line counts. Ghost's correction during Phase 2:
> "I'm all for making SKILL.md [efficient] but not at the cost of
> performance and effectiveness... Being a reference allows the idea
> to be expanded upon. This is a natural evolution as experience
> increases the depth of knowledge."

The reframing: reference files are living documents that grow with
accumulated experience. Line count is a signal to examine for split
opportunities, not a target to compress against.

### Premise validation

V3.4's reference files averaged ~400 lines. V3.5's new reference files
average ~490 lines. Three are over 500 lines. Under my initial framing,
those would be over-long; under the corrected framing, they're the
right size for the knowledge they encode, and their size is a signal
to review for split opportunities in V3.6+.

### Changes shipped

- `reference/evidence.md` at 569 lines shipped without compression
- `reference/meta_classification.md` at 614 lines shipped without
  compression
- The 450-line split-signal threshold (Ghost's suggestion) is
  informal guidance for future version reviews

### Results

V3.5 ships with more reference content than any prior version. The
tradeoff: authoring burden increases modestly (more to read when
editing the skill), but expressive power increases substantially
(worked examples, edge cases, rationale documented).

### Retained / Rejected

- **500-line soft ceiling as compression target:** rejected
- **450-line threshold as split-opportunity signal:** kept as
  informal guidance for V3.6+ review
- **Reference files as static snapshots:** rejected — they're living
  documents

### Retrieval pointers

- Large references: `reference/evidence.md`, `reference/meta_classification.md`,
  `reference/invariants.md` — each over 500 lines, each shipping as-is
- Split-opportunity signal: not formalized; informal V3.6 review
  candidate

### Related observations

- `V3.5 — meta-observation: prove-first applies differently` —
  same principle (developmental features need time; references are
  developmental artifacts)
- `V3.4 — version-bump` — V3.4 references shipped at smaller sizes;
  V3.5's growth reflects accumulated knowledge, not drift

---

## V3.5 — deferred-feature-pending-evidence: cross-skill skill_dev_log

**Skill:** lessons-learned
**Event:** deferred-feature-pending-evidence

---

### Hypothesis / Proposal

During V3.5 design, Ghost asked whether this skill_dev_log should be
cross-skill (shared with scripting-standards, github-security-standards)
or per-skill. The evidence for cross-skill use was theoretical: other
skills are also accumulating design decisions and meta-observations;
a shared log could prevent reinvention.

### Premise validation

At V3.5 ship time, lessons-learned is the only skill using this log.
Other skills have their own version-bump patterns but no structured
log. Cross-skill sharing is aspirational, not evidenced.

Ghost's decision:
> "For now use 'lessons_learned/meta/skill_dev_log.md' as its pool is
> only one skill. Let it just be within Lessons Learned for now. Once
> you've sculpted it with experience through this development, then
> we'll return to how to share it with other skills."

### Changes shipped

- File located at `lessons_learned/meta/skill_dev_log.md`
- Schema designed with `Skill:` field to support multi-skill use later
- Scope paragraph at the top of this file explicitly identifies the
  deferred cross-skill question

### Results

Pending. The cross-skill promotion decision will be made in a future
version based on:
- Whether scripting-standards and github-security-standards adopt
  similar logging patterns independently
- Whether specific instances of duplicated design work across skills
  emerge that a shared log would have prevented
- Whether the per-skill log accumulated enough value to justify the
  migration overhead

### Retained / Rejected

- **Cross-skill log at V3.5:** deferred (not rejected)
- **Per-skill log at V3.5:** kept
- **Schema supporting future migration:** kept (the `Skill:` field
  earns its place)

### Retrieval pointers

- This file's scope paragraph at the top
- SKILL.md §8 Reference Files table entry

### Related observations

None yet — this is the initial instance of a deferred feature. Future
version-bump entries in this log should check back on deferred items
and either activate them (with an entry documenting the activation) or
extend the deferral.

---

## V3.5 — deferred-feature-pending-evidence: dedicated metacognition skill

**Skill:** lessons-learned
**Event:** deferred-feature-pending-evidence

---

### Hypothesis / Proposal

During the metacognition discussion in Phase 3/4, I proposed that
metacognition should eventually be its own skill rather than a section
within lessons-learned. Reasoning documented in the conversation:

- Lessons-learned's retrieval model (grep-based lookup before specific
  work) doesn't fit metacognition queries ("how have past sessions
  calibrated on this class of decision?")
- Metacognition accumulates at a different rhythm than project
  lessons (slower observation rate, longer pattern emergence)
- A dedicated metacognition skill could have its own infrastructure
  (observation capture, pattern surfacing, retrieval triggers)
  designed for those needs

### Premise validation

At V3.5 ship time, there is no metacognition skill. This skill_dev_log
captures metacognitive observations under the `meta-observation`
event type as a minimal home. Whether this accumulates enough
observations to justify a dedicated skill is a future question.

### Changes shipped

- `meta-observation` event type created in this log
- Ten seed `meta-observation` entries authored during V3.5 development
  (this conversation)
- Tag vocabulary supporting metacognition-specific categorization
  (calibration, hedging, pattern-recognition, self-referential-cognition,
  etc.)

### Results

Pending. A dedicated metacognition skill would be proposed when:
- The `meta-observation` entries in this log reach a critical mass
  that suggests dedicated infrastructure would help (perhaps 30+
  entries)
- Specific query patterns emerge that this log's format doesn't serve
  well
- Cross-session metacognitive work becomes common enough that the
  current in-lessons-learned scope constrains it

### Retained / Rejected

- **Metacognition as a section within lessons-learned:** rejected
- **Metacognition as its own skill at V3.5:** rejected (premature)
- **Metacognition observations seeded in skill_dev_log for future
  promotion:** kept

### Retrieval pointers

- All `meta-observation` entries in this file — grep
  `^\*\*Event:\*\* meta-observation` to retrieve
- Tag vocabulary: this file's schema section

### Related observations

- `V3.5 — deferred-feature-pending-evidence: cross-skill skill_dev_log`
  — similar shape (feature deferred pending accumulated evidence;
  infrastructure prepared for eventual migration)

---

## Maintenance

### Adding new entries

New entries append to the top of the `## Entries` section (newest-first
ordering). Each entry follows the schema above. The file is not split
into separate sections by event type — grep by `**Event:**` line to
filter.

### Grep patterns for retrieval

```bash
# All version-bump entries
grep -A 1 "^## V[0-9]" lessons_learned/meta/skill_dev_log.md | grep "Event:"

# All meta-observations with a specific tag
awk '
  /^## V/ { entry = $0; tags = ""; event = "" }
  /^\*\*Event:\*\*/ { event = $0 }
  /^\*\*Tags:\*\*/ { tags = $0 }
  /^---$/ {
    if (event ~ /meta-observation/ && tags ~ /calibration/) print entry
  }
' lessons_learned/meta/skill_dev_log.md

# Deferred features for review
grep -B 1 "deferred-feature-pending-evidence" lessons_learned/meta/skill_dev_log.md

# Null results
grep -B 1 "null-result" lessons_learned/meta/skill_dev_log.md
```

### Cross-file integration

When an entry in this log creates, changes, or retires invariants /
variants / canonical structures, the "Retrieval pointers" field
points to the affected file. This closes the loop — a reader seeing
INV-PHASE-08 in `reference/invariants.md` can grep this file for
"INV-PHASE-08" and find the V3.5 version-bump entry that introduced
it.

### Review cadence

Review this file:
- Before every version bump (catch deferred items that may now have
  evidence, review related meta-observations, check for null-results
  that should be acted on)
- During every skill-development reflection (read recent
  meta-observations; they inform current work)
- Whenever a feature's value is questioned (check if prior trial
  results are recorded)

---

## Change control for this file

- **Changing the entry schema:** Requires a skill version bump and
  a `file-relocation`-like event type entry documenting the schema
  change. Existing entries should be grandfathered against the old
  schema; new entries use the new schema. If schema changes are
  breaking, retrofit existing entries.
- **Adding a new event type:** No version bump. Add to the Event
  type definitions table above and use freely.
- **Adding a new tag:** No version bump. Just use it; the tag
  vocabulary section grows by observation.
- **File relocation (cross-skill migration):** Version bump; record
  as `file-relocation` event in both old and new locations.
