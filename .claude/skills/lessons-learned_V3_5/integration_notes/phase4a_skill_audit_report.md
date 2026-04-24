# Sub-step 4a — SKILL.md Audit for V3.5 Integration

## Audit purpose

Identify what in V3.4 SKILL.md is load-bearing workflow (must stay),
what is explanatory or example content (candidate for relocation to
references), and what new content Phase 1–3 deliverables require SKILL.md
to add. The goal is a V3.5 SKILL.md that integrates new disciplines
cleanly without bloating the orchestrating workflow.

This audit is not itself a decision about what to move — it's a
structured identification of candidates. The actual relocation decisions
happen in Sub-step 4b drafting, informed by this audit.

---

## The workflow-vs-reference test

For each section of V3.4 SKILL.md, the audit asks:

**Test 1:** Does this content describe *what the author does* (workflow)
or *why/how it's formatted* (reference material)?

**Test 2:** Can the content be compressed to a pointer ("see
reference/X.md for the details") without losing what a reflection needs
to run correctly?

**Test 3:** If a future Claude session never reads this section but has
access to its target reference, can they still author a correct
reflection?

Content that passes all three tests is a relocation candidate. Content
that fails any one should stay in SKILL.md.

A secondary concern: some SKILL.md content is currently duplicated in
`reference/templates.md` (e.g., the 9-outcome vocabulary appears in both
places). Deduplication is its own kind of relocation — keep the
canonical definition in the reference, leave a minimal enumeration or
pointer in SKILL.md.

---

## V3.4 SKILL.md — section-by-section audit

### Frontmatter + opening paragraphs (lines 1–28)

**Content:** YAML frontmatter with trigger description; 2-paragraph
framing of what the skill does and its scope exclusion (project-level
knowledge, not user preferences).

**Verdict:** Stays. This is identity and trigger material — it has no
reference alternative and it must load first.

**V3.5 change:** Bump version to V3.5; add `"Format:"` declaration and
drift intake to the trigger list (e.g., "undocumented variant detected"
as a trigger).

---

### Section 1 — System Architecture Three Layers (lines 30–60)

**Content:** The three-layer architecture (phase files, INDEX, AI
files), file locations, access patterns, and the relationship between
layers.

**Verdict:** Stays, lightly edited. This is the mental model for
everything else in the skill — a session that doesn't understand the
three layers can't author correctly.

**V3.5 change:** No architectural change. Minor wording: add a single
sentence noting that phase files declare a `**Format:**` variant
(pointer to `templates.md` §"Phase File Variants"). The architecture
itself is unchanged.

**Relocation candidate:** None. Every sentence is load-bearing context
for the rest of the skill.

---

### Section 2 — Lookup Protocol (lines 63–180)

**Content:** When to look up, how to choose keywords, quick-lookup
commands, deep-lookup commands, zero-hit/too-many-hit/ambiguous-hit
resolution, the grep contract explanation, token budget discussion, and
the `/tmp/lookups_{phase_id}.md` tracking format.

**Verdict:** Mixed. Two distinct content types share this section —
workflow ("here's what you do") and explanatory reference ("here's why
the grep contract works").

**Load-bearing workflow (stays in SKILL.md):**
- When to look up / when to skip
- The 3-source keyword selection table
- Quick lookup command sequence (5 steps)
- Deep lookup command sequence
- Zero-hit broaden / too-many narrow / ambiguous filter (these are
  decision trees a session applies during lookup)
- The `/tmp/lookups_{phase_id}.md` tracking instruction — this is
  workflow, and it's load-bearing for the Applied Lessons feedback loop

**Relocation candidate: The grep contract explanation (lines 139–158).**
This is ~20 lines explaining *why* INDEX rows and AI files are formatted
as they are. The format rules themselves live in `templates.md`. This
block tells the same story from the retrieval-side perspective.

- *Move to:* A new section in `templates.md` titled "Why the grep
  contract works" or a new `reference/lookup.md` carrying the full
  lookup protocol details
- *Leave in SKILL.md:* A one-line reminder that "INDEX rows, AI file
  headings, and _overview.md are format-constrained for grep
  efficiency — see templates.md §Grep Contract"
- *Savings:* ~15–20 lines

**Relocation candidate: The outcome vocabulary list (lines 176–178).**
The 9-value enumeration appears inline here, and again in
`templates.md` §"Applied Lessons Table Format" → Outcome Vocabulary.
Two copies that must stay in sync — duplication risk.

- *Move to:* Keep full definitions in `templates.md` only
- *Leave in SKILL.md:* The 9 values in a bare list with a pointer:
  `Outcome vocabulary (9 values): applied | applied proactively |
  in place | N/A | missed | REGRESSED | contradicted | revised |
  discovered — see templates.md §Applied Lessons for definitions`
- *Savings:* ~5 lines (the inline definitions go; the enumeration
  stays)

---

### Section 3a — Full Reflection (lines 185–321)

**Content:** 31 sub-steps across 5 groups (GATHER, DRAFT, UPDATE INDEX,
UPDATE AI, VERIFY). This is the heart of the skill's workflow.

**Verdict:** Mostly stays — this IS the workflow. But several sub-steps
currently carry inline explanatory content that has reference homes.

**Load-bearing workflow (stays):**
- All 31 sub-steps' core instructions
- The GATHER / DRAFT / UPDATE / UPDATE / VERIFY orchestrating structure
- The "If a reflection is interrupted" recovery note at the bottom

**Relocation candidate: Sub-step 9's expanded REGRESSED/contradicted
explanations (lines 215–226).** Sub-step 9 instructs filling the
Applied Lessons table, then dedicates ~12 lines to explaining REGRESSED
semantics and handling `contradicted` rules. This semantic depth
belongs in `templates.md` §"Applied Lessons Table Format".

- *Leave in SKILL.md:* The sub-step instruction ("Fill the table
  from the GATHER inventory and your /tmp/lookups_{phase_id}.md note")
  plus a single-line reminder about REGRESSED being the most important
  outcome.
- *Move to:* `templates.md` already contains most of this. Confirm
  the destination is complete; trim the SKILL.md duplication.
- *Savings:* ~8–10 lines

**Relocation candidate: Sub-step 21's tier-graduation criteria
(lines 262–271).** The Active→Foundation and Foundation→Reference
graduation rules are documented in Section 4d as well. Duplication.

- *Leave in SKILL.md:* The sub-step instruction ("Graduate old Active
  entries at phase transitions") with a pointer: "see §4d"
- *Savings:* ~8 lines

**V3.5 additions to §3a:**

- **New sub-step in Step 1 — GATHER for evidence block.** Between
  current sub-step 2 and sub-step 3: add "Run the evidence block
  commands and write output to `/tmp/evidence_{phase_id}.md` — see
  `reference/evidence.md` §Evidence Block for commands." About 2–3
  lines inline.
- **New sub-step in Step 2 — DRAFT for variant declaration.** After
  sub-step 8 (write header): add "Declare `**Format:**` variant on the
  header block — see `templates.md` §Phase File Variants for the three
  documented variants or `reference/drift_intake.md` for undocumented
  shapes." About 2–3 lines.
- **Modified sub-step 16 — classification.** Replace the single
  "`type: meta`" tag reference with the three sub-type classification
  (`meta-fix` / `meta-question` / `meta-wish`), with a pointer:
  "see `reference/meta_classification.md` §Three Sub-Types". About
  3–4 lines (replacing ~6 existing lines, net saving).
- **New sub-step in Step 2 — completeness check.** Between drafting
  and moving to Step 3 (INDEX update): add "Run the completeness check
  against the evidence block output — see `reference/evidence.md`
  §Completeness Check." About 2–3 lines.
- **New Step 6 — synchronous meta-fix loop.** After VERIFY (Step 5):
  full new step with ~8–10 lines orchestrating the meta-fix loop,
  with a pointer to `reference/meta_classification.md` §Synchronous
  Step 6 for the detailed per-entry workflow.

**Net effect on §3a:** Addition of ~20–25 lines for V3.5 features;
removal of ~16–18 lines through relocation. Net addition ~5–9 lines.

---

### Section 3b — Lightweight Capture (lines 323–340)

**Content:** Mid-session single-lesson capture — append to current
phase file, add one INDEX row, add one AI rule.

**Verdict:** Stays entirely. This is workflow and it's short enough
not to need compression.

**V3.5 change:** Minor — note that variant declaration applies to
lightweight-captured phase files too, and that completeness check is
optional for lightweight capture.

**Relocation candidate:** None.

---

### Section 3c — Conflict Avoidance (lines 342–353)

**Content:** Git diff check before writing, with bash command.

**Verdict:** Stays. Short, load-bearing, no natural reference home.

---

### Section 4 — Decision Trees (lines 355–423)

**Content:** Four decision trees — what to record, type classification,
AI file routing, INDEX tier.

**Verdict:** These are the decision trees a session runs during
capture. They ARE workflow, but they're high-load workflow — tables of
criteria the author looks up mid-authoring.

**Load-bearing (stays):**
- 4a "Is this worth recording?" — directly decision-supporting
- 4c "Which AI subject file?" — directly decision-supporting
- 4d "Which INDEX.md tier?" — directly decision-supporting

**Relocation candidate: 4b "What type is this?" table (lines 379–390).**
The type vocabulary (rule/bug/pattern/insight) is authoritative in
`templates.md` §"INDEX.md Row Format" → Type vocabulary. This table
duplicates that definition with one additional column (Example).

- *Option A:* Keep in SKILL.md — it's a quick decision reference the
  author uses mid-authoring
- *Option B:* Replace with a pointer and keep just the 4-value
  enumeration
- *Preference:* Option A. This is the type of table an author wants
  visible while classifying; a pointer increases lookup friction. The
  duplication is acceptable because the type vocabulary is one of the
  invariants (INV-INDEX-05) and is unlikely to drift.

**V3.5 change to §4:** Add a 5th decision tree — 4e "Which variant?"
— that points to `templates.md` §Phase File Variants. Short — ~5
lines including the variant decision summary: *"Single unit of work?
canonical. Arc-level? meta-reflection. Teaching future sessions?
case-study. None fit? drift intake protocol."*

---

### Section 5 — Anti-Patterns (lines 426–434)

**Content:** 6 bullet-point anti-patterns (things NOT to record).

**Verdict:** Stays entirely. Short, scannable, directly relevant to
drafting discipline.

**V3.5 change:** Consider adding one anti-pattern about the anchor
discipline: e.g., *"Writing Lesson lines that restate the entry title —
a Lesson line must carry actionable content beyond the title."* From
`reference/evidence.md` §Anti-patterns. One line inline.

---

### Section 6 — Quick Reference Card (lines 437–462)

**Content:** 26-line compressed cheat sheet covering lookup, capture,
sections, entry/INDEX/AI formats, isolation rules, applied lessons
format, supersession, cross-ref, types, tiers, graduation, CF, new
file, split, bootstrap, retroactive, self-review.

**Verdict:** Stays. This is the compressed reference format that
experienced authors scan instead of reading full sections. Cutting it
would lose value for sessions that have internalized the workflow and
need reminders.

**V3.5 changes:**
- Add lines for new V3.5 concepts:
  - `Format:     canonical | meta-reflection | case-study — declared in phase file header`
  - `Variants:   see templates.md §Phase File Variants; undocumented → drift_intake.md`
  - `Anchor:     **Lesson:** line on every Bugs/DD entry — cite commit / file:line / function / count`
  - `Evidence:   churn + errors + test-delta → /tmp/evidence_{phase_id}.md during GATHER`
  - `Completeness: after drafting, cross-check top churned files + error classes against entries`
  - `Meta-notes: **Sub-type:** meta-fix | meta-question | meta-wish — classify at authorship`
  - `Step 6:    meta-fix entries become synchronous edit proposals (max 3 per reflection)`
- Consider consolidating: the current card has some slightly-redundant
  lines (e.g., "Bootstrap" and "Retroactive" can combine to one line
  with both pointers)

**Net effect:** ~7 new lines added, ~2 consolidated. Net growth ~5
lines.

---

### Section 7 — Portable Export (lines 466–478)

**Content:** Project-completion export workflow — Foundation tier to
`export.md`.

**Verdict:** Stays, unchanged. This is workflow and it's bounded.

---

### Section 8 — Reference Files (lines 481–508)

**Content:** Table of reference files with "read when" conditions, plus
the closing "prove-first before shipping a change" note.

**Verdict:** Stays, but MUST be updated for V3.5.

**V3.5 changes:**
- Add rows for new V3.5 references:
  - `reference/invariants.md` — "Before editing the skill; when Check 13/16 fires"
  - `reference/evidence.md` — "Before authoring Bugs/DD entries; when Check 14 fires"
  - `reference/meta_classification.md` — "When authoring wishlist entries; running Step 6"
  - `reference/drift_intake.md` — "When a phase file shape doesn't fit documented variants"
  - `templates.md` §"Phase File Variants" (new section) — referenced indirectly
  - `lessons_learned/meta/skill_dev_log.md` — "When making skill-design decisions or recording meta-observations"
- The closing "prove-first" paragraph gets a brief update referencing
  V3.5's additions and the Interpretation-A/B learning (the distinction
  between measurable features and developmental features, recorded as
  meta-observation in skill_dev_log)

**Net effect:** ~8–10 lines added (new reference rows + updated prose).

---

## Aggregate audit findings

### What stays in SKILL.md

- All of §1 (architecture) — unchanged except one sentence about variant declaration
- Most of §2 (lookup protocol) — retain workflow, compress grep-contract explanation
- All of §3a structural workflow — 31 sub-steps, lightly modified; new sub-steps added for V3.5 features
- All of §3b and §3c — short, load-bearing
- Most of §4 (decision trees) — 4 current trees stay as-is; new 4e added
- §5 anti-patterns — stays, one new bullet
- §6 Quick Reference Card — stays, updated for V3.5
- §7 Portable Export — stays unchanged
- §8 Reference Files table — stays, significantly updated

### What moves out

- Grep contract explanation (§2, ~15–20 lines) → `templates.md` or new
  `reference/lookup.md`
- Inline outcome vocabulary definitions (§2, ~5 lines) → reference only
- REGRESSED/contradicted expanded semantics (§3a sub-step 9, ~8–10 lines)
  → already in templates.md, deduplicate here
- Tier graduation criteria duplicated in §3a sub-step 21 (~8 lines) →
  already in §4d, deduplicate here

**Total relocation candidate: ~36–43 lines.**

### What's added

- V3.5 sub-steps in §3a for evidence block, variant declaration,
  meta-classification, completeness check, Step 6 (~25 lines)
- New §4e "Which variant?" decision tree (~5 lines)
- Anti-pattern addition for anchor discipline (~1 line)
- Quick Reference Card entries for V3.5 features (~5 lines)
- Reference Files table updates (~8–10 lines)
- Minor wording changes for version and variants throughout (~5 lines
  cumulative)

**Total addition: ~50 lines.**

### Net line budget projection

V3.4 SKILL.md: 508 lines.
Additions: ~50 lines.
Relocations out: ~36–43 lines.

**Projected V3.5 SKILL.md: ~515–522 lines.**

Modest growth. Within your guidance — growing where performance
requires, compressing where duplication exists.

If tighter budget is desired, the next trim targets are:
- Further compression of §2's zero-hit/too-many/ambiguous subsections
  — these could become bulleted-list-only (removing the ~8 lines of
  command examples) with command examples moving to a new
  `reference/lookup.md`
- Full relocation of the §2 grep contract to a new reference file
  (frees ~20 lines)

Both are available if the ~515-line projection feels off. My instinct
is not to trim further — the additions are earning their place and
~515 is a reasonable size for a skill this sophisticated.

---

## New references Phase 4 creates

This audit reveals no need for additional new references beyond what
Phases 1–3 already produced. The four new references stay:

- `reference/invariants.md`
- `reference/drift_intake.md`
- `reference/evidence.md`
- `reference/meta_classification.md`

Plus `templates.md` gaining a new §"Phase File Variants" section
(Phase 1 Sub-step 1b deliverable), and `verify.md` gaining Checks 14,
15, 16 (Phase 5).

If the grep-contract relocation is done, a candidate new reference
`reference/lookup.md` could emerge — but it's optional and not required
for V3.5 integration. Defer unless Sub-step 4b drafting reveals a
cleaner integration with it present.

---

## Deduplication opportunities surfaced

Several duplications between SKILL.md and `templates.md` / `verify.md`:

1. **Outcome vocabulary** — full definitions appear in both §2 of
   SKILL.md and §"Applied Lessons Table Format" of templates.md.
   Resolution: keep in templates.md only; SKILL.md carries the
   enumeration with pointer.

2. **Tier graduation criteria** — appears in §3a sub-step 21 and
   §4d of SKILL.md. Resolution: consolidate to §4d with §3a pointing
   to it.

3. **REGRESSED semantics** — detailed explanation in §3a sub-step 9
   and in templates.md §"Applied Lessons Table Format". Resolution:
   trim SKILL.md to the essential instruction, keep detail in
   templates.md.

4. **Type vocabulary** — appears in §4b table and in
   templates.md §"INDEX.md Row Format" → Type vocabulary. Resolution:
   **DO NOT deduplicate.** §4b is a decision-support table used during
   authoring; the duplication earns its place because the type
   vocabulary is invariant-level stable.

5. **AI rule format skeleton** — partial appearance in §6 Quick
   Reference Card and full definition in templates.md §"AI File Rule
   Format". Resolution: **DO NOT deduplicate.** The Quick Reference
   version is compressed; the templates.md version is canonical. They
   serve different purposes.

The distinction between "deduplicate" and "don't deduplicate" is
about workflow access patterns. If the information is consulted during
active work (decision-making while drafting), having it local in
SKILL.md reduces friction. If it's consulted during setup or
verification (before or after work), a pointer is fine.

---

## Audit summary

V3.5 SKILL.md grows modestly (~+7 to +14 lines net) with the audit
suggestions applied. All new V3.5 features integrate with pointers
to their reference files; SKILL.md retains its orchestrating role
without becoming the reference it depends on. Duplication is reduced
in three places; preserved in two where workflow access patterns
justify it.

**Recommendation:** Proceed to Sub-step 4b drafting with the audit
suggestions applied, targeting ~515 lines as the projected line count.
Accept slight growth as the honest cost of the V3.5 feature additions.
