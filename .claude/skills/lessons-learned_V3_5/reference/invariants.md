# Retrieval Invariants — Lessons Learned V3.5

## What this file is

This file names the structural properties of `lessons_learned/` that **must
remain stable** for grep-based retrieval by future Claude sessions to keep
working. Everything not listed here is presentation drift that is allowed,
even expected, to evolve.

Read this file:
- Before editing the skill (any change that might affect a file format)
- When Check 13 (format drift) or Check 16 (variant conformance) fires
- When introducing a new phase-file variant (see Drift Intake Protocol,
  Sub-step 1c)
- When reviewing a PR that modifies any `lessons_learned/` file

Do **not** read this file during normal reflections. The canonical workflow
in `SKILL.md` and exact formats in `templates.md` are sufficient for
authoring. This file is the contract *underneath* those — the load-bearing
layer that must not drift.

---

## The Frame — Why Invariants vs. Presentation

The lessons-learned system has two concurrent audiences:

1. **Grep-based retrieval** by future Claude sessions running the lookup
   protocol. This is machine-consumed, pattern-matching, tolerant of
   nothing — a regex either matches or it doesn't. This audience reads
   INDEX.md rows, AI rule headings + `**When:**` lines, phase-file entry
   titles, and `**Lesson:**` anchors.

2. **Human review** by the author and reviewers. This audience reads
   phase-file narrative, section headings, tables, and code blocks. This
   audience tolerates variation and actually benefits from it — a tool
   onboarding case study and a bug-fix retrospective should not look
   identical.

The line between invariants and presentation is the line between what
audience 1 depends on and what audience 2 benefits from. Everything
audience 1 grep-hits is an invariant. Everything audience 2 reads as
narrative is presentation.

**Drift in presentation is constructive** — it lets new kinds of work
find appropriate shapes. **Drift in invariants is destructive** — it
silently breaks retrieval for every session that follows.

Check 13 (format drift) flags violations of invariants.
Check 16 (variant conformance) validates that a phase file's declared
variant uses only documented presentation patterns.

---

## Invariants by File

Each invariant has:
- **ID** — stable identifier for verify.md checks to reference
- **Statement** — what must hold
- **Validation** — grep pattern or procedure that tests it
- **Failure mode** — what breaks if this drifts
- **Source** — V3.4 `templates.md` section or `verify.md` check where
  this is already documented (this file is a pointer to truth, not
  a duplicate)

---

### Phase File Invariants

**INV-PHASE-01 — Entry heading format.**
Every actionable entry (rule, bug, pattern, insight narrative block) is
introduced by `### N. Title` (single integer) or `### N.N Title`
(section-grouped). N restarts at 1 per phase file (or per section when
sections are used) and increases monotonically.
*Validation:* `grep -oE "^### [0-9]+(\. |\.[0-9]+ )" {phase_file}`
*Failure mode:* INDEX.md source pointers (`{phase_id}:N`) no longer
resolve; Check 1 cannot match entries to rows.
*Source:* templates.md §"Phase File Entry Format".

**INV-PHASE-02 — Lesson anchor on actionable entries.**
Bugs/Pitfalls and Design Decisions entries carry a bold `**Lesson:**` line
containing a single-sentence takeaway that stands alone when grep-hit
without the surrounding narrative.
*Validation:* For each `### N. Title` heading under a Bugs or DD section,
the next 30 lines must contain `^\*\*Lesson:\*\*`.
*Failure mode:* Grep hits on INDEX.md point to entries whose takeaway
requires reading surrounding prose — retrieval cost rises from ~20 tokens
to hundreds per hit.
*Source:* templates.md §"Phase File Entry Format" (new in V3.5: enforced
by Check 14; this formalizes the existing convention).

**INV-PHASE-03 — Applied Lessons table columns.**
When Applied Lessons is present, the table has exactly three columns in
this order:
`Rule (source → heading) | Outcome | Note`
Column names are strict; column order is strict.
*Validation:* `grep -A 1 "^## Applied Lessons" {phase_file}` must show
the header row matching that exact sequence.
*Failure mode:* Downstream Missed/REGRESSED analysis queries the fixed
column positions; renaming breaks the feedback loop.
*Source:* templates.md §"Applied Lessons Table Format".

**INV-PHASE-04 — Applied Lessons source-column format.**
The source column cell contains exactly one of:
- `{ai_file}.md → "{Rule Title}"` (AI file lookup)
- `{memory_file} (memory)` (memory-file lookup)
- `NEW (this phase)` (rule discovered in this phase)
- `INDEX → {tag}, {tag} — {description}` (INDEX-tag-based, observed in
  phase78+)
*Validation:* Each non-header row's first cell matches one of these four
patterns.
*Failure mode:* Automated rollup of "which rules have been consulted
across phases" breaks on unparseable source cells.
*Source:* templates.md §"Applied Lessons Table Format" (V3.5 adds the
INDEX-tag variant — it was observed in real use from phase78 onward).

**INV-PHASE-05 — Outcome vocabulary.**
The Outcome column cell contains exactly one of the 9 values:
`applied | applied proactively | in place | N/A | missed | REGRESSED |
contradicted | revised | discovered`.
Capitalization is significant: `REGRESSED` is all-caps; the others are
lowercase.
*Validation:* Each Outcome cell matches the vocabulary set.
*Failure mode:* Metrics rollups ("how many REGRESSED per phase?") depend
on exact match. New outcome values require a skill version bump.
*Source:* templates.md §"Applied Lessons Table Format" → Outcome Vocabulary.

**INV-PHASE-06 — Missed table columns.**
When the Missed table is present (split Applied/Missed format), columns
are exactly:
`Rule (source → heading) | Why missed | Consequence`
Column names and order are strict. The source column uses the same format
as INV-PHASE-04.
*Validation:* `grep -A 1 "^## Missed" {phase_file}` header match.
*Failure mode:* The split Applied/Missed feedback loop depends on Missed
being distinguishable from Applied at the column level.
*Source:* templates.md §"Missed Table (Applied Lessons split)".

**INV-PHASE-07 — Carry-Forward ID format.**
Open items use `CF-N` or `CF-{phase_id_short}-N` identifiers that are
stable across phases. When an item is resolved, the resolving phase's
table entry reads:
`| {CF-ID} | RESOLVED in {phase_id}: {brief note} | ... |`
*Validation:* CF-IDs match `^CF-[0-9]+(-[0-9]+)?$`; resolution entries
contain literal `RESOLVED in`.
*Failure mode:* Carry-forward tracking across phases (Check 7) fails.
*Source:* templates.md §"Carry-Forward Items Table Format".
*Note:* The CF-table column set beyond the ID column (e.g., `Priority`
vs. `Owner | Due`) is presentation, not invariant — see "Ambiguity 1"
in the commentary for this sub-step.

**INV-PHASE-08 — Phase file `**Format:**` declaration.**
Every phase file opens with `**Format:** {variant-name}` on its own line
within the header block (typically on the third or fourth line, after the
H1 title and Scope). The variant name is one of the variants documented
in `templates.md` or a proposed-variant name flagged by the Drift Intake
Protocol.
*Validation:* `grep -m1 "^\*\*Format:\*\*" {phase_file}` returns exactly
one match within the first 15 lines.
*Failure mode:* Check 16 (variant conformance) cannot route validation
to the correct schema; authors default to assuming canonical when they
are writing something else.
*Source:* New in V3.5. Introduced by the Drift Intake Protocol (Sub-step
1c). Retroactive bootstrap: existing phase files without this line are
assumed `Format: canonical` until edited.

**INV-PHASE-09 — Superseded-entry markers.**
When a rule is superseded, both the superseded and the superseding side
carry bidirectional markers:
- Superseded rule: `**Superseded by:** {file}.md → "{New Rule Title}"` +
  `**Supersession reason:** {corrected | refined | narrowed | split}`
- Superseding rule: `**Supersedes:** {file}.md → "{Old Rule Title}"`
Supersession reason vocabulary is strict and requires a skill version
bump to extend.
*Validation:* Grep for `^\*\*Superseded by:\*\*` finds mutual
`^\*\*Supersedes:\*\*` pointers (Check 10, Check 11).
*Failure mode:* Retrieval hits on superseded rules don't redirect;
stale guidance gets applied.
*Source:* templates.md §"Superseded Rules Format".

---

### INDEX.md Invariants

**INV-INDEX-01 — Row structure.**
Every data row in Active, Foundation, and Reference tier tables is
pipe-delimited with exactly 4 content columns:
`| tags | description | source | type |`
Header rows, separator rows (`| --- | --- | --- | --- |`), and blank
lines are permitted between rows but not within a row.
*Validation:* Each non-header, non-separator row under a tier heading
has exactly 4 `|`-delimited fields.
*Failure mode:* Grep-based lookup (the primary retrieval mechanism)
produces malformed results on rows that don't parse.
*Source:* templates.md §"INDEX.md Row Format".

**INV-INDEX-02 — Tag syntax.**
Tags in the tags column are lowercase, comma-separated, with the primary
tag first. Multi-word tags use hyphens (no spaces within a tag). No
quoting or bracketing.
*Validation:* The tags cell matches `^[a-z0-9-]+(, [a-z0-9-]+)*$`.
*Failure mode:* `grep -i "tag"` queries in the lookup protocol miss
entries with mismatched tag syntax.
*Source:* templates.md §"INDEX.md Row Format" → Tags column rule.

**INV-INDEX-03 — Description length.**
Description cells are under 120 characters. The key concept is
frontloaded — a grep hit that shows only the first 80 characters must
still be useful.
*Validation:* Each description cell's character count < 120.
*Failure mode:* Terminal-width grep truncation cuts off key concepts;
lookup becomes ambiguous.
*Source:* templates.md §"INDEX.md Row Format" → Description column rule.

**INV-INDEX-04 — Source pointer form.**
The source column matches one of the documented source-pointer forms in
`templates.md` §"Source format inside AI files" — these same 9 forms
apply to INDEX rows. Canonical is `{phase_id}:{N}`.
*Validation:* Check 13 format-drift regex (already implemented).
*Failure mode:* Check 1 (phase file → INDEX row) and Check 2 (AI file
source → phase entry) cannot resolve pointers that don't match documented
forms.
*Source:* templates.md §"Source format inside AI files".

**INV-INDEX-05 — Type vocabulary.**
The type column cell is exactly one of: `rule | bug | pattern | insight`.
Extending this vocabulary requires a skill version bump.
*Validation:* Each type cell matches the vocabulary set.
*Failure mode:* Check 3 (every rule/bug/pattern has an AI file entry)
cannot partition rows by type.
*Source:* templates.md §"INDEX.md Row Format" → Type vocabulary.

**INV-INDEX-06 — Three-tier structure.**
INDEX.md contains exactly three tier sections, in this order:
`## Active Index`, `## Foundation Index`, `## Reference Index`.
Each entry lives in exactly one tier at any time. Additional tiers
require a skill version bump.
*Validation:* `grep -c "^## (Active|Foundation|Reference) Index"
{INDEX.md}` returns 3.
*Failure mode:* Tier-scoped queries (recent-only vs. stable-only) break.
*Source:* SKILL.md §4d "Which INDEX.md tier?".

**INV-INDEX-07 — Tag vocabulary block.**
A "Tag Vocabulary" block near the top of INDEX.md lists the project's
canonical tags. New tags appearing in rows are expected to be added here
during the reflection that introduces them.
*Validation:* `grep -B 1 -A 100 "^## Tag Vocabulary" {INDEX.md}` returns
a non-empty list.
*Failure mode:* Tag-sprawl without a canonical reference causes synonym
drift (auth vs. authentication vs. authn), degrading grep precision.
*Source:* bootstrap.md §"Step 3 — Seed INDEX.md".

---

### AI File Invariants

**INV-AI-01 — Rule heading format.**
Rule headings are `### Short imperative title` (plain H3, canonical).
Legacy exception: `### Rule N: Title` is accepted in `wpscan.md` only
(12 rules in the current repo). New AI files must use the canonical
form.
*Validation:* Check 13 drift detection — canonical `^### [A-Z]` or
wpscan-legacy `^### Rule [0-9]+:`.
*Failure mode:* Mixed rule-heading forms across the same file break
Check 4 (rule count) and make table-of-contents greps inconsistent.
*Source:* templates.md §"AI File Rule Format" → Heading format.

**INV-AI-02 — Mandatory rule lines.**
Every rule body contains `**When:**` and `**Rule:**` lines. These two
are the isolation-read skeleton — a grep hit on the heading should be
able to locate both within the next 20 lines.
*Validation:* For each `### Title`, the next 20 lines contain
`^\*\*When:\*\*` AND `^\*\*Rule:\*\*`.
*Failure mode:* Isolation-read discipline (SKILL.md §3a Step 4,
isolation-read sub-step) cannot run; rules are useless at cold-start.
*Source:* templates.md §"AI File Rule Format".

**INV-AI-03 — Optional rule lines with strict format when present.**
The following lines are optional but when present must match their exact
bold-prefix format:
- `**Not when:**` (single line, one boundary condition)
- `**Why:**` (single line or short paragraph)
- `**Companions:**` (comma-separated `{file}.md → "{Rule Title}"` refs)
*Validation:* If any of `Not when`, `Why`, `Companions` appears, it uses
the bold prefix exactly.
*Failure mode:* Companion-link resolution (Check 6b) fails; isolation-read
doesn't identify Not-when conditions.
*Source:* templates.md §"AI File Rule Format".

**INV-AI-04 — Source line format.**
Every rule ends with a source line: `*Source: {pointer}*` in italics,
matching one of the 9 documented source-pointer variants.
*Validation:* `grep -oE "^\*Source: .+\*$" {file}` — each rule has
exactly one.
*Failure mode:* Check 2 (AI source resolves to real phase entry) cannot
run; orphaned rules accumulate silently.
*Source:* templates.md §"Source format inside AI files".

**INV-AI-05 — Tag comment format when present.**
When an AI rule has a `<!-- tags: -->` HTML comment, it appears
immediately after the `### Title` line on its own line, contains
lowercase comma-separated tags with no quoting, and follows the syntax:
`<!-- tags: tag1, tag2, tag3 -->`.
*Validation:* If `<!--\s*tags:` appears, it matches the single-line form
with valid tag syntax.
*Failure mode:* Malformed tag comments break tag-based sub-grep inside
AI files.
*Source:* templates.md §"AI File Rule Format" (format); V3.5 presence-
tolerance clarified — 7 of 313 current rules (2.2%) have tag comments,
concentrated in recent rules from metasploit.md, docker.md, process.md.
**Presence is NOT retroactively required.** New rules authored from V3.5
forward are encouraged to include the tag comment; older rules without
it do not trigger Check 13.

**INV-AI-06 — Companion link mutuality.**
If rule A lists rule B as a companion, rule B must list rule A. One-sided
companion links are invalid.
*Validation:* Check 6b (documented in verify.md).
*Failure mode:* Companion-chain traversal during lookup produces
inconsistent results depending on direction of first grep.
*Source:* templates.md §"Companions" guidance.

**INV-AI-07 — Superseded rule markers (AI side).**
Superseded rules retain `**Superseded by:**` + `**Supersession reason:**`
markers; the superseding rule carries `**Supersedes:**`. Mutual.
*Validation:* Check 10 and Check 11.
*Failure mode:* Same as INV-PHASE-09 — stale rules continue to be
retrieved as live.
*Source:* templates.md §"Superseded Rules Format".

**INV-AI-08 — Cross-reference format in See Also sections.**
Cross-references to other files use `- See: {file}.md → "{Rule Title}"`
exactly. The primary file owns the full rule body; secondary files
carry only the See reference.
*Validation:* Check 6.
*Failure mode:* Duplicate full rules across files create conflicting
sources of truth; See format drift breaks Check 6 resolution.
*Source:* SKILL.md §4c "Which AI subject file?" → Cross-cutting rules.

---

### _overview.md Invariants

**INV-OVERVIEW-01 — Row structure.**
Each AI file has exactly one row with format:
`| [{file}.md]({file}.md) | {rule_count} | {keywords} |`
Three columns. `_overview.md` does not have a row for itself.
*Validation:* Parse the "AI Subject Files" table; one row per file in
`lessons_learned/ai/` excluding `_overview.md`.
*Failure mode:* Lookup-protocol step 2 (`grep -i "keyword"
lessons_learned/ai/_overview.md`) produces malformed results.
*Source:* bootstrap.md §"Step 4 — Seed ai/_overview.md".

**INV-OVERVIEW-02 — Rule count exclusion of superseded.**
The rule_count field excludes rules marked `**Superseded by:**`.
Superseded rules are not actionable recall and must not inflate the count.
*Validation:* Check 4 (already implemented — subtracts superseded count).
*Failure mode:* File-size thresholds (30+ rules → split) trigger
incorrectly on files with many legacy superseded rules.
*Source:* templates.md §"Superseded Rules Format".

---

### Cross-File Invariants

**INV-X-01 — Phase entry → INDEX row mapping.**
Every actionable phase-file entry (one that represents a rule, bug,
pattern, or insight) has exactly one INDEX.md row pointing to it via
`{phase_id}:N` or an equivalent documented pointer form.
*Validation:* Check 1.
*Failure mode:* Lessons captured in phase files but not indexed are
invisible to the lookup protocol — they exist but are unreachable.
*Source:* verify.md Check 1.

**INV-X-02 — INDEX row → AI rule mapping for rule/bug/pattern.**
Every INDEX row of type `rule`, `bug`, or `pattern` has an AI file rule
whose `*Source:*` pointer matches. Type `insight` is exempt — insights
may live in phase file + INDEX only.
*Validation:* Check 3.
*Failure mode:* Rules indexed but not surfaced in AI files break the
structured-recall layer.
*Source:* verify.md Check 3.

**INV-X-03 — AI source → phase entry resolution.**
Every AI rule's `*Source:*` pointer resolves to a real phase file with
a real entry at the specified number.
*Validation:* Check 2.
*Failure mode:* Orphaned AI rules cite phantom sources; the narrative
source of truth is broken.
*Source:* verify.md Check 2.

**INV-X-04 — Carry-forward continuity.**
A CF item opened in phase N remains in subsequent phases' Carry-Forward
tables (or their equivalent) until resolved or explicitly dropped. A CF
that disappears without a `RESOLVED in ...` entry is lost debt.
*Validation:* Check 7.
*Failure mode:* Silent carry-forward loss; institutional debt tracking
fails.
*Source:* verify.md Check 7.

---

## What Is Explicitly NOT an Invariant

Drift in the following areas is allowed and expected. Check 13 must not
fire on these.

### Phase files
- Section names ("Bugs and Pitfalls" vs. "Bugs" vs. "Pitfalls" vs.
  "Issues" vs. "Challenges" — all valid)
- Section ordering within the phase file body
- Presence or absence of optional sections (What Went Badly, Metrics,
  Tooling Wishlist, etc. — omit when empty, don't pad)
- Section heading depth (##, ###, or deeper)
- Narrative style: prose, bulleted, numbered, case-study, table-first
- Whether entries are introduced with `### N. Title` numbered or
  `## {Section Name}` descriptive — *only the actionable entries that
  need INDEX source pointers must follow INV-PHASE-01; purely
  narrative sections may use descriptive headings*
- Tooling wishlist entry IDs (`TW-N`, `TW-{phase}-N`, unnumbered) —
  the ID format is presentation; the meta-note sub-type (introduced in
  Sub-step 2 Phase 3) is invariant

### INDEX.md
- Ordering of rows within a tier (usually chronological or by tag but
  not strictly required)
- Whether tiers use a single table or sub-grouped sub-headings within
- Tag Vocabulary block formatting (flat list vs. grouped by category)

### AI files
- Order of rules within a file
- Whether rules are grouped under `## Section` sub-headings or flat
- Length of rule bodies (5 lines or 50 lines — both valid)
- Code block language tags
- Presence/absence of code blocks (not every rule needs one)

### _overview.md
- Whether the file has a prose header or only the table
- "How to use" section phrasing

---

## Pointers to Documented Format Variants

For convenience, here are the reference sections in `templates.md` and
other skill files where the documented-variant sets live. When a regex or
check needs the authoritative list, it lives in these sections:

| What | Where |
|------|-------|
| 9 source-pointer form variants (AI file + INDEX shared) | templates.md §"Source format inside AI files" |
| 9 Applied Lessons outcome vocabulary values | templates.md §"Applied Lessons Table Format" → Outcome vocabulary |
| 4 type vocabulary values (INDEX rows) | templates.md §"INDEX.md Row Format" → Type vocabulary |
| 4 supersession reason vocabulary values | templates.md §"Superseded Rules Format" |
| 3 INDEX tiers | SKILL.md §4d |
| Phase file variant names (3 documented in V3.5 Sub-step 1b: Canonical, Meta-reflection-with-Wishlist, Case-study) | templates.md §"Phase File Variants" (to be added in Sub-step 1b) |

Extending any of these closed sets requires a skill version bump and an
entry in `lessons_learned/meta/skill_dev_log.md` recording the rationale.

---

## Relationship to Drift Intake Protocol (Sub-step 1c)

The Drift Intake Protocol handles **new phase-file variants** — shapes
of reflection that don't fit any currently documented variant. It does
not authorize drift in retrieval invariants.

A new variant can:
- Introduce new section names, ordering, and narrative style (presentation)
- Omit optional sections that don't apply (e.g., a case-study variant
  with no Bugs section)
- Use descriptive headings for purely narrative parts

A new variant cannot:
- Change column names in Applied Lessons / Missed / INDEX rows
- Invent new outcome vocabulary values
- Use unindexed entry heading formats for actionable entries
- Skip `**Lesson:**` anchors on Bugs/DD entries
- Skip the `**Format:**` declaration line

If a reflection genuinely needs one of those changes, it's not a new
variant — it's a V3.6 proposal. Route it through the skill development
log.

---

## Change Control

Changes to this file follow these rules:

1. **Adding an invariant** (making something previously-drifting now
   strict) requires:
   - Retrofitting existing files to comply, OR
   - An explicit grandfathering note (like INV-AI-05's 2.2% current
     compliance note) with a migration path
   - A skill version bump
   - An entry in `skill_dev_log.md`

2. **Relaxing an invariant** (making something previously-strict now
   drifting) requires:
   - Evidence that the invariant is redundant or over-constrained
   - Confirmation that retrieval still works with the relaxation
   - A skill version bump
   - An entry in `skill_dev_log.md`

3. **Modifying an invariant's validation pattern** (fixing a broken
   regex) does not require a version bump if the semantic intent is
   unchanged. Record the fix in skill_dev_log.md as a drift-formalization
   event.

This file is the contract. Breaking it silently is how skills become
untrustworthy — the scripts and workflows that depend on it have no way
to know the rules have changed.
