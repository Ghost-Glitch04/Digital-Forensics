# Evidence and Anchor Discipline — Lessons Learned V3.5

## What this file is

This file teaches two paired disciplines that make captured lessons
**retrievable** by future Claude sessions:

1. **The Lesson anchor discipline** — every actionable phase-file entry
   (Bugs, Pitfalls, Design Decisions) carries a `**Lesson:**` bold line
   containing a one-sentence standalone takeaway with a specific
   citation. This is the grep target future sessions will hit; it must
   stand alone.

2. **The completeness check** — a post-drafting prompt that uses
   lightweight evidence gathered during GATHER to catch lessons the
   author would otherwise forget to write up. Grounded in the observation
   that a file or error pattern the author kept returning to, but never
   explicitly wrote up, is usually a lesson.

Read this file:
- Before authoring any Bugs, Pitfalls, or Design Decisions section in a
  phase file
- When running Check 14 (anchor consistency) and a failure appears
- When the evidence block prompts surface an entry candidate that the
  author is uncertain how to write

This file works alongside `reference/invariants.md` (which names the
Lesson anchor as invariant INV-PHASE-02) and `reference/templates.md`
(which shows the entry format). This file goes deeper on the *discipline*
— how to produce entries that actually satisfy the invariant's intent,
not just its letter.

---

## Why This Discipline Matters — The Grep-Retrieval Reality

The lessons-learned system has a specific retrieval model: future
sessions run `grep` against INDEX.md, follow source pointers to phase
file entries, and read the smallest possible context needed to extract
the lesson. The token budget for a single lookup is ~100–200 tokens.

This means when a grep hit lands on a phase file entry, the session
has to decide — in the space of about 20 surrounding lines — whether
the entry applies to the current task. The `**Lesson:**` anchor is the
designated load-bearing sentence for this decision.

Without a clean anchor, three failure modes appear:

- **The entry becomes a narrative only the author understands.** The
  context, the reasoning, the fix — all present, but distributed across
  paragraphs. A grep-hitting session reads the narrative, doesn't find
  a specific takeaway, and either skips the entry (losing the lesson)
  or reads too deep (wasting budget on a rule that may not apply).

- **The citation evaporates.** The entry says "we had a bug in the
  parser" without naming which parser, which bug, or which fix. A
  future session with a similar-shaped problem has no way to verify
  relevance.

- **The lesson falls back to convention.** If the anchor says "Write
  clean code" or "Be careful with strings," the retrieval layer is
  working but the payload is useless. Bad anchors fail silently — grep
  returns them, sessions read them, sessions learn nothing.

This discipline is built specifically against those three failure
modes. The invariant ensures the anchor exists; the discipline ensures
the anchor earns its place.

---

## The Lesson Anchor — Format and Content Standards

### Format invariant (from INV-PHASE-02)

Every actionable entry (those that will be indexed as rule, bug, pattern,
or insight) ends with a single line:

```
**Lesson:** {one-sentence takeaway that stands alone when grep-hit}
```

The bold-prefix `**Lesson:**` is the grep anchor. The sentence after
it is the payload.

### Content standards — what makes a Lesson line earn its place

The sentence after `**Lesson:**` must satisfy all three of these tests:

**Test 1: Standalone.** Read only the Lesson line in isolation, without
the entry heading, without the surrounding narrative, without the code
block. Does it still carry actionable content?

**Test 2: Specific.** Does it name a concrete thing — a file, a
function, a flag, a count, a specific error string, a test name, a
commit SHA — that a future session could recognize or search for?

**Test 3: Prescriptive or diagnostic.** Does it tell a future session
either (a) what to do or not do, or (b) what a symptom means? Vague
observations ("we learned a lot about error handling") fail this test.

A Lesson line that passes all three is retrievable. A line that fails
any is a candidate for rewrite.

### Citation patterns — what counts as specific

The "specificity" test is concrete: the Lesson line should carry at
least one of these citation patterns when the entry admits one:

| Citation type | Example |
|---|---|
| Commit SHA | `fix landed in commit a3f8d12` |
| File and line | `parser.py:147 still has the legacy path` |
| Function or method | `_updateRunningIndicator() must be called inside the .then() callback` |
| Specific count | `wpscan default mode fingerprints 571 files before attacking` |
| Specific error string | `nmap emits 'microsoft-ds' not 'smb' — service_in must match` |
| Specific test name | `test_pentest_web_9443_triggers_sslscan_suggested encoded the manual-approval flow` |
| Specific config or command flag | `add --detection-mode passive to every wpscan probe under a 60s budget` |
| Specific value or constant | `[] or None evaluates to None; use [rule.when.port_in or []] to preserve the empty list` |

**When no citation is possible:** Some entries genuinely lack a
specific citation (e.g., "our planning process produced the right
scope on the first pass"). These are typically process insights, not
bugs or design decisions. If you're writing a Bugs or Design Decisions
entry and can't produce any of the citation types above, the entry
may actually be a process insight belonging in What Went Well or What
Would Help Me Grow instead.

### Anti-patterns — Lesson lines that fail the tests

These are real patterns that appear in drafts and need rewriting.

**Anti-pattern 1: Restating the title.**
```
### 5. Parser drops rows over batch size 1000
**Lesson:** The parser drops rows over batch size 1000.
```
The Lesson line adds nothing. A grep hit on this entry returns two
copies of the same information. Rewrite to carry the *fix* or the
*recognition signal*: `**Lesson:** Batch any parser input over 1000
rows; silent truncation with no error.`

**Anti-pattern 2: Vague conclusion.**
```
**Lesson:** Be careful with date formatting.
```
No specificity, no actionable content. A future session searching for
date-formatting advice finds this and learns nothing. Rewrite with the
concrete case: `**Lesson:** Python datetime.isoformat() includes
microseconds by default; strip with .replace(microsecond=0) before
serializing to APIs that expect second precision.`

**Anti-pattern 3: Narrative sentence.**
```
**Lesson:** When we ran into the issue with the database migration,
we ended up needing to revert and re-apply with a different strategy.
```
Prose, not rule. No future session can act on this. Rewrite with the
specific trigger and action: `**Lesson:** Alembic upgrade must run
inside the Docker container; postgres hostname only resolves inside
the compose network.`

**Anti-pattern 4: Purely autobiographical.**
```
**Lesson:** I should have tested this before committing.
```
Admonishment, not institutional knowledge. A future session isn't
going to benefit from the author's self-criticism. Rewrite as the
actionable process rule: `**Lesson:** Run make check before every
commit; it catches the tool-count assertion drift in 2 seconds.`

---

## The Evidence Block — Lightweight GATHER Extension

### Purpose

The evidence block is a small set of commands the author runs during
GATHER (SKILL.md §3a Step 1) to surface signals the narrative
recollection would miss. It produces a scratch file the author consults
during and after drafting.

The block is intentionally lightweight — it's Tier A signals only from
the Sub-step 1a analysis. Heavier analysis (session log mining, tool
usage patterns) is opt-in and not part of the default flow.

### When to run the block

- Always during a full reflection (§3a Step 1)
- Always during a meta-reflection covering multiple phases (same place)
- Optional during lightweight capture (§3b) — the author's judgment on
  whether the single lesson being captured warrants the check

### The commands

Run these during GATHER and append their output to
`/tmp/evidence_{phase_id}.md`:

```bash
# Signal 1: Churn histogram — top files by commit-range touch count
# Answers: "which files did I keep returning to? Did I write up why?"
git log --pretty=format: --name-only {start_commit}..{end_commit} \
  | grep -v '^$' | sort | uniq -c | sort -rn | head -10

# Signal 2: Error-pattern frequency — most-repeated errors in session output
# Answers: "which error class did I hit multiple times? Does a single
# entry capture it, or did I solve instances without naming the class?"
grep -hE "(Error|Exception|Failed|Traceback):" {session_notes_or_logs} \
  | sed 's/.*\(Error\|Exception\|Failed\): //' \
  | awk '{print $1, $2, $3}' \
  | sort | uniq -c | sort -rn | head -5

# Signal 3: Test delta — which tests were added, removed, or flipped
# Answers: "are there new tests I should have mentioned in the narrative?
# Are there removed tests whose intent I absorbed into other tests?"
git diff --stat {start_commit}..{end_commit} -- '**/test_*.py' 'tests/*.py'
git log --pretty=format:"%h %s" {start_commit}..{end_commit} -- 'tests/'

# Signal 4: Commit-message first-word frequency (optional)
# Answers: "am I repeatedly 'fix'-ing the same thing? What was I fixing?"
git log --format=%s {start_commit}..{end_commit} \
  | awk '{print tolower($1)}' | sort | uniq -c | sort -rn
```

Adjust paths and patterns for the project being reflected on. The
commands above assume a Python-ish project with `tests/` — adapt the
test-pattern grep for other languages. The important thing is the
shape of the signal, not the exact grep.

### The scratch file format

The output lands in a plain scratch file the author consults during
and after drafting. Example shape:

```
# Evidence block — phase82_example_work
Date: 2026-04-20
Commit range: a3f8d12..f9e2b44

## Top 10 churned files
  14 parser.py
   9 tests/test_parser.py
   7 config/schema.yaml
   ...

## Top 5 error classes (from session notes)
   6 AttributeError
   4 TimeoutError
   2 KeyError
   ...

## Test delta
 tests/test_parser.py        | 47 ++++++++++++---
 tests/test_ingest.py        | 12 ++----
 tests/test_new_backend.py   | 83 +++++++++++++++++++++++++
 (3 new tests files, 1 substantially changed)

## Commit first-word frequency
   8 fix
   3 add
   2 refactor
   1 rename
```

### The scratch file is ephemeral

The evidence block is a GATHER aid, not a permanent artifact. Once the
reflection is complete and verified, `/tmp/evidence_{phase_id}.md` can
be deleted. The lessons it surfaced live in the phase file; the raw
evidence does not need to persist.

**Exception:** If the evidence surfaced a pattern that belongs in
skill_dev_log.md (e.g., "commit first-word histogram consistently
reveals rework patterns worth capturing"), preserve the scratch file
as an attachment to the skill_dev_log.md entry for that insight.
This is rare.

---

## The Completeness Check — Post-Drafting Prompt

### Purpose

After drafting the phase file, the author runs a short completeness
check that uses the evidence block to catch unwritten lessons. This is
a prove-first analog of the isolation-read discipline: isolation-read
catches *clarity* gaps in entries that exist; the completeness check
catches *existence* gaps in entries that should have been written but
weren't.

### The check

For each of the top signals from the evidence block, ask:

**For each of the top 3 churned files:**
- Is this file named in at least one entry (Bugs, DD, What Went Well,
  or What Went Badly)?
- If not — did the author touch this file repeatedly without a lesson
  worth recording, or did they skip writing the lesson up?

**For each of the top 2 repeated error classes:**
- Is this error class captured in a Bugs entry or Applied Lesson?
- If not — was each instance a different root cause (no shared
  lesson), or did the author solve them instance-by-instance without
  extracting the class?

**For test deltas:**
- Does any entry discuss the test-shape changes? If a new test file
  appeared, is its purpose captured somewhere?
- If not — was the test a mechanical addition (genuinely no lesson)
  or did the test reveal something worth naming?

Each "no" answer is either (a) a legitimate omission because there's
genuinely no lesson, or (b) a gap. The author's judgment decides which.
The check's value is forcing the decision to be conscious rather than
implicit.

### Time budget

The completeness check should take under 5 minutes. If it takes longer,
the evidence block is producing too much signal — trim the commands to
focus on the most productive signals for the author's typical work
shape.

---

## Worked Examples

### Example 1 — Refactoring a Lesson from narrative-only to anchored

**Before** (from a hypothetical draft):

```markdown
### 3. Batch insert silently dropped rows

We had an issue where the batch insert was losing data. After some
investigation it turned out to be related to the batch size. We ended
up having to split the input and process it in chunks, which worked
better. The tests had to be updated to handle the new chunking logic.
```

This entry has a title, narrative, and implicit lesson — but no
`**Lesson:**` anchor, no citation, no standalone takeaway. A grep hit
on this entry returns three sentences of context with no extractable
rule.

**After** (applying the discipline):

```markdown
### 3. Batch insert silently dropped rows over 1000

SQLAlchemy's `session.bulk_insert_mappings()` silently truncates
input to 1000 rows when the underlying connection's `executemany_mode`
is `'values'`. No error, no warning — rows 1001+ are discarded. The
fix is either chunking the input with `itertools.batched(records,
1000)` or setting `executemany_mode='values_plus_batch'` on the
connection.

**Lesson:** `bulk_insert_mappings()` silently caps at 1000 rows under
`executemany_mode='values'`; chunk inputs or switch to
`values_plus_batch` to preserve all rows.
```

The before-and-after shows three things:
1. The title gains specificity (`over 1000` is a recognition signal)
2. The body cites specific APIs and values (`session.bulk_insert_mappings()`,
   `'values'`, `itertools.batched`, `'values_plus_batch'`)
3. The Lesson line is standalone — a grep hit on it alone gives a
   future session enough to act

### Example 2 — The completeness check surfacing an unwritten lesson

**Scenario:** Phase reflection drafted. Four Bugs entries, three Design
Decisions, populated Metrics. The author thinks they're done.

**Evidence block output:**

```
## Top 10 churned files
  14 runbook/taxonomy.py
   9 tests/test_taxonomy.py
   7 config/service_taxonomy.yaml
   5 runbook/conditions.py
   ...
```

**Completeness check:**
- `taxonomy.py` — named in DD-1 and Bugs-2. Covered.
- `test_taxonomy.py` — not named in any entry. Gap candidate.
- `service_taxonomy.yaml` — named in DD-1. Covered.
- `conditions.py` — named in Bugs-2 and DD-1. Covered.

The author pauses on `test_taxonomy.py`. Reflecting: the file was
touched nine times because each alias expansion bug required adding a
regression test, and the shape of those tests stabilized after the
fourth one — a fixture-driven approach.

That's an unwritten lesson. The author adds an entry:

```markdown
### 6. Fixture-driven parametrization caught alias-expansion regressions
efficiently

Six alias-expansion bugs required six regression tests. After the
fourth, the tests converged on a fixture-driven pattern:
`@pytest.mark.parametrize("input,expected", load_fixture("alias_cases"))`.
Each bug then added a row to `tests/fixtures/alias_cases.json` rather
than a new test function. The last two bugs were each 2-line fixture
entries with zero test code changes.

**Lesson:** For families of similar regression cases (like alias
expansion), invest in a fixture-driven parametrize harness at the 4th
instance; subsequent cases become single-file data additions.
```

The evidence block didn't write the lesson — the author did. The
evidence block surfaced the *candidate* for the lesson, which the
author would otherwise have missed because the tests felt "mechanical"
in the moment.

### Example 3 — The completeness check correctly finding no gap

**Scenario:** Phase 78/79 (from Ghost's real repo — two carry-forward
items closed). Short phase, two files touched per sub-phase.

**Evidence block output (hypothetical):**

```
## Top 5 churned files
   3 static/js/app.js
   2 static/css/app.css
   1 static/index.html
   1 static/js/timeline.js

## Top 2 error classes
   0 (no errors — clean run)
```

**Completeness check:**
- `app.js` — named in What Went Well #3 ("event-driven indicator" —
  specific function `_updateRunningIndicator()` cited) and DD-1
  (placement discussion). Covered.
- `app.css` — named in What Went Well #5 (CSS var discipline).
  Covered.
- `index.html` — implicit in the Metrics table's "3 files modified"
  line. Not named in a narrative entry, but there's no lesson — just
  5 lines of HTML for the indicator markup. No gap.
- `timeline.js` — this is Phase 78's lone-line change. Named in the
  Phase 78 entries. Covered.

**Result:** No gaps. Draft is complete. The check ran in under a
minute and confirmed the reflection is done.

This is the healthy case: the check doesn't always find gaps, and
when it doesn't, that's evidence the drafting discipline was strong.
Running the check *and finding no gaps* is a positive signal about
reflection quality, not wasted effort.

---

## Integration With the Reflection Workflow

### Where the evidence block runs

SKILL.md §3a Step 1 GATHER. Either as a new sub-step or woven into the
existing sub-steps. The specific integration is Phase 4's decision; this
file provides the content.

### Where the completeness check runs

SKILL.md §3a after Step 2 DRAFT and before Step 3 UPDATE INDEX.md.
The natural flow is:

1. Draft all sections of the phase file
2. Run isolation-read discipline on each AI rule (INV-AI-02 intent)
3. Run the completeness check on Bugs / DD / What Went Well /
   What Went Badly — consult the evidence scratch file
4. If the check surfaces a gap, revise the phase file before proceeding
5. Proceed to INDEX.md updates

### The completeness check does NOT replace other reviews

It's specifically scoped to **existence gaps** — entries that should
have been written and weren't. It does not replace:

- Isolation-read (for entries that exist but aren't self-contained)
- Applied/Missed review (for the lookup feedback loop)
- Skill self-review (for `type: meta` opportunities, see Phase 3 on
  meta-note classification)

These are four distinct review disciplines, each catching a different
class of issue.

---

## Relationship to Check 14 (Anchor Consistency)

Check 14 in `reference/verify.md` is the automated counterpart to this
discipline. The check scans phase files for Bugs/DD entries and
validates that each has a `**Lesson:**` line containing at least one
citation pattern.

Check 14 catches:
- Missing anchors
- Anchors that contain only stop-word content (no citation patterns
  detected)

Check 14 does NOT catch:
- Anchors that have a citation but fail Test 1 (standalone) or
  Test 3 (prescriptive/diagnostic) — these require human judgment
- Gaps where the entry doesn't exist at all — that's the completeness
  check's job, not Check 14's

This is the typical split between automated verification and human
discipline: the check catches format-level violations; the discipline
catches judgment-level violations. Both are needed.

---

## When This Discipline Is Wrong

Three scenarios where strict anchor discipline is counterproductive:

**1. Purely narrative sections in meta-reflections.** A meta-reflection's
"Summary Judgment" section is not an actionable entry — it's prose
synthesis. Requiring a `**Lesson:**` anchor on it would distort the
section's purpose. The invariant INV-PHASE-02 applies to actionable
entries (those that will be indexed), not to all sections.

**2. Case study teaching sections.** phase81's "The real N-location
rule for tools" section is a teaching block with a descriptive heading,
not a numbered actionable entry. It doesn't need a Lesson anchor for
the same reason a meta-reflection summary doesn't — it's not the
retrieval surface for a specific indexed rule.

**3. Entries the author is actively uncertain about.** If an author
can't produce a clean Lesson line after honest effort, the entry may
be premature — the insight hasn't crystallized yet. Better to leave
the entry out, or mark it as a `CF` item for the next reflection to
revisit, than to write a bad anchor that misleads future sessions.
Bad anchors are worse than missing anchors.

In all three cases, the judgment call is: *does this content exist to
be retrieved as a specific rule, or does it serve another purpose?* If
the answer is "another purpose," the anchor discipline doesn't apply.

---

## Change Control

This discipline's thresholds and tests are informed by reflection
experience; they should evolve based on what works in practice.

- **Adjusting the citation-pattern list:** No version bump. New patterns
  (or removed patterns) are documented as drift-formalization events in
  skill_dev_log.md. Example: if "regex pattern that matched" becomes a
  recognizable citation type, it gets added to the table.
- **Changing the three content-standard tests:** Skill version bump —
  this is changing the contract for what a Lesson line must do.
- **Changing the evidence block commands:** No version bump unless the
  command *set* changes (adding Tier B signals like session log mining).
  Per-project command adaptations are expected and don't require
  documentation.
- **Changing the completeness check's signal thresholds** (e.g., top-3
  vs. top-5 churned files): No version bump; record as drift-formalization
  in skill_dev_log.md. This is a heuristic, not a contract.

The goal is discipline that's honest about its own heuristics:
documented but adjustable, with a clear record of why adjustments
happened.
