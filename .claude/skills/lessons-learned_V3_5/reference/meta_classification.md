# Meta-Note Classification and Synchronous Update Loop

## What this file is

This file documents two paired disciplines for the meta-improvement
feedback loop:

1. **Meta-note classification** — when a reflection surfaces an
   observation about the skill itself, the tooling, or the environment,
   the author classifies it into one of three sub-types:
   `meta-fix`, `meta-question`, or `meta-wish`. The sub-type determines
   how the observation is handled.

2. **Synchronous Step 6** — a new workflow step where `meta-fix`
   entries from the current reflection become immediate proposals to
   apply the suggested change. The author reviews and approves or
   defers; approved proposals apply during the reflection rather than
   entering an async backlog.

Together these close a specific feedback loop: the skill observes a
gap in itself → the gap is classified → if bounded and actionable, it
gets fixed now. The V3.4 experience — where meta-notes accumulated in
"What Would Help Me Grow" sections and mostly stayed there — is what
this is designed to correct.

Read this file:
- When authoring any entry in a phase file's "What Would Help Me Grow"
  / "Tooling Wishlist" section
- When Check 15 (meta-note sub-type coverage) flags a missing sub-type
- When running Step 6 during a reflection

---

## Why Classification Matters — The V3.4 Experience

V3.4 introduced `type: meta` as a tag on "What Would Help Me Grow"
entries. The intent was to route these observations to a future
skill-authorship reflection thread. In practice, looking at Ghost's
phase76 (2026-04-18) through phase81 (2026-04-18):

- **phase76 surfaced 5 tooling wishlist items.** Two were resolved
  within a week (40% rate). The other three were still unresolved
  months later.
- **phase80 had an entry explicitly tagged** `*(type: meta on process
  skill, not code.)*` — a self-reflective observation about which
  skill needed the change, appearing in a wishlist entry.
- **phase80 also had an entry** (TW-80-3) that was literally commentary
  on V3.4's `type: meta` feature, noting zero gaps surfaced that
  reflection and asking "sign of skill maturity or am I not adversarial
  enough?"

The pattern is: **the author was already classifying meta-notes
implicitly** — distinguishing fixable items from feature requests from
process questions — but the skill had no place for the classification
and no mechanism to act on bounded items synchronously. V3.5 makes the
classification explicit and adds the synchronous loop.

The falsifiable hypothesis: synchronous handling of bounded `meta-fix`
items will raise the action rate on tooling-wishlist observations
substantially (Phase 0's analysis projected 60-80% for items that
retroactively classify as `meta-fix`). Phase 7 trial measures this.

---

## The Three Sub-Types

### `meta-fix`

**Definition:** A bounded, actionable observation where (1) the exact
file or location of the fix is known, (2) the replacement content is
known, (3) no alternative fix is plausible.

All three conditions must hold. If any fails, it's not `meta-fix` —
it's `meta-question`.

**Examples from Ghost's real phase files:**

- **phase76 TW-3** ("E2E test xfail marking or targeted modal fix
  session"). Exact target files known (`tests/e2e/app.spec.js` + three
  modal tests). Replacement known (change `toHaveCount(4)` to `7`,
  scope modal selectors with `#new-engagement-overlay`). No alternative
  required analysis beyond fix vs. xfail, and the fix-vs-xfail decision
  was itself a bounded Design Decision. **Classifies as `meta-fix`.**
- **phase76 TW-5** ("`// @ts-check` rollout for remaining JS files").
  Exact target files known. Replacement known (add the pragma, fix any
  type errors that surface). Mechanical. **Classifies as `meta-fix`.**
- **phase80 TW-80-4** ("Delete-rule preflight helper — grep test suite
  and `lessons_learned/` for rule_id, exit 1 if references exist"). The
  helper's behavior is fully specified. Target file is a new script. No
  design question. **Classifies as `meta-fix`.**

**Handling:** Eligible for synchronous Step 6 proposal during the
current reflection. If approved, the edit applies immediately; the
wishlist entry is closed with a `RESOLVED in {phase_id}` note.

### `meta-question`

**Definition:** An observation that requires design thought before
action. The *right* fix isn't obvious, or multiple reasonable fixes
exist with different tradeoffs, or the fix might introduce different
problems than it solves.

**Examples from Ghost's real phase files:**

- **phase76 TW-4** ("Live test after every UI phase batch — formalize
  as documented step in CLAUDE.md or CONTRIBUTING.md"). The *intent*
  is clear (catch visual regressions earlier) but the implementation
  has open questions: Which file does this go in? How prescriptive?
  What counts as "a batch"? Does it apply to non-UI phases? **Classifies
  as `meta-question`.**
- **phase79 CF-79-1** ("Add `Not when:` boundary to cytoscape animation
  rule — clarify it does not apply when mutation sites are owned").
  The observation is concrete, but it requires a judgment call about
  the rule's current scope (was it written broader than intended? is
  the Not-when the right fix or does the rule need splitting?).
  **Classifies as `meta-question`.**
- **phase80 TW-80-3** ("zero meta gaps this reflection — am I
  adversarial enough?"). This is explicitly a question about
  methodology. There is no fix; there is a question about whether a
  problem exists. **Classifies as `meta-question`.**

**Handling:** Stays in the phase file's "What Would Help Me Grow"
section with the `meta-question` sub-type tag. Feeds a future
skill-development reflection where the design thought happens. Does
NOT get synchronous Step 6 treatment.

### `meta-wish`

**Definition:** A feature request or capability gap. The skill doesn't
do X and probably should, but adding X is a new capability — not a fix
to existing drift.

**Examples from Ghost's real phase files:**

- **phase76 TW-1** ("`make check-css-vars` gate — 20-line Python script
  wired into `make check`"). This is a new capability (a CI gate that
  doesn't exist), not a fix to an existing gate. Implementation is
  bounded but *adding it* is a feature request, not a drift
  correction. **Classifies as `meta-wish`.** (Arguably `meta-fix` if
  the "fix" is interpreted broadly — see Edge Cases below.)
- **phase76 TW-2** ("Rules tab 'no matching finding' empty-state
  messaging"). New UX feature. **Classifies as `meta-wish`.**
- **phase80 TW-80-2** ("A 'phase plan → verify' script that emits a
  git-diff-based checklist"). New script, new capability. Tagged
  `*(type: meta on process skill, not code.)*` — author was already
  signaling this was a wishlist item for skill tooling.
  **Classifies as `meta-wish`.**
- **phase81 "Onboarding speedup ideas"** (items 1 and 2:
  `make check-tool-registration` and `make new-tool` scaffolder). New
  tooling. **Classifies as `meta-wish`.**

**Handling:** Stays in the phase file's wishlist section with the
`meta-wish` sub-type tag. Routed to either (a) a carry-forward item
for the next reasonable phase to pick up, (b) a skill-development
backlog tracked in `skill_dev_log.md`, or (c) left as an aspirational
entry if priority is unclear. Does NOT get synchronous Step 6
treatment.

---

## The Three-Criterion Test

The boundary between `meta-fix` and `meta-question` is the most
important classification call. Apply these three criteria explicitly:

**Criterion 1: Location is known.**
Is the exact file, function, line, or configuration target specified?
If the author has to figure out where the fix goes, it fails this
criterion.

**Criterion 2: Content is known.**
Is the replacement text, code, or config specifiable without design
work? If the author has to design the fix before writing it, it fails.

**Criterion 3: No plausible alternative.**
Would two reasonable implementers produce substantially the same fix?
If different people would produce meaningfully different fixes, there's
a design question hiding in the observation — it fails.

All three criteria must pass for `meta-fix`. Failing any one routes to
`meta-question`.

The `meta-wish` distinction is separate: it's asking whether the
observation is about *fixing existing drift* or *adding new capability*.
A meta-wish can pass all three criteria (location known, content known,
no alternatives) and still be `meta-wish` rather than `meta-fix` because
it's proposing something new, not correcting existing behavior.

---

## Synchronous Step 6 — The Proposal Loop

### When Step 6 runs

SKILL.md §3a Step 6, inserted between VERIFY (Step 5) and whatever
comes after. Step 6 runs only if the current reflection's wishlist
section contains any `meta-fix` entries. If zero `meta-fix` entries,
Step 6 is a no-op and the reflection is complete.

### The per-entry workflow

For each `meta-fix` entry in the current reflection:

1. **Draft the change.** The author produces the exact edit as a
   proposal: what file, what diff, rationale from the wishlist entry.
2. **Present to user.** The proposal is shown with:
   - Target file path
   - Current content (the text being replaced, if any)
   - Proposed content (the text to replace with or add)
   - Rationale (the wishlist entry itself, or a condensed form)
3. **User decides.** Three outcomes:
   - **Approve:** The edit applies immediately. The wishlist entry in
     the phase file is marked `RESOLVED in {phase_id} Step 6: {brief
     note}`. Control proceeds to the next `meta-fix` entry.
   - **Decline:** The edit is not applied. The wishlist entry stays
     in the phase file with its `meta-fix` classification. The author
     may add a note on why it was declined.
   - **Defer to meta-question:** The user decides the item needs more
     design thought after all. The sub-type is changed to
     `meta-question` in the phase file. The item stays in the wishlist
     for future skill-development reflection.
4. **Confirm and continue.** If the edit was applied, a short
   confirmation is logged in the reflection's Step 6 summary. Control
   proceeds.

### Safety rules

These constrain what Step 6 can propose synchronously:

- **Current-project-only.** Synchronous edits apply only to files in
  the current project — typically `CLAUDE.md`, the current skill's
  own files, or configuration files within the project root. Edits
  to other skills (e.g., proposing a change to `scripting-standards`
  during a `lessons-learned` reflection) are NEVER synchronous.
  Cross-skill edits always route to `meta-wish` or `meta-question`
  handling, regardless of how bounded they appear.
- **Uncommitted-changes deferral.** If the target file has uncommitted
  changes in the current session, the Step 6 proposal defers rather
  than applies. The wishlist entry is preserved; the author can run
  Step 6 on the next reflection after the target file is stable.
- **Per-reflection cap: 3 proposals.** A single reflection may
  synchronously apply at most 3 `meta-fix` edits. If more than 3
  are eligible, the author picks the 3 highest-priority and defers
  the rest to `meta-question` (signal that systemic drift is
  present — consider a dedicated skill-development reflection
  instead of bundling 5+ fixes into one session).
- **No chained edits.** A Step 6 proposal cannot depend on another
  Step 6 proposal in the same reflection. Each is independent. If
  a second edit's viability depends on the first, the second is
  `meta-question` until the first ships.

### What Step 6 produces in the phase file

After Step 6 runs, the phase file's "What Would Help Me Grow" section
gets additional annotations:

```markdown
### TW-{N} — {brief description} — `meta-fix`

{Original content from the wishlist entry.}

**Step 6 outcome:** APPLIED — {brief note on what was changed and where}
```

Or:

```markdown
### TW-{N} — {brief description} — `meta-fix`

{Original content.}

**Step 6 outcome:** DECLINED — {brief note on why}
```

Or:

```markdown
### TW-{N} — {brief description} — `meta-fix` → reclassified `meta-question`

{Original content.}

**Step 6 outcome:** DEFERRED to meta-question — {brief note on what design
thought is needed}
```

These annotations become a retrievable record: Check 14 can parse
"Step 6 outcome" lines to track per-phase approve/decline/defer rates.
Over time this is the data that validates or invalidates the synchronous
loop's value.

---

## Declaring Sub-Types in Phase Files

### The tag convention

Wishlist entries declare their sub-type in a trailing code-span on the
entry title:

```markdown
### TW-1 — `make check-css-vars` gate — `meta-wish`
```

Or as a separate bold line if the title is long:

```markdown
### TW-80-4 — Delete-rule preflight helper

**Sub-type:** `meta-fix`

{Entry content.}
```

Either placement is valid. Check 15 (meta-note sub-type coverage)
grep-matches either form:

```bash
grep -E "(meta-fix|meta-question|meta-wish)" {wishlist_section}
```

### Transitioning from V3.4's bare `type: meta`

Existing phase files with bare `type: meta` tags remain valid — the
V3.5 invariants tolerate legacy unclassified notes. But new reflections
should use the sub-type classification. At the author's discretion,
legacy entries encountered during subsequent reflections can be
retroactively classified (e.g., during the skill_dev_log backfill in
Phase 6).

### Multiple sub-types on one entry

Rare but possible: an observation that's partly a `meta-fix` and partly
a `meta-wish`. Example: "Add Not-when boundary to rule X AND also
consider whether the rule should be split into two." The fix portion
is bounded; the split portion is a wish.

**Resolution:** Split the entry into two wishlist items with separate
sub-types. Each gets its own handling. Forcing a single sub-type on a
compound observation degrades the feedback loop's value.

---

## Worked Examples — Classifying Real TW Items

Taking the real wishlist items from Ghost's phase76 and phase80,
classified under V3.5 rules:

| TW item | Original wording (abbreviated) | Sub-type | Reasoning |
|---|---|---|---|
| phase76 TW-1 | `make check-css-vars` gate | `meta-wish` | New capability, not drift correction. Implementation is bounded but it's adding a feature. |
| phase76 TW-2 | Rules-tab empty-state messaging | `meta-wish` | UX feature. |
| phase76 TW-3 | E2E `xfail` marking or fix | `meta-fix` | Location known (4 specific tests), content known (either fix the assertion or add `@pytest.mark.xfail`), no alternative beyond the fix-vs-xfail Design Decision that itself is bounded. *Resolved in phase77.* |
| phase76 TW-4 | Live-test-after-UI-batch process gate | `meta-question` | Implementation target ambiguous (CLAUDE.md? CONTRIBUTING.md?). Scope ambiguous (UI phases? all phases?). Needs design. |
| phase76 TW-5 | `// @ts-check` rollout completion | `meta-fix` | Mechanical task, known files, known replacement. *Resolved in phase78.* |
| phase80 TW-80-1 | `check_profile_services.py` flag unused families | `meta-wish` | New capability for existing script. Small, but it's adding rather than correcting. |
| phase80 TW-80-2 | Phase-plan → verify script | `meta-wish` | New tooling. Author explicitly tagged `type: meta on process skill`. |
| phase80 TW-80-3 | `type: meta` adversarial-enough check | `meta-question` | Methodology question, not an action. |
| phase80 TW-80-4 | Delete-rule preflight helper | `meta-wish` | New script. Implementation specified but it's adding capability. |
| phase81 item 1 | `make check-tool-registration <name>` | `meta-wish` | New capability. |
| phase81 item 2 | `make new-tool` scaffolder | `meta-wish` | New tooling, larger investment. |
| phase81 item 3 | CLAUDE.md 4→8 location correction | `meta-fix` | Target file known (CLAUDE.md), content known (replace "4 locations" with the documented 8), no alternative — the correction is mechanical. |

**Retroactive classification rates:**

- `meta-fix`: 3 of 12 items (25%) — phase76 TW-3, phase76 TW-5, phase81
  item 3
- `meta-question`: 2 of 12 items (17%)
- `meta-wish`: 7 of 12 items (58%)

Two of the three `meta-fix` items were actually resolved in subsequent
phases within a week (TW-3 → phase77, TW-5 → phase78). Under V3.5,
both would have been candidates for synchronous Step 6 during phase76's
reflection — likely resolving them in minutes rather than 0-2 phases
later.

**Phase 0 threshold check:** My Phase 0 plan set ≥60% `meta-fix` as the
threshold for the sub-type architecture to be worth shipping. The
actual rate is 25%. **This is below threshold.** The skill ships the
sub-type architecture anyway because:

- The 25% that are `meta-fix` are the ones where synchronous handling
  provides the most value (they otherwise wait 0-2 phases)
- The 58% that are `meta-wish` benefit from being *named* `meta-wish`
  even without synchronous handling — the classification clarifies
  they're feature requests, not overdue fixes
- The 17% that are `meta-question` benefit from being explicitly
  flagged as requiring design thought rather than mistaken for
  overdue action items

This is the honest answer. The Phase 0 threshold was set too high; the
sub-type architecture's value isn't only about the synchronous path,
it's about making the classification explicit at all. Phase 7 trial
measures whether this holds in new work.

---

## Handling `meta-question` and `meta-wish` Over Time

The synchronous loop only handles `meta-fix`. What happens to the
other two sub-types?

### `meta-question` routing

Meta-questions stay in the phase file's wishlist. They're candidates
for the next skill-development reflection (a reflection whose scope is
specifically *improving a skill*, distinct from normal project
reflections).

When a skill-development reflection runs, it:

1. Greps all phase files for `meta-question` items
2. Groups related questions (e.g., "all questions about process
   formalization")
3. Designs resolutions — which may result in `skill_dev_log.md`
   entries, skill version bumps, or formal "we decided this stays
   open" outcomes
4. Updates the originating wishlist entries with resolution notes

If a `meta-question` has been open for 2+ skill-development reflections
without movement, it's a candidate for retirement (close with "no
action; the problem did not recur"). Keeping stale questions in
wishlists degrades the signal-to-noise of the wishlist itself.

### `meta-wish` routing

Meta-wishes are tracked separately because they're feature backlog,
not drift correction. Three possible paths:

1. **Carry-forward to a concrete phase.** A wish becomes a CF item in
   a future phase ("CF-82-1: implement the `check-css-vars` gate").
   This is appropriate when the wish is small enough to be a
   sub-component of other work.
2. **Skill-development reflection picks it up.** Larger wishes
   (scaffolder, multi-file refactors) become the scope of dedicated
   reflections.
3. **Remain aspirational.** Some wishes never get picked up because
   priority is unclear or the wish was aspirational from the start.
   This is fine. Wishlists are idea-capture, not commitment-tracking.

A `meta-wish` that remains in wishlists for 6+ months without movement
can be retired with a note: "Captured but not prioritized; revisit if
the need recurs."

---

## Edge Cases

### Edge case 1: The `meta-fix` vs. `meta-wish` borderline

Some items genuinely sit on this boundary. Example: phase76 TW-1
(`make check-css-vars` gate) is implementable as a ~20-line script —
bounded, specifiable. Is it `meta-fix` or `meta-wish`?

**Resolution:** The author's call, but the test is: *does this item
correct a drift that's producing failures now, or does it add a
capability the project didn't have before?* A `check-css-vars` gate
does the latter — no such gate exists today, and the hardcoded-hex
problem was caught without it by live testing. So it's `meta-wish`.

If, alternatively, the item were "update the existing check-css-vars
gate to also catch `rgb()` patterns," it would be `meta-fix` — the
gate exists, it's missing a case, and the fix is bounded.

The distinction matters because `meta-wish` items don't pressure the
synchronous loop. Classifying ambiguous items as `meta-wish` by default
keeps Step 6 focused on true fixes.

### Edge case 2: The author is uncertain about classification

If the author genuinely can't decide, the decision is: **default to
`meta-question`.** This is the conservative choice:

- `meta-fix` misclassified as `meta-question` delays the fix by one
  reflection; the next author to review the wishlist can reclassify
- `meta-question` misclassified as `meta-fix` risks a synchronous
  edit that shouldn't happen — the cost of reverting an unwanted edit
  is higher than the cost of waiting

### Edge case 3: A `meta-fix` turns out to be wrong when the proposal is drafted

During Step 6 drafting, the author realizes the "known fix" isn't as
known as they thought. The target file has more complexity than the
wishlist entry acknowledged; the proposed content doesn't quite work.

**Resolution:** Defer to `meta-question`. Update the wishlist entry:
"Initially classified `meta-fix`; discovered during Step 6 drafting
that {specific complexity}. Reclassified `meta-question` — next
skill-development reflection to resolve." This is a normal outcome;
it's what the three-criterion test is supposed to catch. The fact
that Step 6 drafting caught it (rather than the classification at
authorship time) is a sign the discipline is working — not a sign of
failure.

### Edge case 4: Step 6 gets approval on all 3 proposals and another is eligible

The reflection had 4 `meta-fix` items. Three go through Step 6 and
apply. The fourth hits the per-reflection cap.

**Resolution:** The fourth stays in the wishlist with `meta-fix`
classification. It's eligible for Step 6 in the next reflection that
has spare capacity. A phase file's Metrics table can include "Step 6
applied: 3 / Step 6 deferred: 1" to make the deferral visible.

If deferrals accumulate over multiple reflections (3+ items deferred
from prior Step 6 caps), the author has systemic drift pressure and
should run a dedicated skill-development reflection to clear the
backlog rather than continuing to defer one per reflection.

### Edge case 5: A `meta-fix` in this reflection would affect the reflection's own templates

Rare but possible: an author writes a reflection, surfaces a
`meta-fix` that says "the phase file template should have section X
in canonical variant," and wants to apply it to `templates.md`. But
the current reflection IS using the old template.

**Resolution:** The Step 6 edit applies; the current reflection does
not retroactively update itself to use the new template. The next
reflection uses the updated template. This is cleaner than trying to
retrofit the current reflection mid-stream.

---

## Relationship to Check 15

Check 15 in `reference/verify.md` validates sub-type coverage: every
wishlist entry in a phase file authored under V3.5 has a sub-type tag.

Check 15 catches:
- Missing sub-type on a new (V3.5-authored) wishlist entry
- Malformed sub-type (typo, wrong format)

Check 15 does NOT catch:
- Misclassified entries (wrong sub-type chosen) — this requires
  judgment
- Whether Step 6 proposals were correctly drafted for `meta-fix`
  entries — the presence of `**Step 6 outcome:**` lines is a proxy
  but not a validation of correctness

Legacy V3.4 entries with bare `type: meta` are grandfathered.

---

## When This Discipline Is Wrong

Three scenarios where strict sub-type classification is counterproductive:

**1. Very small phases with no meta observations.** A lightweight
capture (§3b) that produces one lesson and nothing else doesn't need
a wishlist section. Forcing one would be ceremony without value. The
wishlist (and therefore sub-type classification) applies only when
wishlist entries exist.

**2. Skill-development reflections.** A reflection whose scope is
specifically *improving a skill* is itself the resolution mechanism for
meta-questions and meta-wishes. Its own wishlist section may be sparse
because the meta-concerns of the project are being addressed in-scope
rather than deferred.

**3. When sub-type classification would distract from a more important
observation.** If the author has a significant arc-level observation
that doesn't fit cleanly into any sub-type, write it up without forcing
a sub-type and let the classification fall out naturally during review.
The classification is a tool; don't let it prevent capturing the
observation in the first place.

---

## Change Control

Changes to the sub-type architecture:

- **Adding a fourth sub-type:** Skill version bump. Requires evidence
  that the three existing sub-types don't partition real meta-notes
  cleanly. Should be proposed via the drift intake protocol pattern —
  recurrence across multiple reflections before canonization.
- **Changing the three-criterion test:** Skill version bump. Contract
  change for what qualifies as `meta-fix`.
- **Changing the per-reflection cap (3):** Skill version bump. The
  cap is itself a heuristic; changing it affects Step 6's character
  (more fixes per reflection vs. more focused sessions).
- **Changing the safety rules (current-project-only, uncommitted
  deferral, no chained edits):** Skill version bump. These prevent
  specific failure modes and relaxing them needs evidence the failure
  mode isn't real.
- **Adjusting which files count as "current project":** No version
  bump; recorded as drift-formalization in `skill_dev_log.md`. Project
  structure varies.

---

## Signals the Discipline Is Working

Track across reflections to validate the hypothesis:

- **`meta-fix` action rate:** % of `meta-fix` items approved in Step 6.
  Target: ≥70%. Below 60% suggests classification is too permissive —
  items that should have been `meta-question` are being routed to Step
  6 and declined.
- **Revert rate on Step 6 edits:** % of applied edits later reverted
  or superseded. Target: <20%. Higher suggests synchronous edits are
  being applied without adequate drafting review.
- **Time-to-action on `meta-fix` items:** Median latency from entry
  creation to resolution. V3.4 baseline: 0-2 phases (days to weeks).
  V3.5 target: same reflection (minutes).
- **Classification accuracy over time:** % of entries that retain their
  original sub-type vs. being reclassified later. Stable classification
  suggests the discipline is internalized; frequent reclassification
  suggests either the criteria are unclear or the author's judgment is
  drifting.

These signals feed Phase 7 trial and subsequent reflection metrics.
Phase 0's analysis of Ghost's existing work established the V3.4
baseline (40% action rate, 25% retrospective `meta-fix` classification).
V3.5 trial measures whether the discipline improves these numbers.
