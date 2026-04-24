# Templates — Exact Formats for Lessons Learned

This file contains every format SKILL.md refers to. Read it before writing any
lesson entries. The formats here are drawn from observed practice in the real
`lessons_learned/` directory — not from an idealized schema. If a future reflection
uses a format that isn't documented here, update this file first, then write the entry.

---

## Phase File Structure

Each phase file is one markdown document with this skeleton:

```markdown
# Phase {N} — {Short Title}

**Tags:** tag1, tag2, tag3

---

## Overview

2–5 sentences framing the scope of this phase and the headline outcome.

---

## Section 1 — {Topic} (optional grouping)

### 1. {Entry Title}

Narrative body: what happened, what was learned, what the code does now.

**Lesson:** One-line takeaway that can stand alone.

### 2. {Entry Title}
...

### 3. {Entry Title}
...

---

## Applied Lessons
(See "Applied Lessons Table Format" below)

## What Went Well
3–5 bullets. Approaches that worked or decisions validated.

## Bugs and Pitfalls
Numbered entries for each non-trivial technical bug encountered. Root cause and fix.

## What Went Badly (optional)
Judgment calls that wasted effort, ignored warnings, premature optimization,
stale assumptions, near-misses caught by a later step. Distinct from Bugs —
bugs are specific technical failures; badly covers decisions you'd make
differently with hindsight.

## Design Decisions
Entries for non-obvious architectural or structural choices with tradeoffs.

## Carry-Forward Items
(See "Carry-Forward Items Table Format" below)

## What Would Help Me Grow — Tooling Wishlist (optional)
Meta-level observations about the skill, tooling, or environment itself.
Entries here may surface a gap in the lessons-learned skill itself — those
entries are the seed for the next skill-authorship reflection.

## Metrics
(See "Metrics Table Format" below)
```

**Key conventions observed in the real repo:**
- Entry headings are `### N. {Title}` — single-integer numbering, monotonic
  within the phase file. This is the dominant format (30 of 31 phase files).
- Sections (`## Section N — Topic`) are an **optional grouping layer** used
  only when a phase file has many entries that benefit from being clustered.
  When sections are used, entry headings may also be two-level
  (`### N.N Title`, section.entry) — observed in `phase22_testing.md` only.
- `**Lesson:**` bold line at the end of each entry is the grep anchor used by
  some INDEX entries — keep it consistent.
- The "Overview" section is always present, always short.
- Optional sections (Applied Lessons, Bugs, etc.) can be omitted when they
  have no entries; phase files do not pad empty sections.

---

## Phase File Entry Format

Individual entries inside a section follow this shape:

```markdown
### 5. Wpscan detection-mode passive saves ~55s on every probe

Wpscan's default `mixed` mode runs `wp_version/unique_fingerprinting.rb`,
which probes 571 JS/CSS files to compute version checksums. This takes
~57s before the actual password-attack work begins. In `passive` mode,
wpscan reads the HTML once (~2s) and moves on.

| Mode | Time | Use case |
|------|------|----------|
| mixed (default) | ~62s | Never in 60s probes |
| passive | ~9s | Always in integration probes |

**Lesson:** Add `--detection-mode passive` to every wpscan probe in a
≤60s timeout.
```

Every entry has:
1. `### N. Title` — single-integer numbering, title frontloaded with the
   concept (not a verb). Two-level `### N.N Title` is acceptable only when
   the phase file uses `## Section N — Topic` grouping (rare — one file).
2. Narrative body — short paragraphs, optional tables, optional code blocks
3. `**Lesson:**` — a single-sentence takeaway that can stand alone when
   grep-hit without the narrative body

---

## INDEX.md Row Format

INDEX.md is the grep-optimized discovery layer. Every row is one line,
pipe-delimited, with exactly four columns:

```
| tags | description | source | type |
```

**Example rows from the real repo:**
```
| wpscan, testing | Passive detection-mode saves ~55s on every probe; default mode fingerprints 571 files before attacking | phase22_testing:5 | rule |
| metasploit, windows | winrm_cmd runs commands over WinRM without dropping a payload — zero AV surface | phase17_msf_sql01:3 | pattern |
| docker, alembic | Alembic upgrade must run inside Docker container; postgres hostname only resolves in Docker network | phase3f_osint_stage | rule |
```

**Column rules:**

| Column | Rule |
|---|---|
| `tags` | Lowercase, comma-separated, primary tag first, no spaces inside a tag (use `-` for multi-word). Primary tags come from the project's tag vocabulary — see INDEX.md top section. |
| `description` | Under 120 characters. Frontload the key concept. Grep hits must be useful without loading the source. |
| `source` | `{phase_id}:{N}` where `{N}` is the integer entry number in the phase file (e.g., `phase17_msf_sql01:3`). The `.md` suffix is omitted. If the lesson spans a whole phase file with no specific entry, use just `{phase_id}`. Range (`phase7_sbom_debugging:1-4`) and multi-entry (`phase6_filesystem_tools:1,5,6`) forms are accepted. |
| `type` | One of: `rule`, `bug`, `pattern`, `insight`. See Type Vocabulary below. |

**Type vocabulary (four types, not three):**

| Type | Definition | Example |
|------|------------|---------|
| `rule` | Prescriptive: "always X" or "never Y". Violating causes predictable failure. | "Validate UUID before any DB query" |
| `bug` | Specific failure encountered and fixed. Record failure mode + root cause. | "Batch insert silently drops rows over 1000" |
| `pattern` | Reusable approach that worked. Not prescriptive — alternatives exist. | "Fixture-driven parser testing" |
| `insight` | Meta-observation about process, methodology, or architecture. Not code-level. | "Two-round Build+Validate → Adversarial Review predicted which bugs each round should catch" |

Default to `rule` when uncertain. `insight` is reserved for process/methodology
observations; don't dilute it by tagging every general observation as one.

**Source-pointer format for AI files is different — see AI File Rule Format.**
INDEX rows and AI file rules each have their own pointer shape, don't mix them.

---

## AI File Rule Format

AI subject files are the structured-recall layer. A cold-start session reads
one or two files and gets working rules without narrative overhead.

```markdown
### Short imperative title
<!-- tags: primary, secondary -->

**When:** The specific context where this rule applies. One line.
**Not when:** (optional) Contexts where the rule does NOT apply, one line.
**Rule:** The rule statement. One or two sentences. Prescriptive voice.

```bash
# Code example showing the correct and incorrect pattern side by side
# WRONG:
gcc test.c   # error: limits.h not found on slim Ubuntu

# RIGHT:
apt-get install -y gcc libc6-dev   # both required together
```

**Why:** (optional) One-sentence reason, typically the underlying mechanism.
Include this when the rule sounds arbitrary without the explanation.

**Companions:** (optional) file.md → "Rule Title", file.md → "Rule Title"

*Source: phase18_tool_testing:5*

---
```

**Heading format (canonical):** `### Short imperative title` — plain H3
with the rule stated as an imperative. This is the format used by 17 of
18 AI files in the real repo. Titles do not include a `Rule N:` prefix;
rules are looked up by grep-matching the title text or the optional
`<!-- tags: -->` comment that follows.

**Heading format (legacy — wpscan.md only):** `### Rule N: Short title` —
the `Rule N:` prefix is used in `lessons_learned/ai/wpscan.md` only
(12 rules). Rules are numbered, restart at 1, and increase monotonically.
This format is valid historical drift; new AI files should use the plain
canonical format unless they have a strong reason to number their rules.

**Source format inside AI files:** `*Source: {phase_id}:{N}*` — italicized,
`.md` suffix omitted, no `§` anchor. The `N` after the colon is
**polymorphic**: it can be an **entry number** (matches `### N. Title` in
the phase file) OR a **line number** (when the phase file has H2 sections
or no numbered entries, or when deeper granularity is needed). Both
interpretations are observed and both are valid.

| Form | Example | N means |
|------|---------|---------|
| Single entry | `*Source: phase16_metasploit_target:5*` | entry or line |
| Phase ID only (no :N) | `*Source: phase19_wrapper_gaps*` | whole file |
| Multi-value in one phase | `*Source: phase9_vulnerable_target:1,2*` | entries or lines |
| Range | `*Source: phase7_sbom_debugging:1-4, 6-7*` | entry range |
| Multi-phase | `*Source: phase10_nuclei:4, phase11_nuclei:2*` | entries |
| Alpha entry ID | `*Source: phase18_tool_testing:A1*` | labeled entry |
| Parenthetical context | `*Source: phase6_filesystem_tools:4 (StringsWrapper bug)*` | entry + note |
| Cross-phase annotation | `*Source: phase5_terminal_notes:adversarial (corrects phase3e_operational:350)*` | named + corrected line |
| Section-anchor (wpscan.md only) | `*Source: phase22_testing.md §2.1*` | section §entry |

**Prefer plain `phase_id:N`** for new rules. When in doubt about whether
to use an entry number or a line number, use the entry number — it's more
stable across phase file edits. Avoid inventing new variations — Check 13
(format drift) flags any AI file whose pointer forms fall outside this table.

**wpscan.md section-anchor legacy:** `lessons_learned/ai/wpscan.md` uses
`*Source: {phase_file}.md §{section}*` in all 12 rules. This is the only
file using the `.md §` variant. New reflections should use canonical
`phase_id:N`; wpscan.md is either reconciled in a future phase or left as
historical drift.

**When/Rule discipline — isolation read:** After writing a rule, re-read only
the **When**, **Not when**, and **Rule** lines in isolation from the surrounding
narrative. If those three lines don't carry the rule without the code block or
Why, a future session that grep-hits only the rule heading will get nothing
actionable. Rewrite until the rule is self-contained in its When/Rule pair.

**Not when:** Add a **Not when** boundary when the rule's keywords overlap a
context where the rule actively doesn't apply. Example: a rule about "probe
timing in wpscan integration tests" should have `**Not when:** Running wpscan
manually outside an integration harness — there is no 60s kill deadline.`
Sparse use is fine; 19 instances across 7 files in the real repo is not an
under-use — it's the right density.

**Companions:** Add `**Companions:** file.md → "Rule Title"` when another rule
in a different file addresses a related facet that this rule's effectiveness
depends on. Links must be mutual — if A lists B as a companion, B must list A.
The verify.md Check 6b confirms mutuality. Keep the list to 1–3 entries;
larger clusters belong in a concern map (deferred — see §"Deferred Features").

---

## Applied Lessons Table Format

The Applied Lessons table is the feedback loop between **lookup** and **capture**.
It records which prior rules the session consulted during work and whether
they helped.

**Format:**

```markdown
## Applied Lessons

| Rule (source → heading) | Outcome | Note |
|-------------------------|---------|------|
| wpscan.md → "Rule 1: detection-mode passive" | applied | Saved ~55s per probe on 14 probes |
| process.md → "Lookup-before-work" | REGRESSED | Knew the rule, still skipped lookup on the bash script trap |
| feedback_shell_testing_traps (memory) | REGRESSED | Memory caught it after the test run, not before |
| testing.md → "Mock fidelity" | in place | No mocks touched this phase |
| docker.md → "CLI tool vs language binding" | applied proactively | Added libc6-dev alongside gcc on sight |
| NEW (this phase) | discovered | wpscan xmlrpc body-credential-extraction vector |
```

**Columns:**

| Column | Rule |
|---|---|
| `Rule (source → heading)` | Either `{ai_file}.md → "{Rule Title}"` or `{memory_file} (memory)` or `NEW (this phase)` for rules discovered during this phase. |
| `Outcome` | One of the vocabulary values below. |
| `Note` | One-line context. What specifically about this phase made the rule apply, fail, or get skipped. |

**Outcome vocabulary — nine values:**

| Outcome | Meaning |
|---|---|
| `applied` | The rule was looked up, consulted, and used to make a decision. |
| `applied proactively` | The rule was recalled from prior work without a lookup — automatic application. |
| `in place` | The rule was already satisfied by existing code; no change needed this phase. |
| `N/A` | The rule was consulted but didn't apply to this phase's context. |
| `missed` | The rule existed in INDEX/AI files but was **not consulted** during work. Discovered in hindsight during reflection. |
| `REGRESSED` | The rule was **known** (in memory, prior Applied table, or personal recall) and **still violated**. Distinct from missed — missed is "didn't know to look", REGRESSED is "knew, didn't consult, failed". |
| `contradicted` | The rule was followed and caused a failure. The rule itself is wrong or needs a Not-when boundary. |
| `revised` | The rule applied in spirit, but this phase discovered a new boundary condition. Feeds a Not-when addition. |
| `discovered` | A new rule created this phase, not looked up from prior work. Lets the Applied table double as a first-pass catalog of new rules. |

**`REGRESSED` is the most important outcome.** It directly diagnoses
lookup-protocol failure — the exact feedback loop this skill exists to
strengthen. If a phase's Applied table has any `REGRESSED` rows, the next
phase's `Missed` scan should include those rules and the cause of the lookup
miss should be named. Repeated `REGRESSED` on the same rule is a signal to
escalate the rule from AI file to memory file, or vice versa, or to adjust
the rule's trigger keywords.

**Every Applied row with outcome `missed` or `REGRESSED` must also appear in a
Missed entry if a split Applied/Missed table is in use** (see below).

---

## Missed Table (Applied Lessons split)

A phase can optionally split the Applied Lessons section into two tables:

```markdown
## Applied Lessons

| Rule (source → heading) | Outcome | Note |
|-------------------------|---------|------|
| (only rows with outcomes: applied, applied proactively, in place, N/A, revised, discovered)

## Missed

| Rule (source → heading) | Why missed | Consequence |
|-------------------------|------------|-------------|
| process.md → "Lookup-before-work" | Skipped the lookup step on fresh bash script | Wrote `[[ ]] && cmd` under set -e, bash script crashed at runtime |
| feedback_shell_testing_traps (memory) | Memory not reviewed before writing the test script | Silent failure in timeout wrapper, had to debug from scratch |
```

**Why split?** Applied is easy to bias-fill — you remember what you used.
Missed requires a separate grep pass against INDEX.md (targeted at the tags
the phase touched) which is where real growth happens. The split forces the
grep pass. Small phases can keep the single combined table; large phases or
phases where lookup discipline is being actively measured should split.

**Discovery procedure for Missed:**
1. Identify the tags that describe this phase's work area (usually 2–4 tags).
2. `grep -i "{tag}" lessons_learned/INDEX.md` for each tag.
3. For each hit, ask: was this rule consulted during work? If no, is it a
   genuine miss or is its Not-when satisfied?
4. Genuine misses go in the Missed table with a "Why missed" column.

---

## Carry-Forward Items Table Format

Open debt that a phase creates but does not resolve. Must be tracked in a
table so each item has a stable ID across phases.

```markdown
## Carry-Forward Items

| ID | Item | Priority |
|----|------|----------|
| CF-1 | Re-verify phase-9's "SUID bits stripped by Docker" claim — didn't reproduce in privesc ecology. | Low |
| CF-2 | Document the SNMP port quirk (`11161` works, `1161` doesn't) in an inline comment. | Medium |
| CF-3 | Add a `make test-targets-all` CI smoke job — currently the full 87-probe run is manual. | Medium |
```

**Conventions:**
- `CF-N` IDs are stable across phases. A CF-N created in phase5 remains CF-N
  in phase6 unless resolved.
- When a CF item is resolved in a later phase, the resolving phase's
  Carry-Forward section includes: `| CF-N | RESOLVED in phase{N}_{name}: brief note | — |`.
- Priority vocabulary: `Low`, `Medium`, `High`, `Critical`.
- CF items are **debt with a due date** — unresolved items roll forward
  into the next phase's Carry-Forward table automatically. Don't drop them.

**CF-N is a table column value, not a line prefix.** The V3_3 skill documented
`CF-N: description` as a prefix format — that format is not in use anywhere
in the real repo. Tables are the observed format.

---

## Metrics Table Format

Records quantitative measurements of phase output. Optional but recommended.

```markdown
## Metrics

| Metric | Value |
|--------|-------|
| Probes added | 14 (101 total, up from 87) |
| New AI rules | 12 (wpscan.md: 12) |
| Existing rules applied | 8 |
| Rules REGRESSED | 2 |
| CF items opened | 3 |
| CF items resolved | 1 (CF-6 from phase21) |
| Session count | 4 |
| Phase duration | 3 days |
```

Metrics that are hard to measure are fine to omit. Three categories that
are *always* valuable to capture if available:
1. **New knowledge added** (rule count, CF count)
2. **Prior knowledge exercised** (applied count, REGRESSED count)
3. **Work output** (probe count, test count, feature count)

The REGRESSED count is the most important single metric — it's the direct
measure of whether the lookup protocol is working. A phase with 3+ REGRESSED
rows is a signal that the next phase needs a stricter lookup discipline.

---

## Superseded Rules Format

When a rule is replaced or corrected (not merely refined), both sides must
be marked so a grep hit on the old rule redirects to the new one.

**In the superseded AI rule:**

```markdown
### Rule 7: Old rule title

**Superseded by:** docker.md → "Rule 18: New rule title"
**Supersession reason:** corrected — the original rule was wrong about SUID
bit preservation in Docker layers. The phase-21 privesc ecology proved they
do persist; phase-9's original observation was specific to the older
supervisord-based image.

(original body retained below for context)
```

**In INDEX.md:**

```
| docker | [SUPERSEDED] Docker build layers strip SUID bits — see Rule 18 | phase9_vulnerable_target | rule |
```

**Supersession reasons — controlled vocabulary:**

| Reason | Meaning |
|---|---|
| `corrected` | The old rule was factually wrong. New rule replaces it entirely. |
| `refined` | The old rule was directionally correct but the new rule adds a boundary condition or generalizes the statement. |
| `narrowed` | The old rule was too broad. New rule applies only in a narrower context. |
| `split` | The old rule covered two distinct cases. New rules handle each case separately. |

**Forward pointers must be mutual.** If Rule 7 is superseded by Rule 18, Rule
18 should list Rule 7 in a `**Supersedes:** docker.md → "Rule 7: old title"`
line. Verify.md Check 11 confirms both sides.

**Superseded rules are excluded from `_overview.md` rule counts** — they no
longer provide actionable recall.

---

## Worked Example — One Lesson Flowing Through All Three Layers

This shows a single lesson being captured from phase file to INDEX to AI file.

### Step 1 — In the phase file (narrative source of truth)

```markdown
### 5. Passive detection-mode saves ~55s on every probe

Wpscan's default `mixed` detection mode runs `wp_version/unique_fingerprinting.rb`,
which probes 571 JS/CSS files to compute version checksums. This takes ~57s
before any real work begins — killing the 60s integration probe timeout.
In passive mode, wpscan reads the HTML once (~2s) and proceeds directly to
the password attack.

| Mode | Time | Use case |
|------|------|----------|
| mixed (default) | ~62s | Never in 60s probes |
| passive | ~9s | Always in integration probes |

**Lesson:** Add `--detection-mode passive` to every wpscan probe in a
≤60s timeout.
```

### Step 2 — In INDEX.md (discovery router)

Add one row to the **Active** tier:

```
| wpscan, testing, timing | Passive detection-mode saves ~55s on every probe; default mixed mode fingerprints 571 files before attacking | phase22_testing:5 | rule |
```

- Tags: primary tag first, comma-separated.
- Description: 119 chars (under 120), concept frontloaded.
- Source: `phase22_testing:5` — integer entry number only, no `.md`.
- Type: `rule` — prescriptive, violation causes predictable failure.

### Step 3 — In ai/wpscan.md (structured recall)

Add a new rule using the canonical plain-title format (`### Short imperative`).
Note: wpscan.md is the one file using legacy `### Rule N:` numbering — new
entries there may continue the numbering for consistency, but the canonical
format shown here is what every other AI file uses.

```markdown
### Always use --detection-mode passive in integration probes
<!-- tags: wpscan, testing, timing -->

**When:** Writing any wpscan probe in an integration test with a ≤60s timeout
**Rule:** Add `--detection-mode passive` to every wpscan probe. Default mixed
mode makes 571+ HTTP requests for version fingerprinting, taking ~57s before
the actual probe work begins.

```bash
# SLOW (default): ~57s fingerprinting + 5s attack = ~62s → timeout killed
wpscan --url http://target/ --usernames admin --passwords list.txt --password-attack wp-login

# FAST: ~2s base scan + 5s attack = ~9s → well within 60s
wpscan --url http://target/ --detection-mode passive --usernames admin \
    --passwords list.txt --password-attack wp-login
```

**Why:** The `wp_version/unique_fingerprinting.rb` phase probes 571 JS/CSS
files to compute version checksums. This dominates total scan time and
provides no value when the test only needs a password attack result.

*Source: phase22_testing:5*

---
```

### Step 4 — In ai/_overview.md (routing index)

Update the wpscan row's rule count and keywords:

```markdown
| [wpscan.md](wpscan.md) | 12 | passive detection mode (saves 55s), --enumerate u timing trap, ... |
```

### Isolation read check

Re-read only these three lines from the AI rule:

```
**When:** Writing any wpscan probe in an integration test with a ≤60s timeout
**Rule:** Add `--detection-mode passive` to every wpscan probe. Default mixed
mode makes 571+ HTTP requests for version fingerprinting, taking ~57s before
the actual probe work begins.
```

Does a future session that grep-hits only this rule heading get actionable
knowledge from those three lines alone? **Yes** — the When specifies the
exact context (integration probe with a 60s budget), the Rule specifies the
exact fix (add the flag), and the Rule's parenthetical justifies the fix
without requiring the Why line. This rule passes the isolation read.

If the isolation read had required loading the code block or the Why line
to be actionable, the rule would need to be rewritten.

---

## Deferred Features

These features existed in V3_3 but are deferred in V3_4 because zero or
near-zero repo usage does not justify the context tax:

- **Concern maps** — V3_3 documented concern maps as "the most efficient
  lookup path" but zero concern maps exist across 19 AI files. Feature
  removed from SKILL.md, verify.md, and _overview.md. Can be reintroduced
  in a future version if a real use case emerges.

If a future phase builds a genuine multi-rule design-concern cluster (3+
mutually-companioned rules addressing a shared architectural concern),
document it in a new phase file's "What Would Help Me Grow" section first
— that entry will seed the concern-map feature's reintroduction if it
proves worthwhile.
