# Lessons Learned — Skill Development Memory

This folder captures **patterns recognized** during the development of the `scripting-standards` skill itself. Each entry records a real incident (or a protocol success worth generalizing), extracts the rule that would have caught it (or did catch it), and encodes the lesson for future recognition.

**Load `lessons.md` when:** recognizing a pattern that might have been encountered before; about to make an architectural decision resembling a past one; authoring a new lesson and checking for duplicates; reviewing whether a current approach risks a known failure mode.

**Do not load during normal scripting work.** This file is institutional memory about the skill's own development, not a reference the skill uses to do its job.

---

## Purpose

Lessons answer one question:

> "What pattern should I recognize the next time something like this comes up?"

They do not answer:

- "Why did we choose this approach?" — that's a decision; use `../developer_log/log.md`.
- "How do I debug this class of bug?" — that's project-level tooling knowledge; use Ghost's general `lessons-learned` skill.
- "How does this feature work?" — that's documentation.

The separation is deliberate. A pattern without an incident to ground it is decoration. A decision trail reframed as a lesson dilutes both.

---

## Scope

**In scope:**

- Real incidents from developing this skill (bugs caught, bugs missed, architectural surprises)
- Protocol success stories **when they carry a generalizable rule** (see Success Story Lessons below)
- Retroactive captures of patterns evidenced in existing skill files

**Out of scope:**

- Incidents from project work that uses this skill — those belong in Ghost's general `lessons-learned` skill
- Hypothetical patterns ("this could happen if...") — inherits `prove_first.md`'s real-incidents-only rule
- Routine protocol passes without a generalizable rule — those are logs, not lessons
- Decisions with alternatives — those are dev log entries
- Calibration observations without a resulting rule

---

## Format Contract

The grep-stable anchor and six-field schema. **Must not drift** — format uniformity is what lets retroactive audit work across sessions.

### Entry anchor

```
### <lesson:YYYY-MM-DD:slug>
```

**Grep pattern:** `^### <lesson:`

- `lesson` literal (never `lessons`, `lesson_entry`, etc.)
- **Date** — ISO 8601, the date the entry was written. For retroactive entries, today's date; the original incident context goes in Situation.
- **Slug** — lowercase, hyphen-separated, content-descriptive. Stable once assigned.

### Entry fields

Six fields, inherited from `reference/prove_first.md`'s case study schema, adapted slightly for skill-development scope. In this order:

```markdown
### <lesson:YYYY-MM-DD:slug>

**Situation.** What was being built, what assumption was held, what context surrounded the incident. For retroactive entries, cite the existing-file evidence.

**What went wrong.** The failure, including time lost and any cascading consequences. For success story lessons, this field states what the protocol *almost* missed — the hypothetical failure that didn't happen because the protocol caught it.

**Root cause.** The false assumption or architectural gap, stated plainly.

**What would have caught it.** *(or, for success lessons and retroactive entries where the catching mechanism now exists in the skill: "What did catch it.")* The specific intervention — a protocol step, a test, a review pass, a format-contract check. For retroactive entries, this field describes the rule or section that was added in response to the incident and now prevents its recurrence.

**Lesson encoded.** Cross-reference to where this learning now lives in the skill — a reference file section, a protocol rule, a memory entry, a schema constraint.

**Generalizable rule.** The pattern other sessions should recognize. One or two sentences. Should work as a standalone statement decoupled from the incident.
```

### Cross-reference format

- Within this file: `<lesson:YYYY-MM-DD:slug>`
- To `../developer_log/log.md`: `<devlog:YYYY-MM-DD:slug>`
- To `reference/prove_first.md`: `reference/prove_first.md § Case Study N — <name>`
- To other skill files: `reference/<file>.md § <Section Name>` or `SKILL.md § <Section Name>`
- To Ghost's general `lessons-learned` skill: `lessons-learned skill § <section>`

---

## Gatekeeping Rules

Inherited from `reference/prove_first.md` with two skill-development extensions:

1. **Real incidents only.** Hypothetical scenarios, invented examples, and "this could happen" patterns are rejected. Every lesson must point to a real event — a debugging session, an authoring session, a protocol run — that demonstrates the pattern.

2. **Retroactive entries require existing-file evidence.** For patterns captured from V4.7 or earlier, the Situation field must cite the sourcing file and section. Memory-only reconstruction is rejected.

3. **Success story lessons require a generalizable rule.** A lesson like "end-to-end verification caught a bug" is only accepted if it includes a rule that applies beyond the specific incident (e.g., "verification discipline applies at the skill level, not only at the script level"). Success without a rule is a routine pass and belongs in the run log.

4. **One pattern per lesson.** A complex incident that teaches multiple independent patterns becomes multiple lessons. Bundling dilutes the rule.

5. **The Generalizable Rule is the test.** If you cannot state a one-or-two-sentence rule that stands alone without the incident, the lesson isn't ready. Rewrite or reject.

Enforcement: self-enforced at authoring time. The gatekeeping is what keeps this file institutional memory rather than a junk drawer.

---

## Retroactive Entries

Same convention as the developer log:

- **Date in anchor** = capture date, not original incident date
- **Situation field** states the original circumstance and cites existing-file evidence

The sourcing citation lets a future reader verify the lesson's basis independently — and confirms that the lesson wasn't reconstructed from memory alone.

---

## Success Story Lessons

Most lessons start from failures. But some patterns are worth recognizing because a protocol *prevented* failure — and the generalizable rule is "apply this protocol broadly."

A success story qualifies as a lesson if and only if:

1. It describes a specific event where a protocol or discipline caught a real issue
2. The issue was non-trivial (not a routine pass)
3. The generalizable rule extends beyond the specific protocol to a broader class of situations

Example: a verification pass that caught a bug static review missed, teaching "verification applies at the skill level, not only at the script level." The rule extends from scripts to skills — that's generalization. A verification pass that caught a typo it was supposed to catch isn't a lesson; it's a routine run.

---

## How to Add a New Lesson

1. **Identify the incident** — a specific event, session, or existing-file piece of evidence.
2. **Walk the six-field schema** — can you complete all six fields from real information? If any field requires hypothesizing, the lesson isn't ready.
3. **Verify no duplicate** — grep `lessons.md` for keywords; if the pattern is already captured, extend that lesson's Generalizable Rule rather than making a new one.
4. **Write the Generalizable Rule first** — one or two sentences, standalone. If you cannot, the lesson fails gatekeeping.
5. **Write the entry** using the Format Contract verbatim. All six fields populated.
6. **Cross-reference** via the fields themselves ("Lesson encoded" cites the skill location where the rule now lives) and via optional `See also:` lines.
7. **Append to the end of `lessons.md`**, newest lessons at the bottom. Chronological order by capture date.

---

## Relationship to `reference/prove_first.md`

`prove_first.md` holds case studies about **using the skill on project work** — debugging incidents from Ghost's projects (Phase 4.1 Celery tests, wpscan timeouts, masscan loopback quirks). Scope: project-level bugs.

This folder holds lessons about **developing the skill itself** — schema violations, protocol gaps, authoring-time bugs, editorial drift. Scope: skill-level bugs.

The schemas are intentionally similar (six fields, real-incidents-only gatekeeping) because the *shape* of institutional memory is the same. The scopes are intentionally separate because mixing "bug in a Celery test" with "format-contract violation in a skill patch" would force a reader to filter by relevance on every read.

When a lesson in this folder is directly related to a `prove_first.md` case study, cross-reference explicitly. Do not duplicate.

---

## Relationship to Ghost's General `lessons-learned` Skill

Ghost maintains a general `lessons-learned` skill (V3.5+) covering cross-cutting institutional knowledge from project work. That skill is the authoritative home for lessons about:

- Tool quirks (wpscan, masscan, specific libraries)
- Debugging strategies
- Environmental issues
- Patterns across multiple projects

This folder is scoped to the `scripting-standards` skill's **own** development. It is not a replacement for the general skill and does not try to cover its ground.

**Cross-referencing convention:** this folder may point outward to `lessons-learned skill § <section>` when a skill-development lesson has a related project-level lesson. The general skill is not expected to point inward to this folder — the dependency is one-directional, which keeps the general skill's scope clean.

When in doubt about where a lesson belongs: if it's about this skill's code, schemas, or authoring discipline, it's here. If it's about anything else, it's in the general skill.
