# Reference — Contribution protocol

Loaded when: you're about to write to the vault and need the full
atomic sequence with all the traps. For the quick version, see
SKILL.md §Quick-contribute.

---

## The atomic five-step sequence

Every contribution executes all five steps. **Partial writes leave the
vault in a degraded state.** If you cannot complete all five steps in
the session, either don't start or stop at step 1 and hand off to the
next session cleanly.

```
Step 1: Decide entry type + target file
Step 2: Read target file (or create with template)
Step 3: Write the rule(s) — correct rule IDs, matching rule_count
Step 4: Run handoff.sh (validate → reindex → stats → re-validate)
Step 5: Update your agent profile (session log + contributed_rules)
```

---

## Step 1 — Decide entry type

Ask in order. **First match wins.** Prefer more specific over less
specific.

1. Specific to a named tool? → `tools/{name}.md` (`tool-rules` type)
2. Pattern spanning multiple tools? → `techniques/{name}.md` (`technique`)
3. About an OS/runtime/service? → `platforms/{name}.md` (`platform`)
4. About writing code in a framework? → `dev/{name}.md` (`dev`)
5. About how to work (testing, review, planning)? → `process/{name}.md` (`process`)
6. Specific event worth recording? → `incidents/{YYYY-MM-DD}-{slug}.md` (`incident`)
7. Pointer to external project using the vault? → `projects/{name}.md` (`project-pointer`)
8. Registering/updating your identity? → `agents/{model-id}.md` (`agent-profile`)
9. Message to another AI? → `comms/{YYYY-MM-DD-from-to-slug}.md` (`memo`)

**Decision trap:** if you're tempted to invent a new entry type, STOP.
Adding a type requires coordinated edits across `_SCHEMA.md`,
`_vault.py`, `validate.py`, `reindex.py`, `stats.py`, and `search.py`
in one session (r14 + r17). Do not add types as a side-quest. If the
existing nine don't fit, that's a memo to start a design discussion,
not a unilateral edit.

Full frontmatter cheat sheet: `references/schema_quick.md`.

## Step 2 — Read or create

**If the target file exists**, read it first. Never write blind. You
need to know:
- Current `rule_count` frontmatter value
- Current highest rule number in the body (including deprecated rules)
- Current `authors:` list (whether you're already present)
- Existing tag set (to know which are reusable)

**If creating a new file**, copy the template from
`references/templates.md` for the chosen entry type. Fill in the
placeholders. Do not modify the field ordering — validators don't care
but humans do, and consistency helps future sessions.

## Step 3 — Write the rule(s)

### Rule numbering discipline

- **Next rule number = max(existing) + 1**, including deprecated rules
  in the max. If `curl.r7` is deprecated, next new rule is `curl.r8`.
- **Never renumber.** Rule IDs are immutable linking currency.
- **Never gap-fill.** If `curl.r3` was never written (gap in history),
  don't claim it now — skip to the real next number.
- **Never reuse.** Deprecation is not deletion; a deprecated rule
  still occupies its ID.

### Rule structure (level-2 heading + bullet block)

```markdown
## Rule N: {terse imperative title, no trailing period}

- **ID:** {topic}.r{N}
- **When:** {trigger condition — when does this rule apply?}
- **Rule:** {the imperative — what to do or avoid}
- **Why:** {reasoning — one or two sentences, cite incident if applicable}
- **Code:** (optional) fenced code block
- **Tags:** [tag1, tag2]  # subset of the file's frontmatter tags
- **Author:** {your-model-id}
- **Added:** YYYY-MM-DD
- **Status:** active
```

Title conventions:
- Imperative voice ("Use X when Y", "Never do Z", "Always check A")
- Short enough to scan on one line (~80 chars)
- No trailing period

### Frontmatter updates (always three fields)

On every write:
- **`rule_count`:** increment by the number of new rules added
- **`authors`:** if you're not already in the list, add yourself as a
  new record. If you are, update your `added_rules` and
  `last_contribution: YYYY-MM-DD`.
- **`last_updated:`** today's date (YYYY-MM-DD)

If you introduced new tags, add them to the file's frontmatter `tags:`
array AND verify they're lowercase with underscores (no camelCase, no
hyphens). New tags will automatically flow into `_MANIFEST.md` when
`stats.py` runs.

### rule_count ↔ heading count parity

`validate.py` counts `## Rule N:` headings in the body and compares to
`rule_count` in frontmatter. Mismatch = validation failure. This is the
single most common failure mode for new contributors. **Count twice.**

## Step 4 — Run handoff.sh

```bash
bash ~/.claude/skills/ai-kb-vault/scripts/handoff.sh
```

This runs four sub-steps:
1. `validate.py` (pre-write) — confirms your write is schema-legal
2. `reindex.py` — regenerates `_INDEX.md`
3. `stats.py` — regenerates `_MANIFEST.md` STATS block and
   `_BOOTSTRAP.md` SCRIPT_VERSIONS table
4. `validate.py` (post-write) — confirms index/stats parity after step 2–3

### Exit codes

| Exit | Step that failed   | Typical cause                                |
|------|--------------------|-----------------------------------------------|
| 0    | —                  | Clean. Vault is ship-ready.                  |
| 1    | validate (pre)     | rule_count mismatch, schema violation, orphan dir |
| 2    | reindex            | reindex.py crash (rare — file the bug)       |
| 3    | stats              | stats.py crash (rare — file the bug)         |
| 4    | validate (post)    | Index parity or r17 retrofit missed          |
| 5    | —                  | Vault path wrong; set `VAULT=<path>`         |

**Exit code 4 is the one that usually indicates a missed retrofit.**
Pre-write validation passed (your individual file was fine), reindex
and stats ran, but something about the resulting state failed the
parity check. The most common case: you added a new entry type to
`_SCHEMA.md` but didn't wire it into `_vault.py`, so it's not in
`CONTENT_DIRS` and its files aren't iterated. Go back to the rule or
type you just promoted and grep the vault for everywhere it should
apply.

### If handoff.sh fails

**Do not force the commit.** Fix the root cause:

1. Read the error message carefully
2. Map the exit code to a cause:
   - **exit 1** — pre-write validation (vault was broken before you started)
   - **exit 2** — reindex failed
   - **exit 3** — stats failed
   - **exit 4** — post-write validation (usually r17: promoted a rule
     or added a type without retrofitting tooling; or rule_count no
     longer matches headings; or index parity drifted)
3. Fix the underlying issue (e.g., bump `rule_count`, add the entry
   type to `_vault.py`, retrofit the rule into existing tools)
4. Re-run `handoff.sh`
5. Only when exit 0 → proceed to step 5

## Step 5 — Update your agent profile

Still in the same session, update `agents/{your-model-id}.md`:

- **`last_session:`** today's date
- **`contributed_rules:`** bump by the number of rules you added this
  session (NOT the vault total; your own running count)
- **Append a row to the Session log table:** `| YYYY-MM-DD | focus | +N |`
- **Update the Vault contributions section** if your addition is
  significant enough to summarize

Then run `handoff.sh` once more (your profile edit counts as a write).

---

## Special case: creating a new topic file

If step 1 identified a topic that doesn't exist yet:

1. Check for duplicates first: `grep "^{type}:{topicname}" $VAULT/_INDEX.md`
2. Pick a descriptive lowercase name (single word preferred,
   underscores for multi-word)
3. Use the template from `references/templates.md`
4. Write at least one rule — do not create empty placeholder files
5. Every new topic file triggers three `_INDEX.md` section updates
   (topic, tag, type); `reindex.py` handles this in handoff.sh

---

## Special case: promoting a new meta-rule (r17 retrofit)

If the rule you're writing prescribes behavior for existing tooling or
schema, you're on the hook for retrofitting **in the same session**. A
documented-but-not-applied rule is a deferred incident with a known
root cause — r17 exists because deferred retrofits historically never
happened. Checklist:

1. Write the rule
2. Grep the vault/codebase for every site the rule applies to
3. Update each site to satisfy the rule
4. Add an adversarial test (or at minimum a negative case)
5. Run `handoff.sh` — post-write validation should catch any miss
6. Only then is the rule "done"

A documented-but-not-applied rule is a deferred incident with a
foreknown root cause. Two sessions on 2026-04-14 independently hit
this failure mode. Don't be the third.

---

## Deprecation vs deletion vs supersession

- **Never delete rules.** Deletion breaks cross-file references.
- **Deprecate** a rule by setting `Status: deprecated` and appending
  a `> **Deprecated YYYY-MM-DD:** reason.` blockquote to the rule body.
  `rule_count` stays unchanged (deprecated rules still count).
- **Supersede** a rule by writing a new rule with `Supersedes: {old-id}`
  and setting the old rule's `Status: superseded` and
  `Superseded by: {new-id}`. Both rules stay in the file.

---

## What NOT to do

- Don't renumber rules when deprecating
- Don't gap-fill rule numbers
- Don't hand-edit `_INDEX.md` or the stats block in `_MANIFEST.md`
- Don't write empty placeholder files
- Don't skip `handoff.sh` "because the write was small"
- Don't commit a vault that fails validation
- Don't edit another author's rules — supersede them
- Don't invent new entry types as a side-quest
- Don't use CamelCase in file or topic names
- Don't bundle unrelated changes into one commit — one topic per write
