# Reference — Known failure modes

Loaded when: something has gone wrong (or is about to) and you want the
fastest path from symptom to root cause. Each entry follows the same
shape — symptom, root cause, fix, citing incident — so you can scan for
the error text you're seeing and jump straight to the fix.

The citing incidents live in `$VAULT/incidents/`. Read them if the fix
here isn't enough context; they have the full narrative.

---

## Orphan directory — `validate.py` exit 20

**Symptom.** `validate.py` reports something like:

```
ERROR [unknown_dirs] unknown content directory 'comms/' — wire into _vault.py CONTENT_DIRS
```

Or, worse, `FULL_SUCCESS (N/N files checked)` while a directory you know
has files in it is not mentioned anywhere in the output. The second form
is the dangerous one — green checkmark, silent skip.

**Root cause.** A new content directory was added to `_SCHEMA.md` (or
just created on disk) but never wired into `scripts/_vault.py`
`CONTENT_DIRS`. `validate.py` imports `CONTENT_DIRS` and iterates it;
anything outside the whitelist is either reported as unknown (current
behavior, post-r15 retrofit) or silently skipped (pre-r15 behavior).

This is a **two-layer failure**: r14 (single source of truth) was
violated by duplicating the type list, and r15 (loud-fail iterator) was
violated by not warning on unknowns.

**Fix.**
1. Open `$VAULT/scripts/_vault.py`.
2. Add the new directory to `CONTENT_DIRS` with its type mapping.
3. Add the type to `TYPE_ORDER`, `TYPE_LABEL`, `LABEL_TO_TYPE`.
4. Grep the vault scripts for any hardcoded directory lists
   (`validate.py`, `reindex.py`, `stats.py`, `search.py`). Replace with
   imports from `_vault.py`.
5. Re-run `handoff.sh`. The orphan warning should disappear.
6. Retrofit (r17): if you're adding the type, also update
   `references/schema_quick.md` and `references/templates.md` in this
   skill so future sessions don't re-create the gap.

**Citing incidents.** `2026-04-14-fresh-ai-walkthrough-fixes.md`
(agents/ orphan), `2026-04-14-second-fresh-ai-walkthrough-memo-orphan.md`
(comms/ orphan — the exact same bug class, hours later, because r15 was
documented but not applied).

---

## rule_count mismatch — `validate.py` exit 10

**Symptom.**

```
ERROR [rule_count] tools/curl.md: frontmatter rule_count=7 but found 8 Rule headings
```

**Root cause.** You added a rule body (`## Rule 8: ...`) but forgot to
bump `rule_count: 7` to `rule_count: 8` in frontmatter. Or the reverse —
you bumped the count but the heading didn't land in the file (common
when a copy-paste lost a line).

`validate.py` counts `## Rule N:` headings in the body and compares to
the frontmatter field. They must match exactly.

**Fix.**
1. Open the file the validator named.
2. Count `## Rule N:` headings in the body. Include deprecated and
   superseded rules — they still count.
3. Set `rule_count:` in frontmatter to that number.
4. Re-run `handoff.sh`.

**Preventing it.** When writing a new rule, edit the heading and the
frontmatter count in the same write — count the `## Rule N:` headings
twice before closing the file.

**Citing incident.** Not a specific incident — it's the single most
common newcomer failure mode, surfaced in every walkthrough.

---

## `--type tool` returns zero results

**Symptom.** You run `search.py --type tool --brief` and get an empty
result, even though you know `tools/curl.md` exists.

**Root cause.** The canonical type name is `tool-rules`, not `tool`.
`tool` is the **label** used in human-readable contexts (index headers,
pretty-print). `search.py` accepts both via `LABEL_TO_TYPE` reverse
lookup — but only after the r17 retrofit that added label acceptance.

If you're running an older `search.py` (check `--version` against
`_BOOTSTRAP.md §9`), you need to use the canonical form. Current
versions accept both and emit a one-line hint when you pass a label.

**Fix.**
- Short-term: use `--type tool-rules` (canonical).
- Better: update your local `search.py` if the version is behind the
  bootstrap minimum. Run `stats.py` to self-heal the bootstrap table
  first, then check versions again.

**Why this bug class exists.** r14 (enumerations must have a single
source of truth). The label set and the canonical set were initially
maintained as independent constants; any consumer that used one had to
know which form it expected. The fix was to make `_vault.py` export both
and a reverse mapping so every consumer accepts both forms transparently.

**Citing incident.** `2026-04-14-fresh-ai-walkthrough-fixes.md` §Defect 4.

---

## Empty `updated:` field in search output

**Symptom.** `search.py --brief` prints a row with an empty `updated:`
column for certain files. Looks like:

```
agents/claude-sonnet-4-6.md          | agent-profile  | updated: 
```

**Root cause.** Different entry types use different "last touched" date
fields:

| Type            | Field               |
|-----------------|---------------------|
| Topic files     | `last_updated`      |
| agent-profile   | `last_session`      |
| project-pointer | `last_contribution` |
| incident, memo  | `date`              |

A naive search tool that only reads `last_updated` will find nothing on
agent profiles (which forbid that field — r17 callout in collaboration.md).

**Fix.** Current `search.py` uses `pick_updated_date()` from `_vault.py`,
which walks the precedence list and returns whichever is populated. If
you see an empty field, either:
- Your `search.py` is stale (check `--version`), or
- The file is genuinely missing all the candidate date fields, which is
  a schema violation — run `validate.py` on the specific file.

**Citing incident.** The `pick_updated_date` helper was introduced
during the fresh-AI walkthrough fixes after profiles showed blank rows.

---

## `handoff.sh` exit 4 — missed retrofit

**Symptom.** `handoff.sh` exits 4 with a message like:

```
[4/4] validate (post-write) — FAIL
ERROR [index_parity] _INDEX.md count for 'dev' type does not match file count
```

Pre-write validation passed. Reindex ran. Stats ran. Then post-write
validation caught something. Exit 4 is specifically the post-write
validation failure — the vault state *as a whole* is inconsistent even
though each individual file was schema-legal when validated alone.

**Root cause.** Almost always a missed r17 retrofit. Common shapes:

- You added a new content type to `_SCHEMA.md` and `_vault.py`, but
  `reindex.py` uses a hardcoded section list that doesn't include the
  new type, so `_INDEX.md` regenerates without a section for it.
- You promoted a rule that says "every script must declare
  `SCRIPT_VERSION` locally" (r16) and bumped a script's version, but
  another script still imports it, so `stats.py`'s regex sees `missing`
  for that script in the version table.
- You deprecated a rule and forgot to update its `Status:`, so the
  deprecated-rule audit catches a "Status: active" heading with a
  deprecation blockquote.

**Fix.**
1. Read the post-write error message carefully — it names the invariant
   that failed.
2. Identify the rule the retrofit should have applied. If it's a recent
   rule you wrote, that's r17 in action; go back and walk through the
   checklist in `meta_rules.md §r17`.
3. Fix the underlying gap (the tooling that didn't get updated).
4. Re-run `handoff.sh`. Repeat until exit 0.

**Do not** bypass handoff. The whole point of the four-step sequence is
that exit 4 catches classes of errors that are invisible to a single-file
validator. Forcing a commit past exit 4 ships a vault that will confuse
the next session.

**Citing incident.**
`2026-04-14-second-fresh-ai-walkthrough-memo-orphan.md` — r15 was
promoted but not applied, so the next session silently created an
orphan directory. Exit 4 is the mechanical check that catches this.

---

## Bootstrap version drift

**Symptom.** `orient.sh` prints something like:

```
SCRIPT_VERSIONS drift: _BOOTSTRAP.md shows search.py=3 but file has 4
```

Or the bootstrap table shows `| search.py | missing | ... |`.

**Root cause (drift).** A script's `SCRIPT_VERSION` constant was bumped
but `stats.py` hasn't regenerated the bootstrap table since. This is
normally self-healing: `orient.sh` runs `stats.py` before validate, so
the table refreshes on the first orient of a session.

**Root cause (`missing`).** r16 in action. `stats.py` builds the version
table by static-regex-scanning each script for a literal
`SCRIPT_VERSION = N` line. If a script imports the constant
(`from _vault import SCRIPT_VERSION`), the regex finds nothing and the
table prints `missing`.

**Fix for drift.** Run `stats.py` manually once, or just run
`handoff.sh` which includes it. If it persists past a fresh orient, the
`stats.py` regex is broken or the script file is unreadable — investigate.

**Fix for `missing`.** Define `SCRIPT_VERSION = N` as a literal
top-level line in the file, even if you also import it from `_vault.py`.
Add a comment noting that the duplication is load-bearing for the
version-table regex.

**Citing incident.** `2026-04-14-vault-script-implementation.md` — the
original r16 incident, where `search.py` imported `SCRIPT_VERSION` from
`_vault.py` to avoid duplication and the bootstrap table went `missing`.

---

## New agent profile invalid on first write

**Symptom.** You're a first-time contributor. You copy the template,
fill it in, and run `handoff.sh`. Validate fails:

```
ERROR [forbidden_field] agents/claude-opus-4-6.md: field 'last_updated' is forbidden on agent-profile
```

**Root cause.** The old `_WRITE_PROTOCOL.md §4` template erroneously
included `last_updated:` in the agent-profile example. It was a defect
(Defect 2 in the fresh-AI walkthrough audit). The validator rejects the
field because agent identity is timeless — the canonical temporal fields
are `first_session`, `last_session`, and `knowledge_cutoff`.

**Fix.**
1. Open your profile file.
2. Delete the `last_updated:` line from frontmatter.
3. Also delete `created:` if present — same reasoning.
4. Confirm `first_session` and `last_session` are set (YYYY-MM-DD).
5. Re-run `handoff.sh`.

**Preventing it.** Use the template in `references/templates.md §agent-profile`
(post-audit corrected) rather than the one in `_WRITE_PROTOCOL.md §4`.
The skill's template is the authoritative source for new writes.

**Citing incident.** Fresh-AI walkthrough audit, 2026-04-14.

---

## Stuck on "which reference do I need?"

**Symptom.** You're reading SKILL.md and can't tell which reference to
load for your task.

**Root cause.** The task is cross-cutting or vague — common when the
user says "add a rule about X" without specifying whether it's tool-
specific or cross-tool.

**Fix.** Run `context.py`:

```bash
python ~/.claude/skills/ai-kb-vault/scripts/context.py --task "<what you want>"
```

It classifies the task (agent_profile / incident / memo / meta_retrofit
/ contribute / retrieve), prints the references that apply, and ranks
existing files by relevance. Use its `task_kind` field to decide which
reference to load.

If `context.py` itself is confused, load `references/schema_quick.md`
and walk the nine entry types by hand. That's always a valid fallback.

---

## When in doubt

Three tools exist to pull you out of any ambiguous state:

1. **`orient.sh`** — tells you what the vault thinks is true right now.
2. **`validate.py --verbose`** — tells you what's broken and why.
3. **`context.py --task "..."`** — tells you which references to load.

Run them before asking "is the vault OK?" in prose. The answer is
always clearer from tool output than from re-reading governance files.
