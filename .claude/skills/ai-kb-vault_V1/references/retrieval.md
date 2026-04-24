# Reference — Retrieval protocol

Loaded when: you need to find something in the vault and SKILL.md's
Quick-retrieve isn't enough. For the 3-tier summary, see SKILL.md
§Quick-retrieve.

---

## The three tiers, in order

The vault is organized so deterministic retrieval is always the fastest
option. Only fall back to grep when the first two tiers don't apply.

1. **Constructed path** — you know the topic name; build the path.
2. **`search.py`** — you know a tag, type, keyword, or rule ID.
3. **Grep** — absolute last resort, for substrings that aren't in tags
   or rule fields.

If you find yourself reaching for grep, first ask: "would the vault's
tag vocabulary cover this?" Run `search.py --list-tags` and scan the
existing tags — the term you wanted is often already a tag.

---

## Tier 1 — Constructed path

Every content file lives at `<dir>/<topic>.md` where `<dir>` is fixed
per type and `<topic>` is lowercase with underscores.

| Type            | Directory     | Example                      |
|-----------------|---------------|------------------------------|
| `tool-rules`    | `tools/`      | `tools/curl.md`              |
| `technique`     | `techniques/` | `techniques/auth_bypass.md`  |
| `platform`      | `platforms/`  | `platforms/windows.md`       |
| `dev`           | `dev/`        | `dev/fastapi.md`             |
| `process`       | `process/`    | `process/testing.md`         |
| `incident`      | `incidents/`  | `incidents/YYYY-MM-DD-slug.md` |
| `project-pointer` | `projects/` | `projects/ghost-assessment-platform.md` |
| `agent-profile` | `agents/`     | `agents/claude-sonnet-4-6.md`|
| `memo`          | `comms/`      | `comms/YYYY-MM-DD-...-slug.md` |

Topic naming:
- Lowercase, underscores for multi-word (`port_scan`, not `portScan`)
- Singular (`cookie`, not `cookies`)
- No version suffixes (`python`, not `python3`)

Read the file directly. Done.

---

## Tier 2 — search.py

Run from any directory; auto-detects vault root.

### Flags reference

```bash
# Discovery
python $VAULT/scripts/search.py --list-types    # all types with counts
python $VAULT/scripts/search.py --list-tags     # all tags with file counts

# Filters (combinable)
python $VAULT/scripts/search.py --type <type>   # canonical OR label
python $VAULT/scripts/search.py --tag <tag>     # single-tag AND filter
python $VAULT/scripts/search.py --any-tag X --any-tag Y  # OR-tag
python $VAULT/scripts/search.py --text "phrase" # keyword in rule body
python $VAULT/scripts/search.py --rule curl.r3  # single rule by ID

# Output modes
python $VAULT/scripts/search.py --tag http --brief   # one line per file
python $VAULT/scripts/search.py --tag http           # full rule bodies
python $VAULT/scripts/search.py --tag http --json    # machine-readable
```

### The `--type` label trap (this was a real bug)

`--type` accepts **both** canonical types (`tool-rules`, `agent-profile`,
`project-pointer`) and short labels (`tool`, `agent`, `project`). Both
return the same results.

Prior to the fix, only canonical was accepted, so a fresh AI running
`--list-types` would see `tool (7 files)` and then run `--type tool`
and get zero results. Now both work. But other tools you wrap might
not — if you build on search.py's output, normalize through
`LABEL_TO_TYPE` in `_vault.py` if you need canonical form.

### When to use which flag

| Task                                    | Best flag                    |
|-----------------------------------------|------------------------------|
| "What do we know about wpscan?"         | `--tag wpscan --brief`       |
| "All WordPress rules"                   | `--tag wordpress --brief`    |
| "Anything about the fresh-AI walkthrough" | `--text fresh-ai`          |
| "Look up rule curl.r3 specifically"     | `--rule curl.r3`             |
| "All tool files"                        | `--type tool-rules --brief`  |
| "Any unread memos"                      | `--type memo --brief`        |
| "Rules tagged either entra OR m365"     | `--any-tag entra --any-tag m365` |

### When `--text` fails

`--text` is literal keyword matching — no stemming, no synonyms. If you
search for "authentication" you won't match a rule that only says "auth".
Try shorter stems and broader terms. If still zero results, check
`--list-tags` — the concept might be a tag you didn't think of.

`--text` searches **rule body fields** (When/Rule/Why/Code), not
frontmatter and not prose outside rule blocks. So text in an incident
narrative won't match `--text` because incidents aren't rule-bearing.

### Reading the `updated:` field

`search.py --brief` shows an `updated:` date for every result. The
value comes from `pick_updated_date(fm)` in `_vault.py`, which tries
fields in order:

```
last_updated → last_session → last_contribution → date → created
```

This means different types show the correct temporal field:
- Topic files show `last_updated`
- Agent profiles show `last_session`
- Project pointers show `last_contribution`
- Incidents and memos show `date` (or `created` as fallback)

If a search result shows an empty `updated:`, that's a schema violation
— the file is missing all five fallback fields. Report it.

---

## Tier 3 — context.py

When you don't know the topic, tag, or any specific keyword:

```bash
python ~/.claude/skills/ai-kb-vault/scripts/context.py \
    --task "how should I handle docker network_mode host in tests"
```

Returns:
- ≤12 ranked file paths with scores (keyword matches against
  filename + tags)
- The task kind (retrieve / contribute / incident / memo / agent_profile
  / meta_retrofit) inferred from the task description
- Hints appropriate to that task kind
- Always-applicable entry/exit ritual reminders

The ranking is cheap keyword scoring, not semantic search. If scores
are low (<3) or files feel wrong, broaden or rephrase the task.

Use `context.py` when:
- You're new to the vault and don't know the tag vocabulary yet
- The task crosses multiple topic areas
- You want a quick sanity check on what exists before starting work

Don't use `context.py` when you already know the exact file — reading
directly is one tool call instead of two.

---

## Tier 4 — Grep (absolute last resort)

```bash
# Bash/zsh
grep -rE "your_pattern" $VAULT/tools/ $VAULT/techniques/ $VAULT/platforms/ \
    $VAULT/dev/ $VAULT/process/ $VAULT/incidents/
```

This is slow, noisy, and bypasses the schema. Only use if:
- The term you want isn't in any tag (rare — check `--list-tags` first)
- You're hunting for a specific string inside code examples that
  `search.py --text` won't match because it searches only rule body fields
- You're auditing the vault itself and need brute-force coverage

After a grep reveals a term that should be discoverable by tag, consider
adding it as a tag to the affected file(s) — retrieval gets better over
time only if tags cover what AIs actually look for.

---

## Anti-patterns (real failure modes from prior sessions)

- **Reading `_INDEX.md` to find topics.** It's 20KB. Construct the path
  instead.
- **Grepping when a tag exists.** `grep -r powershell` when
  `--tag powershell` does the same thing faster and more correctly.
- **Ignoring the `--brief` flag.** `search.py` without `--brief` dumps
  full rule bodies; for a discovery query, `--brief` is the right mode.
- **Using `--text` for frontmatter terms.** `--text` searches rule
  bodies only. Use `--tag` for tags and `--type` for types.
- **Stopping at "No results".** Zero results from `--type tool` doesn't
  mean there are no tools — it means you used the label form before a
  fix landed. Try `tool-rules`.

---

## Context budget guide

- Orient only: ~300 tokens of skill output
- Orient + one tier-1 read: ~300 + 2–4KB (one topic file)
- Orient + search.py + one topic file: ~300 + 1KB + 2–4KB
- Orient + context.py + two topic files: ~300 + 1KB + 4–8KB

Most retrieval sessions should stay under 10KB total. If you're burning
more than that on retrieval alone, you're reading too broadly — narrow
the query.
