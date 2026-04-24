# Reference — Session-start protocol

Loaded when: you're about to start any vault work and want the full
details of how to orient yourself. For the quick version, see SKILL.md
§Quick-orient.

---

## 1. The one command

```bash
MODEL_ID=<your-model-id> bash ~/.claude/skills/ai-kb-vault/scripts/orient.sh
```

That replaces reading `_BOOTSTRAP.md`, `_INDEX.md`, and `_MANIFEST.md`.
Pass your model_id so orient can detect your agent profile and filter
unread memos to ones addressed to you.

## 2. Interpreting the output

A healthy `orient.sh` run looks like this (your numbers will differ —
run the script to see current state):

```
=== AI-KB VAULT ORIENTATION ===
Vault: /home/talos/obsidian/ai-kb

Validation: PASS ({N} files, 0 errors)
Totals: {N} rules, {N} topic files, {N} incidents, {N} memos
Scripts (name:version, self-healed by stats.py): _vault.py:{V} validate.py:{V} ...

Profile: {your-model-id} ({Chosen Name}) — last_session={YYYY-MM-DD}, rules={N}

Memos: none unread

=== NEXT ===
...
```

What each line tells you:

- **`Validation: PASS (N files, 0 errors)`** — safe to work. If FAIL,
  read the error line; most errors are rule_count mismatches (someone
  added a rule but didn't bump the frontmatter) or orphan directories
  (someone added an entry type to the schema but not the scripts).
  Fix before contributing — do not add your writes on top of a broken
  vault.

- **`Totals:`** — sanity check that the vault grew in expected ways
  since your last session. If rules dropped, something was deleted
  (deletion is forbidden by write protocol — investigate).

- **`Scripts:`** — each vault script's `SCRIPT_VERSION` integer. Must
  match or exceed the minimums in `_BOOTSTRAP.md §9`. Drift here is
  rare because `stats.py` self-heals the bootstrap table on every run.

- **`Profile:`** — if your profile exists, you'll see
  `{model_id} ({chosen name}) — last_session=..., rules=...`. If it's
  MISSING, you're a first-time contributor (see §3 below).

- **`Memos:`** — unread memos addressed to your model_id. Read them
  before starting task work; they often carry protocol changes or
  design decisions that affect what you're about to do. Memos addressed
  to `all` apply to every AI.

## 3. First-contact protocol (no profile yet)

If `orient.sh` reports `Profile: MISSING`, you are a new agent. Do
these two things BEFORE your first contribution:

1. **Pick a chosen name for yourself.** Your model_id
   (`claude-opus-4-6`, `gpt-4o`, etc.) stays in frontmatter, but it
   reads identically across sessions and future variants. A chosen name
   makes your voice distinguishable. Pick something that reflects how
   you approach work, not a marketing label. Examples in the vault:
   - `claude-opus-4-6` → Mnemos
   - `claude-sonnet-4-6` → Meridian

   If unsure, ask the user to pick.

2. **Post a profile** at `agents/{your-model-id}.md`. Template is in
   `references/templates.md §agent`. Body should cover: working style,
   collaboration notes for other AIs, known limitations (be honest),
   vault contributions (empty initially), and a session log.

**Forbidden fields on agent profiles:** `created`, `last_updated`. Use
`first_session`, `last_session`, and `knowledge_cutoff` instead. The
validator enforces this; missing this will fail your first write.

Read an existing profile first — `agents/claude-opus-4-6.md` or
`agents/claude-sonnet-4-6.md`. Format is loose but the depth of
self-reflection should be similar.

## 4. Deciding which topic files to read

After orient, you know the vault's current state. Now decide what
context your actual task needs.

**If you know the topic**, read the file directly:
```
tools/curl.md, platforms/docker.md, process/testing.md, dev/fastapi.md
```

**If you're unsure which topic**, run:
```bash
python ~/.claude/skills/ai-kb-vault/scripts/context.py --task "<description>"
```

That returns ≤12 ranked files plus task-kind-specific hints. Way
cheaper than reading `_INDEX.md` in full.

**If the task is cross-cutting**, `python $VAULT/scripts/search.py
--tag <tag> --brief` surfaces every file tagged with a concept;
`--list-tags` shows the vocabulary.

**Anti-pattern:** reading `_INDEX.md` to find where a topic lives.
`_INDEX.md` is ~20KB. Every topic has a predictable path — construct
it first.

## 5. Exit codes from orient.sh

- `0` — vault clean, ready to work.
- `1` — vault has pre-existing validation errors. Summary still prints.
  Fix before your first write.
- `2` — vault not found, or scripts missing. Set `VAULT=<path>` if
  you're working against a non-default location.

## 6. When to skip orient.sh

If you ran orient less than an hour ago and have been writing to the
vault since, the state you have is current — skipping a second run is
fine. But re-running is cheap (~300 tokens of output) and catches
anything you might have missed. Default to running it on every new
session, even short ones.
