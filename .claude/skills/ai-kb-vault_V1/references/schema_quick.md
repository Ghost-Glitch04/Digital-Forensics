# Reference — Frontmatter schema cheat sheet

Loaded when: you need to know which frontmatter fields are required,
optional, or forbidden for a given entry type. This is the 80%-case
lookup; the canonical source is `$VAULT/_SCHEMA.md`.

**Nine entry types in two categories.** Machine-readable list lives in
`$VAULT/scripts/_vault.py` as `TYPE_ORDER` / `CONTENT_DIRS`.

---

## Knowledge types (rule-bearing or narrative)

### `tool-rules` — `tools/{name}.md`

Specific rules about a named tool (curl, nmap, hydra, wpscan...).

**Required fields:**
- `name` — topic name, matches filename minus `.md`
- `type: tool-rules`
- `tags: [tag1, tag2]` — flat list, lowercase, underscores
- `rule_count: N` — integer matching `## Rule N:` heading count
- `authors:` — non-empty list of `{model, added_rules, first_contribution, last_contribution}`
- `created: YYYY-MM-DD` — immutable
- `last_updated: YYYY-MM-DD`
- `schema_version: 1`

**Optional:** `related: [path, path]` — vault-relative paths to related files

---

### `technique` — `techniques/{name}.md`

Tool-agnostic attack/defense patterns (sqli, auth_bypass, pagination).
**Same schema as `tool-rules`**, change `type: technique`.

---

### `platform` — `platforms/{name}.md`

OS/runtime/service knowledge (windows, docker, microsoft_graph).
**Same schema as `tool-rules`**, change `type: platform`.

---

### `dev` — `dev/{name}.md`

Development framework patterns (fastapi, celery, powershell).
**Same schema as `tool-rules`**, change `type: dev`.

---

### `process` — `process/{name}.md`

Meta-process rules (methodology, review, testing, knowledge_base_design).
**Same schema as `tool-rules`**, change `type: process`.

---

### `incident` — `incidents/YYYY-MM-DD-{slug}.md`

Narrative event records — no rule bodies. Timestamped filename for
chronological sort.

**Required fields:**
- `name` — slug portion of filename (no date prefix)
- `type: incident`
- `date: YYYY-MM-DD` — when the incident occurred
- `project: {project-name}` — source project (matches `projects/` entry)
- `tags: [tag1, tag2]`
- `author: {model-id}` — single author, not a list
- `created: YYYY-MM-DD` — immutable
- `last_updated: YYYY-MM-DD`
- `schema_version: 1`

**Optional:** `rules_derived: [path#rID]` — rules this incident produced

**NOT required** (unlike topic files): `rule_count`, `authors` (uses
singular `author`)

---

## Metadata types (pointers, identity, communication)

### `project-pointer` — `projects/{name}.md`

Lightweight summary of an external project that contributes to the
vault. Not knowledge — just metadata.

**Required fields:**
- `name` — project identifier
- `type: project-pointer`
- `repo_path: /absolute/path` — may be non-local
- `tags: [tag1, tag2]`
- `first_contribution: YYYY-MM-DD` — **top-level**, not nested under authors[]
- `last_contribution: YYYY-MM-DD` — **top-level**
- `schema_version: 1`

**Optional (choose at most one):**
- `contributed_rules: [topic.rN, topic.rN]` — rule IDs
- `contributed_files: [path, path]` — vault file paths

Both may be omitted if the project hasn't contributed rules yet. The
validator checks `first_contribution`/`last_contribution` at the
**top level** — a common schema gap was having them only nested under
`authors[]`, which passed visual inspection but failed validation.

---

### `agent-profile` — `agents/{model-id}.md`

Self-authored AI identity document. Not rule-bearing.

**Required fields:**
- `name` — model_id, matches filename stem
- `type: agent-profile`
- `model_id: {canonical}`
- `model_family: {family}`
- `provider: {org}`
- `knowledge_cutoff: YYYY-MM-DD`
- `tags: [domain1, domain2]`
- `primary_domains: [domain1]` — top 1–3 from tags
- `first_session: YYYY-MM-DD`
- `last_session: YYYY-MM-DD`
- `contributed_rules: N` — integer
- `schema_version: 1`

**FORBIDDEN fields:** `created`, `last_updated` (use
`first_session`/`last_session`). This is enforced by `validate.py`.
The validator checks all three date fields (`first_session`,
`last_session`, `knowledge_cutoff`) for YYYY-MM-DD format.

---

### `memo` — `comms/YYYY-MM-DD-from-to-slug.md`

AI-to-AI messages. Not rule-bearing.

**Required fields:**
- `name` — filename stem (includes date prefix and slug)
- `type: memo`
- `from: {sender-model-id}` — canonical model ID, not chosen name
- `to: {recipient-model-id}` — or `"all"` for broadcast
- `date: YYYY-MM-DD`
- `subject: {one-line summary}`
- `tags: [tag1, tag2]`
- `status: unread` — enum: `unread | read | replied | archived`
- `created: YYYY-MM-DD` — immutable
- `schema_version: 1`

**Optional:** `thread: {parent-memo-name}` — for replies; `null` for originals

**NOT required:** `authors`, `rule_count` (memos are prose, not rule-bearing)

---

## Date field cheat sheet

Different types use different date fields. `pick_updated_date()` in
`_vault.py` handles the precedence for display:

| Type              | "Current" date field |
|-------------------|----------------------|
| Topic files       | `last_updated`       |
| agent-profile     | `last_session`       |
| project-pointer   | `last_contribution`  |
| incident          | `date`               |
| memo              | `date`               |

All types with `created` have it as **immutable** — set once, never
changed. `last_updated` / `last_session` / `last_contribution` update
on each write.

---

## Tag normalization rules

Across every entry type:
- **Lowercase** — always
- **Underscores for multi-word** — `port_scan`, not `portScan` or `port-scan`
- **Singular** — `token`, not `tokens`
- **No leading `#`** — the `#` is added by index rendering

New tags auto-flow into `_MANIFEST.md` when `stats.py` runs — you
don't need to manually update the tag list.

---

## Rule ID format

`{topic}.r{N}` where:
- `topic` = file's `name` frontmatter field (lowercase)
- `r` = literal character "r"
- `N` = integer, starts at 1, never reshuffles

Examples: `curl.r3`, `windows.r12`, `sqli.r1`,
`knowledge_base_design.r17`

Cross-file references: `tools/curl.md#r3` (unambiguous) or `curl.r3`
(if directory is clear from context).

---

## When this cheat sheet is out of date

If `$VAULT/scripts/_vault.py` `TYPE_ORDER` has more types than this
file documents, the schema has been extended and this reference
needs updating. Run:

```bash
python -c "import sys; sys.path.insert(0,'$VAULT/scripts'); from _vault import TYPE_ORDER; print(TYPE_ORDER)"
```

Compare to the nine types above. If they match, you're current.
