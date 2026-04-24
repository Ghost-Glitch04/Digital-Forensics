# Lookup Protocol — Detailed Commands and Grep Contract

## What this file is

This file extends `SKILL.md` §2 Lookup Protocol with details that
don't belong inline in the main workflow: deep-lookup commands,
refinement patterns for zero/many/ambiguous results, and the full
grep contract explanation.

Read this file:
- When quick-lookup doesn't match what you're looking for and you need
  broader searches
- When zero-hit or too-many-hit refinement is needed
- When you want to understand *why* the format invariants are shaped
  the way they are (the grep contract)

`SKILL.md` §2 carries the quick-lookup command sequence and the core
workflow. This file deepens that without duplicating it.

---

## Deep lookup commands

When quick-lookup returns nothing useful or you're facing a major
design decision:

```bash
# Search across all AI files for broader matches
grep -rn "keyword" lessons_learned/ai/

# Scan a specific AI file's table of contents without loading it
grep "^### " lessons_learned/ai/{topic}.md

# Check the Foundation tier for cross-project stable rules
sed -n '/^## Foundation/,/^## Reference/p' lessons_learned/INDEX.md \
  | grep -i "keyword"

# Check Reference tier for lessons from completed areas
sed -n '/^## Reference/,/^$/p' lessons_learned/INDEX.md \
  | grep -i "keyword"

# Search memory files for rules that never made it to AI files
grep -rn "keyword" ~/.claude/memories/ 2>/dev/null || true

# If you need the full narrative behind a rule, follow its Source
# pointer to the phase file — read only that section:
grep -A 40 "^### {entry_number}\." lessons_learned/{phase_id}.md
```

**Deep lookup cost:** ~300-600 tokens depending on how many AI files
and phase files you load. Use when a design decision justifies the
cost — not for every task.

---

## Refining zero hits

When a lookup returns nothing, the system may genuinely have no
knowledge on the topic, OR the query terminology doesn't match what
the project uses. Try these before concluding the former:

### 1. Check the tag vocabulary
```bash
grep -A 100 "^## Tag Vocabulary" lessons_learned/INDEX.md | head -60
```
Your keyword may not match the project's canonical tag. Look for
synonyms.

### 2. Try the broader problem class
- `timeout` → `performance`
- `auth` → `security`
- `flaky` → `testing`
- `crash` → `reliability`
- `slow` → `performance` or specific subsystem

### 3. Scan all AI file headings directly
```bash
grep "^### " lessons_learned/ai/*.md | grep -i "keyword"
```
This catches rules where the tag or description didn't match your
keyword but the rule title does.

### 4. Check archived or deprecated content
Some rules may have been superseded. A `grep "[SUPERSEDED]"` against
INDEX.md shows rules that were retired but may point to replacements.

If all four refinement attempts return nothing, the system genuinely
has no knowledge on this topic. Proceed carefully with the work, and
note the gap so the next reflection can fill it. This is the most
common way new rules enter the system — a session notices "we should
have had a rule about X" and captures one.

---

## Refining too many hits

When a lookup returns more than ~5 hits, you can't efficiently read
all of them. Narrow the search:

### 1. Combine keywords with piped grep (AND logic)
```bash
grep -i "keyword1" lessons_learned/INDEX.md | grep -i "keyword2"
```
AND-combining two keywords is the most reliable narrow because it
matches only entries where both concepts are present.

### 2. Search only the Active tier
```bash
sed -n '/^## Active/,/^## Foundation/p' lessons_learned/INDEX.md \
  | grep -i "keyword"
```
Active tier contains recent and most-relevant rules. If the work is
in a current problem area, Active has what you need.

### 3. Narrow to a specific AI file
If the _overview.md grep pointed at 3+ possible files, pick the one
most likely to own the rule and search only that file:
```bash
grep -n "keyword" lessons_learned/ai/{most_likely_file}.md
```

### 4. Use tag-specific grep
If you know the primary tag (first in the tag list), grep for rows
where it leads:
```bash
grep "^| {primary-tag}," lessons_learned/INDEX.md
```
This catches rules where the tag is primary rather than secondary.

---

## Ambiguous hit filtering

When you have 3-5 hits that might apply, you need to determine relevance
cheaply before loading full rule bodies. Each rule body costs ~50-150
tokens; loading all of them wastes budget.

### Cheap relevance filter

Read only these lines from each candidate rule (grep-extract before
loading):

```bash
# For each candidate rule, extract just the filter lines:
sed -n '/^### {Rule Title}/,/^---/p' lessons_learned/ai/{file}.md \
  | grep -E "^\*\*(When|Not when|Symptom):\*\*"
```

**For each rule:**
- If **Not when** condition matches your current task → skip immediately
- If **When** condition clearly doesn't match your context → skip
- If **Symptom** is named and impossible in your context → skip

**Cost per filter pass:** ~20-40 tokens per rule (three short lines).
For 5 candidates, ~100-200 tokens instead of ~500-750 for full
loading.

### What "impossible in your context" means

Rules often describe symptoms that are context-specific: "API returns
403 when token has no scope" is impossible if your task doesn't
involve tokens. "Query returns empty when cache TTL expired" is
impossible if the code path doesn't use caching.

If the symptom description is context-compatible (could plausibly
occur in your task), load the full rule. If incompatible, skip.

---

## The grep contract — why the formats work

The lookup protocol depends on INDEX.md, AI file headings, and
_overview.md being formatted so grep results are immediately useful.
This section explains the load-bearing formats from the retrieval-side
perspective. The formats themselves are defined in
`reference/templates.md` and enforced as invariants in
`reference/invariants.md`.

### INDEX.md rows are pipe-delimited and complete

Every INDEX row carries all metadata on one line:
```
| tags | description | source | type |
```

**Why this matters for retrieval:** A single grep returns rows that
are immediately useful — no "load the row plus surrounding context to
understand it." The tags tell you what the rule is about; the
description tells you what to do or avoid; the source pointer tells
you where to read more; the type tells you whether to expect a When/Rule
entry in an AI file.

**The 120-character description limit** exists because terminal grep
output truncates wide lines. If a description exceeds 120 characters,
the key concept gets cut off in the visible output, and grep hits
become ambiguous. The frontloading rule (key concept first) ensures
that even a truncated 80-character view carries the actionable content.

### AI file headings contain the keyword

`### Imperative title` headings are structured so keyword-based grep
returns a scannable table of contents. The canonical imperative form
("Always use --detection-mode passive", "Never batch insert over 1000
rows") puts the concept at the start of the title.

**Retrieval cost:** `grep "^### " {file}` produces all rule titles
in the file at ~20 tokens each. For a 20-rule file, that's ~400 tokens
to see every rule's title — cheap enough to scan for relevance without
loading the bodies.

### When/Not-when/Symptom lines are filter triggers

The invariant that every AI rule has **When** and optional **Not when**
lines (INV-AI-02, INV-AI-03) isn't just formatting — it's the retrieval
system's relevance filter. Before loading any rule body, a future
session can read just these three lines and decide whether to skip.

**Cost model:**
- Full rule body: ~50-150 tokens
- When/Not-when/Symptom lines only: ~20-40 tokens
- Skip decision: 0 tokens (just don't load)

For 5 candidate rules, the difference is ~300 tokens saved when 4 of
5 are filtered out by Not-when or impossible-Symptom. This is the
primary mechanism keeping lookup costs proportional to relevance, not
to total hit count.

### Companions are pre-computed related-rule lookups

Rules with mutual `**Companions:**` links encode the cross-file
dependencies that would otherwise require broad searching. A rule
about database migrations that depends on the CI pipeline rule links
to it directly; the session loading one loads the other with a
single targeted grep.

**Without companions:** Session loads rule A, realizes it needs a
related rule about B, runs a new grep for B, may or may not find the
right one.

**With companions:** Session loads A, sees `**Companions:** ci.md →
"Rule Title"`, loads that specific rule. One targeted read per
companion.

### _overview.md is the file router

```
| [ai-file.md](ai-file.md) | rule_count | keywords |
```

Before touching any AI file, `grep -i "keyword" _overview.md` tells
you which file(s) to load. Keywords are chosen to be descriptive and
non-overlapping — if `testing` appears in only one file's keywords,
grep unambiguously routes there.

**Retrieval cost for file routing:** ~20 tokens to grep _overview.md;
0 tokens if no hits (the concept isn't covered by any file); ~3-6
files loaded if multiple hits (then apply the AI-file-heading scan).

### Why the whole contract exists

Every format choice in INDEX.md, AI files, and _overview.md is made
so that retrieval cost is proportional to relevance rather than to
total knowledge volume. A `lessons_learned/` directory with 1000
rules should cost the same to query as one with 100 rules *for
retrieval of the same specific knowledge*. The grep contract is the
mechanism that delivers this scaling property.

If any invariant drifts, the contract breaks for that drift's
category — grep hits start producing malformed output, or filter
lines stop filtering, or keyword routing starts missing. Check 13
catches most of these; Check 16 catches variant-level cases.

---

## Lookup pattern examples

Worked examples of the protocol applied to realistic queries.

### Example 1 — Specific technology lookup

**Task:** About to modify the wpscan integration harness.

**Quick lookup:**
```bash
grep -i "wpscan" lessons_learned/INDEX.md
```

Returns ~12 hits. Too many.

**Narrow:**
```bash
grep -i "wpscan" lessons_learned/INDEX.md | grep -i "timeout"
```

Returns 2 hits — both about 60s probe deadlines.

**Route to AI file:**
```bash
grep -i "wpscan" lessons_learned/ai/_overview.md
```

Points at `wpscan.md`.

**Filter candidates:**
```bash
grep -E "^### " lessons_learned/ai/wpscan.md
```

Returns 12 rule titles. Scan for relevance to timeout work — 3
candidates.

**Cheap filter on candidates:**
```bash
for rule in "detection-mode" "enumerate" "http-timeout"; do
  sed -n "/### .*${rule}/,/^---/p" lessons_learned/ai/wpscan.md \
    | grep -E "^\*\*(When|Not when):\*\*"
done
```

Two of three have clearly matching When clauses. Load those two
fully. Skip the third.

**Total cost:** ~5 grep calls, ~300 tokens of output, 2 full rules
loaded. Actionable rules in hand before writing code.

### Example 2 — Cross-cutting design decision

**Task:** Designing a retry mechanism for API calls; unsure whether
the project has a preferred pattern.

**Broad lookup:**
```bash
grep -i "retry" lessons_learned/INDEX.md
```

Returns 8 hits across different technologies.

**Route to likely AI files:**
```bash
grep -i "retry" lessons_learned/ai/_overview.md
```

Points at `http.md`, `resilience.md`, and `testing.md`.

**Scan headings in each:**
```bash
grep "^### " lessons_learned/ai/{http,resilience,testing}.md
```

Identifies 3 rules that look directly relevant.

**Check Foundation tier for cross-project patterns:**
```bash
sed -n '/^## Foundation/,/^## Reference/p' lessons_learned/INDEX.md \
  | grep -i "retry"
```

Returns one Foundation rule — retry-with-backoff pattern used across
4 prior phases. Load this first (most-proven); then the 3 topic-
specific rules.

**Total cost:** ~6 grep calls, ~400 tokens of output, 4 rules loaded.
Informed design decision possible.

### Example 3 — Zero-hit refinement

**Task:** Adding an LDAP integration; query for existing LDAP lessons.

**Quick lookup:**
```bash
grep -i "ldap" lessons_learned/INDEX.md
```

Returns nothing.

**Check tag vocabulary:**
```bash
grep -A 100 "^## Tag Vocabulary" lessons_learned/INDEX.md | head -60
```

No `ldap` tag, but `auth` and `directory-services` appear.

**Try broader class:**
```bash
grep -i "directory" lessons_learned/INDEX.md
grep -i "auth" lessons_learned/INDEX.md
```

`auth` returns 6 hits; `directory` returns 2. Scan both.

**Scan AI file headings for LDAP-specific concepts:**
```bash
grep "^### " lessons_learned/ai/*.md | grep -iE "ldap|directory|bind"
```

Finds one rule in `auth.md` about connection binding that's adjacent
to LDAP concerns.

**Conclusion:** System has no specific LDAP knowledge, but related
auth patterns are applicable. Proceed with the related patterns; note
during reflection that an LDAP-specific rule emerged from this work
if one did.

---

## When the lookup protocol is wrong

Three cases where strict lookup-before-work is counterproductive:

**1. Routine cosmetic changes.** Formatting, documentation typos,
dependency bumps with no behavioral change. The lookup cost exceeds
the task cost.

**2. Exploratory / prototype work.** When the goal is to rapidly
validate a hypothesis, not to produce production code, lookup can
slow the feedback loop. Document lessons after the prototype lands;
don't front-load knowledge retrieval for work you might throw away.

**3. When lookup surfaces conflicting rules.** If you get two rules
that directly contradict each other, don't try to reconcile them
mid-lookup. Load both, note the conflict, and decide which applies to
your context. The conflict itself is a signal for a future
reflection: either one rule is wrong (supersession candidate) or they
address different subcases (refinement candidate with Not-when
boundaries).

In all three cases, the judgment call is: *does the lookup cost
match the risk of missing a relevant rule?* For low-stakes or
exploratory work, no. For work that modifies production logic, yes.

---

## Change control

Changes to the lookup protocol:

- **Adding a new refinement pattern** (e.g., a new "too many hits"
  narrowing technique): No version bump. Record as
  drift-formalization in `skill_dev_log.md`. New techniques emerge
  with use.
- **Changing the cheap relevance filter** (the When/Not-when/Symptom
  three-line filter): Version bump if the mandatory filter lines
  change. This is the heart of the cost model.
- **Changing the grep contract invariants:** Version bump — these
  are AI file and INDEX invariants, and changing them affects
  every retrieval.
- **Adjusting the worked examples:** No version bump. Replace old
  examples with more representative ones as the repo's usage patterns
  evolve.
