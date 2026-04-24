# Integration Tracking — Contracts, Consumers, and Change Impact

Reference for tracking function contracts and their consumers across a codebase so that changes to a contract surface their full downstream effect *before* the edit lands, not after.

**Load this file when:** you are about to change a function's parameters, its return type or return object shape, or rename a shared variable, constant, or configuration key — especially when the function is called from more than one file. Also load when resuming work on a project that already carries `<CONTRACT>` or `<USES>` markers, or a `.integration-map.md` file at its root.

**Do not load this file for:** single-file utility scripts, minimal scaffolds, or short one-off scripts with no cross-file consumers. Integration tracking is ceremony for those — see `minimal_scripts.md`.

---

## The Problem This File Solves

Most integration regressions in Claude Code sessions follow the same three-pass pattern:

- **Pass 1.** A function's contract is changed. The obvious consumers — same file, same module — are updated. The change is declared complete.
- **Pass 2.** Tests or runtime reveal a consumer that was missed. The session fixes it.
- **Pass 3.** Fixing Pass 2 reveals a *transitive* consumer — something that consumed the thing that consumed the contract. Another fix.

Passes 2 and 3 are preventable. They happen because Pass 1 committed to the change before enumerating the full consumer set. This file specifies a discipline that front-loads enumeration: markers at definition and consumption sites make consumers grep-findable, a Change Impact Protocol requires the consumer set to be fully classified before the edit, and an Integration Map captures the state of the system so drift is mechanically detectable.

The discipline is scoped to three failure modes where it pays for itself. Other integration concerns (moved files, renamed modules, import restructuring) are out of scope — they are better handled by the language's own tooling.

---

## The Three Failure Modes

All three are contract changes at function boundaries. They share a structural shape — a *definition site* (one place) that changes in a way that breaks *consumption sites* (many places) — but they differ in how grep-friendly they are, which determines the discipline needed.

**Signature change.** Parameters added, removed, reordered, renamed, or retyped. Function name is usually distinctive enough to grep. What grep *cannot* tell you is whether each call site is affected by the specific parameter that changed — partial signatures (named args, splatted hashtables, `**kwargs`) hide the dependency. Discipline needed: explicit parameter enumeration in the contract, consumer classification per-parameter.

**Return type or shape change.** The function's return value changes type, drops a field, renames a field, or changes the semantics of a field. This is the worst of the three to grep for. If a function returned `@{Name; Id}` and now returns `@{Name; ObjectId}`, every caller that reads `.Id` is broken, but nothing in the call syntax ties `.Id` back to the function that produced it. Discipline needed: `<USES fields="...">` markers at consumers that read specific return fields, so the invisible-to-grep dependency becomes grep-visible.

**Variable or constant rename.** A shared module-level variable, a configuration key, or an exported constant is renamed or its value is changed in a breaking way. Easy to verify mechanically (the rename is syntactic), but has the worst false-positive rate — short names collide with substrings, and the same name may be used for unrelated locals in different scopes. Discipline needed: wrap the declaration in a CONTRACT block so the grep anchor is the marker, not the raw name.

The rest of this file specifies the discipline. Three artifacts do the work: **CONTRACT blocks** above definitions, **USES markers** at consumption sites that depend on return shape, and the **Integration Map** at project root that collates them both.

---

## Format Contract

These are the grep-stable formats every artifact in this system uses. They are **invariants**: format drift silently breaks every downstream consumer of the format, so changes to these formats require a deliberate version bump, not a casual edit. The pattern is the same one `log_vocabulary.md` uses for log prefixes — the format *is* the contract, and the contract is how the system survives across sessions.

Every format below has a grep pattern. Memorize the patterns; they are the primary tool for navigating a codebase that uses this system.

### Invariant I1 — CONTRACT block opening

```
# <CONTRACT id="NAME" version="N" scope="public|internal">
```

**Grep pattern:** `<CONTRACT id="`

**Mandatory attributes:** `id`, `version`, `scope`. All three are always present.

- `id` — the function's name exactly as defined. Case-sensitive.
- `version` — integer starting at `1`. Incremented on any breaking change.
- `scope` — `public` (strict enforcement) or `internal` (advisory enforcement). See the Change Impact Protocol for what strict and advisory mean.

**Optional attribute:** `since` — version of the enclosing project where this contract first appeared. Useful for external-facing contracts.

### Invariant I2 — CONTRACT block closing

```
# </CONTRACT>
```

**Grep pattern:** `</CONTRACT>`

Exactly one closing tag per opening tag. The closing tag is required even though it adds a line — it anchors the end of the block for grep-based range extraction (`awk '/CONTRACT id=/,/\/CONTRACT/'`).

### Invariant I3 — USES marker

```
# <USES contract="NAME" version="N" fields="f1,f2">
```

**Grep pattern:** `<USES contract="`

Placed immediately above a consumer call site that depends on the contract's return shape. A single-line marker, not a block.

**Mandatory attributes:** `contract`, `version`.

**Optional attribute:** `fields` — comma-separated list of return-shape fields the consumer reads. Omit only if the consumer reads no fields from the return (calls the function for its side effects or uses the whole return as an opaque value).

**When USES markers are mandatory:** any consumer that reads specific fields off the return value of a cross-file-called `public` contract. This is the rule that makes return-shape changes grep-visible.

**When USES markers are optional but recommended:** consumers of `internal` contracts, consumers of `public` contracts that use only the whole return object. If the consumer ever starts reading specific fields, promote to a full USES marker at that point.

### Invariant I4 — Integration Map contract heading

```markdown
## <contract:NAME>
```

**Grep pattern:** `^## <contract:`

The `<contract:NAME>` wrapper is required. A plain `## NAME` heading would collide with narrative prose in the same file; the angle-bracket wrapper is distinctive and collision-free.

### Invariant I5 — Integration Map consumer entry

```
- CONSUMER: path/to/file.ext:LINE — fields: f1,f2 — via: <USES|call>
```

**Grep pattern:** `^- CONSUMER:`

**Mandatory fields:** path, line number, `via`. The `via` value is either `USES` (an explicit USES marker exists at that site) or `call` (the consumer calls the function without a USES marker).

**Optional field:** `fields` — omitted if the consumer does not read return fields.

### Invariant I6 — Contract Change Log entry opening

```markdown
### <change:NAME:YYYY-MM-DD:vN→vN+1>
```

**Grep pattern:** `^### <change:`

Dates are ISO format. The version transition uses the Unicode arrow (`→`, U+2192) — not `->`. This is a small decision that keeps the format unambiguous for grep and prevents false matches against code that uses `->` for other purposes.

### Governance Rule for Format Changes

These invariants must not drift. If a format change is genuinely needed:

1. Propose it in the skill_development log (V5.1+).
2. Bump the contract-vocabulary version (a new top-level version in this file).
3. Migrate all existing markers in a single commit — do not allow mixed-format states.
4. Update the helper scripts (`verify-integrations.ps1`, `verify-integrations.sh`) in the same commit.

A codebase with half its markers in the old format and half in the new one is worse than either format alone. The format's value is uniformity; half-uniform is zero value.

---

## Language-Specific Marker Syntax

The format contract above is language-agnostic — the tags are distinctive textual substrings that work in any file type supporting line comments. The per-language notes below cover the specifics of how the block integrates with each language's existing unit-header conventions.

### PowerShell

CONTRACT blocks are placed immediately above the existing Unit header comment block, with no blank line between them. The tags are PowerShell line comments (`#`).

```powershell
# <CONTRACT id="Get-UserToken" version="1" scope="public">
#   PARAMS:
#     UserId    [string]   required
#     Scope     [string[]] required
#     TenantId  [string]   optional, default=$script:DefaultTenant
#   RETURNS: [PSCustomObject]
#     Token      [string]   bearer token
#     ExpiresAt  [datetime] UTC expiry
#     Scopes     [string[]] granted scopes (may differ from requested)
#   THROWS: AuthenticationException, NetworkException
#   SIDE_EFFECTS: writes to $script:TokenCache
# </CONTRACT>
# ============================================================
# UNIT: Get-UserToken
# Purpose : Obtain a bearer token for the specified user/scope
# Inputs  : UserId, Scope, TenantId
# Outputs : Token object (see CONTRACT)
# Depends : $script:DefaultTenant (module state)
# ============================================================
function Get-UserToken {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string[]]$Scope,
        [string]$TenantId = $script:DefaultTenant
    )
    # ...
}
```

**Field convention:** PARAMS and RETURNS field keys use **PascalCase** matching PowerShell's native parameter naming. This deviates from the log format contract's `lowercase_snake_case` rule — contracts are read by humans writing PowerShell, and matching the language's convention wins over cross-language uniformity for this specific case.

**USES markers:**

```powershell
# <USES contract="Get-UserToken" version="1" fields="Token,ExpiresAt">
$auth = Get-UserToken -UserId $u -Scope @('read')
if ((Get-Date) -lt $auth.ExpiresAt) { $headers['Authorization'] = "Bearer $($auth.Token)" }
```

### Bash

CONTRACT blocks in Bash are sequences of `#` line comments, identical to the PowerShell structure. The important difference is that Bash functions do not have typed returns in the way PowerShell and Python do — the CONTRACT fields are adapted accordingly, following the substitution policy in `log_vocabulary.md` for `STACK_TRACE`.

```bash
# <CONTRACT id="fetch_user_token" version="1" scope="public">
#   PARAMS (positional):
#     $1  user_id   required
#     $2  scope     required (comma-separated)
#     $3  tenant    optional, defaults to $DEFAULT_TENANT
#   EXIT_CODES:
#     0   success, token written to stdout
#     10  missing required arg
#     30  authentication failed
#     50  network error after retries exhausted
#   STDOUT: single line — "TOKEN|EXPIRES_AT|SCOPES"
#           TOKEN       bearer token string
#           EXPIRES_AT  UTC epoch seconds
#           SCOPES      comma-separated granted scopes
#   STDERR: diagnostic messages only; never parsed by consumers
#   SIDE_EFFECTS: writes to $TOKEN_CACHE_FILE if set
# </CONTRACT>
# ============================================================
# UNIT: fetch_user_token
# ...
# ============================================================
fetch_user_token() {
    local user_id="$1" scope="$2" tenant="${3:-$DEFAULT_TENANT}"
    # ...
}
```

**Substitutions for Bash:**

- `RETURNS` becomes `EXIT_CODES` + `STDOUT` + (optional) `STDERR`. Bash functions communicate through these three channels; a consumer may depend on any of them.
- `THROWS` becomes part of `EXIT_CODES`. The existing Error Code Reference Block in `bash.md` already documents exit codes; the CONTRACT block's `EXIT_CODES` field lists the subset that are part of the function's contract (as opposed to script-wide codes like `99` for unhandled errors).
- `SIDE_EFFECTS` becomes *more* important in Bash, not less — functions frequently communicate through environment variables, files, and process state rather than return values. Document every file path written, every env var set, every global modified.

**USES markers:**

```bash
# <USES contract="fetch_user_token" version="1" fields="TOKEN,EXPIRES_AT">
IFS='|' read -r token expires scopes < <(fetch_user_token "$user" "read")
```

For Bash, the `fields` attribute refers to the pipe-delimited stdout fields in order. Consumers that parse stdout differently (e.g., `jq` on a JSON stdout) document their parsing convention in the CONTRACT block's STDOUT field and match the USES marker accordingly.

### Python

Python CONTRACT blocks are sequences of `#` line comments placed above decorators (which are part of the function, not above them). Field keys use **lowercase_snake_case** matching Python's PEP 8 conventions.

```python
# <CONTRACT id="get_user_token" version="1" scope="public">
#   params:
#     user_id    [str]        required
#     scope      [list[str]]  required
#     tenant_id  [str|None]   optional, default=None
#   returns: dict
#     token       [str]        bearer token
#     expires_at  [datetime]   UTC expiry
#     scopes      [list[str]]  granted scopes (may differ from requested)
#   raises: AuthenticationError, NetworkError
#   side_effects: updates module-level _token_cache
# </CONTRACT>
# ============================================================
# UNIT: get_user_token
# Purpose : Obtain a bearer token for the specified user/scope
# Args    : user_id, scope, tenant_id
# Returns : Dict with keys token, expires_at, scopes
# Depends : _token_cache (module state), DEFAULT_TENANT (config)
# ============================================================
@retry_on_network_error
def get_user_token(
    user_id: str,
    scope: list[str],
    tenant_id: str | None = None,
) -> dict:
    ...
```

**USES markers:**

```python
# <USES contract="get_user_token" version="1" fields="token,expires_at">
auth = get_user_token(user_id, ["read"])
if datetime.utcnow() < auth["expires_at"]:
    headers["Authorization"] = f"Bearer {auth['token']}"
```

### Cross-Language Differences Summary

| Aspect | PowerShell | Bash | Python |
|---|---|---|---|
| Field key case | PascalCase | UPPERCASE | lowercase_snake_case |
| Typed returns | Yes (`.NET` types) | No (substituted with EXIT_CODES + STDOUT) | Yes (type hints) |
| SIDE_EFFECTS importance | Standard | Elevated (primary comm channel) | Standard |
| Decorator placement | N/A | N/A | CONTRACT above decorators |
| Comment syntax | `#` line | `#` line | `#` line |

---

## The Change Impact Protocol

When changing any `<CONTRACT>`, follow this protocol before the edit. The protocol is eleven steps; the first six happen before any code is edited.

### Step 1 — Identify

Name the contract exactly. State the change type: signature, return-shape, rename, or combination. Note the current version number.

### Step 2 — Enumerate

Run the four enumeration queries from the Integration Grep Protocol (section 6):

- Q2: find all USES markers for this contract
- Q3: find all call sites of this contract by name
- Q4: find consumers that read specific return fields (only for return-shape changes)
- Q5: list the contract's entry in `.integration-map.md`

The union of these query results is the candidate consumer set.

### Step 3 — Classify

For each consumer in the candidate set, mark exactly one of:

- **AFFECTED** — will break under the new contract; requires update.
- **UNAFFECTED** — will continue to work unchanged. Common reasons: uses only the parts of the contract that are not changing; calls the function but does not read the changed field.
- **UNCLEAR** — cannot determine without reading the call site in detail, or the consumer's behavior under the new contract is ambiguous.

A three-state classification is deliberate. Two states (affected/unaffected) force false certainty; UNCLEAR is the honest answer when the information is not yet available. UNCLEAR entries do not block classification — they block *proceeding past step 5*.

### Step 4 — Resolve UNCLEAR entries

For each UNCLEAR entry, take exactly one of three actions:

1. Read the consumer's code until the classification is clear; reclassify as AFFECTED or UNAFFECTED.
2. Ask the user for guidance if the consumer is ambiguous for reasons that cannot be resolved from code alone (semantic ambiguity, unknown intent).
3. If the consumer is deprecated or slated for removal, reclassify as AFFECTED and note the intent in the change plan.

**Exit criterion:** zero UNCLEAR entries remain. No exceptions for public contracts.

### Step 5 — Tiered enforcement gate

The protocol's strictness depends on the contract's `scope` attribute:

- **`scope="public"` — strict.** All UNCLEAR entries must be resolved (step 4 completed for every one). The edit does not proceed until every consumer is AFFECTED or UNAFFECTED.
- **`scope="internal"` — advisory.** Remaining UNCLEAR entries require explicit acknowledgment from the user, logged verbatim in the Contract Change Log entry. The acknowledgment names each unresolved consumer and the reason for proceeding anyway.

The tiered enforcement matches the skill's broader pattern: strict rules where the blast radius is large, advisory rules where rapid iteration matters more than completeness.

### Step 6 — Plan

State in plain text:

- What the new contract will be (new version number, new PARAMS/RETURNS/etc.)
- The list of AFFECTED consumers and what each one needs
- The order of edits (definition first or consumers first, depending on language tooling and whether the change is backward-compatible at the signature level)

If the plan cannot be stated concisely — if AFFECTED is more than a dozen consumers and the changes are heterogeneous — that is a signal to split the change into multiple smaller contract revisions, not a signal to proceed with a sprawling plan.

### Step 7 — Edit the definition

Change the function. Update the CONTRACT block in the same commit:

- Bump `version` by one.
- Update PARAMS, RETURNS, THROWS, SIDE_EFFECTS to reflect the new contract exactly.
- The CONTRACT block reflects what is, not what was. Historical information lives in the Contract Change Log, not in the CONTRACT block.

### Step 8 — Update consumers

For each AFFECTED consumer, make the required change. Update the consumer's USES marker (if any) to the new `version="N+1"`. Consumers that did not have a USES marker and are reading return fields should receive one during this step.

### Step 9 — Update the Integration Map

Edit `.integration-map.md` at project root:

- Update the contract's `## <contract:NAME>` section with the new version, new PARAMS/RETURNS summary.
- Update each CONSUMER entry that changed file:line or fields list.
- Add CONSUMER entries for any consumer that received a new USES marker in step 8.

### Step 10 — Log

Append a new entry to the Contract Change Log section of `.integration-map.md`:

```markdown
### <change:NAME:YYYY-MM-DD:vN→vN+1>
- **Change type:** signature | return-shape | rename | combination
- **Summary:** one-sentence description of what changed
- **Consumers affected:** count + brief list
- **Enforcement:** strict (public) | advisory (internal)
- **Unresolved acknowledgments:** (internal-only) list any UNCLEAR consumers that were explicitly waived, with reason
```

### Step 11 — Verify

Run the drift-detection helper for the language in use:

- PowerShell: `.\reference\integration-helpers\verify-integrations.ps1`
- Bash: `./reference/integration-helpers/verify-integrations.sh`

The helpers check all three drift directions (code ahead of map, map ahead of code, version mismatch) and emit `CONTRACT_DRIFT` log prefixes on any mismatch. The edit is not complete until the helper exits clean.

---

## Integration Grep Protocol

This protocol defines the grep queries that make the Change Impact Protocol mechanical. Each query has a name (Q1-Q6), a purpose, and a canonical form. The queries compose — typical workflows run Q1 to find the definition, then Q2+Q3+Q4 to build the consumer set, then Q5 to cross-check against the Integration Map.

The queries are language-aware through file-extension filtering but otherwise language-agnostic. The markers themselves (`<CONTRACT>`, `<USES>`, `## <contract:`) are distinctive enough that false positives are rare.

### Q1 — Find a contract's definition

```bash
grep -rn '<CONTRACT id="NAME"' \
    --include='*.ps1' --include='*.sh' --include='*.py' \
    --include='*.psm1' --include='*.bash'
```

**Purpose:** jump to the authoritative definition site of a contract by name.

**Expected output:** exactly one hit per contract. More than one hit indicates duplicate contract IDs — a bug to fix before proceeding.

### Q2 — Find all USES markers for a contract

```bash
grep -rn '<USES contract="NAME"' \
    --include='*.ps1' --include='*.sh' --include='*.py'
```

**Purpose:** enumerate the explicit consumers — consumers that have declared their dependency on this contract through a USES marker.

**Note:** this query misses consumers that call the function but have no USES marker. Always pair with Q3.

### Q3 — Find all call sites by name

For PowerShell:
```bash
grep -rn '\bGet-UserToken\b' --include='*.ps1' --include='*.psm1'
```

For Bash:
```bash
grep -rn '\bfetch_user_token\b' --include='*.sh' --include='*.bash'
```

For Python:
```bash
grep -rn '\bget_user_token\b' --include='*.py'
```

**Purpose:** catch every call site, including those without USES markers. Paired with Q2 to build a complete candidate consumer set.

**Post-filter:** remove hits inside the definition file itself (those are the definition and internal calls, not cross-file consumers) unless the definition file legitimately contains self-referential consumers.

### Q4 — Find consumers that read specific return fields

This query is the reason USES markers with `fields` attributes exist. Without USES markers, return-shape consumers are invisible to grep — no syntactic marker ties `.FieldName` back to the contract that produced it. With USES markers, the query is direct:

```bash
grep -rn '<USES contract="NAME".*fields=".*FIELD_NAME' \
    --include='*.ps1' --include='*.sh' --include='*.py'
```

**Purpose:** for return-shape changes, find exactly the consumers that depend on the changing field.

**Fallback when USES markers are incomplete:** grep for property accesses on variables produced by the contract's function call. This is best-effort and produces false positives; it is a last resort when retrofitting a codebase that does not yet have full USES-marker coverage.

### Q5 — Read the Integration Map entry

```bash
awk '/^## <contract:NAME>/,/^## <contract:/' .integration-map.md
```

**Purpose:** read the contract's current recorded state — version, consumer list, last change date — from the Integration Map.

The awk range extends from this contract's heading to the next contract heading. For the last contract in the file, the range is open-ended; adjust the second pattern to `^---` or end of file as needed.

### Q6 — Detect drift (markers versus Integration Map)

Markers-ahead-of-map (new USES markers not yet registered):

```bash
comm -23 \
  <(grep -rhn '<USES contract="' --include='*.ps1' --include='*.sh' --include='*.py' | \
    sed -E 's/.*<USES contract="([^"]+)".*/\1/' | sort -u) \
  <(grep -oP '^## <contract:\K[^>]+' .integration-map.md | sort -u)
```

**Expected output when clean:** empty. Any output is a contract referenced in code but absent from the map.

Map-ahead-of-code (CONSUMER entries pointing to stale locations):

```bash
while IFS= read -r entry; do
    file=$(echo "$entry" | sed -E 's/^- CONSUMER: ([^:]+):.*/\1/')
    [[ -f "$file" ]] || echo "STALE: $entry"
done < <(grep '^- CONSUMER:' .integration-map.md)
```

**Expected output when clean:** empty. Any output is a CONSUMER entry pointing to a file that no longer exists.

Version mismatch (USES markers referencing an outdated contract version):

```bash
# Extract id+version pairs from every USES marker:
grep -rhE '<USES contract="' --include='*.ps1' --include='*.sh' --include='*.py' | \
    awk -F'"' '{print $2, $4}' | sort -u > /tmp/uses_versions.txt

# Extract id+version pairs from every CONTRACT definition:
grep -rhE '<CONTRACT id="'  --include='*.ps1' --include='*.sh' --include='*.py' | \
    awk -F'"' '{print $2, $4}' | sort -u > /tmp/contract_versions.txt

# Any id+version pair in uses_versions but not in contract_versions is a mismatch:
comm -23 /tmp/uses_versions.txt /tmp/contract_versions.txt
```

**Expected output when clean:** empty. Any output is a USES marker declaring a version that no longer matches the current CONTRACT. Note that this query assumes marker field order is exactly `id="..." version="..."` — which is part of the Format Contract (invariants I1 and I3) and must not be reordered.

All three drift checks run automatically inside `verify-integrations.ps1` and `verify-integrations.sh`. Run the queries manually when debugging a specific drift report; run the helpers as the final verification step of the Change Impact Protocol.

### Composition Patterns

The queries combine into predictable workflows:

- **Starting a change:** Q1 → Q5 (understand definition and current recorded state).
- **Enumerating consumers:** Q2 ∪ Q3, deduplicated by file:line.
- **Return-shape changes specifically:** add Q4 to the enumeration for the changing field(s).
- **Pre-commit verification:** Q6 (all three directions) as the final gate.

### Performance Notes

The queries above are written in portable grep for maximum environment compatibility — they will run on any system with GNU grep, macOS grep, or busybox grep. Three opt-in improvements apply where the tools are available and the context warrants.

**Ripgrep (`rg`) as a faster alternative.** On codebases where scan time matters (large projects, tight audit loops, CI pipelines), ripgrep is typically 2–10x faster than grep and respects `.gitignore` by default, so manual directory exclusions are rarely needed. The queries translate almost directly:

```bash
# grep:
grep -rn '<CONTRACT id="NAME"' --include='*.ps1' --include='*.sh' --include='*.py'

# ripgrep equivalent:
rg -n '<CONTRACT id="NAME"' -t ps1 -t sh -t py
```

The helper scripts (`verify-integrations.ps1`, `verify-integrations.sh`) deliberately use grep/find to stay portable across environments without a ripgrep dependency. Users who want ripgrep-backed verification should wrap or fork the helpers rather than editing them in place — keeping the upstream versions portable preserves the skill's cross-environment guarantee.

**Fixed-string mode (`-F` / `--fixed-strings`) for literal queries.** Q1 and Q2 search for literal strings with a single interpolated identifier — no regex features are actually used. Passing `-F` skips the regex engine entirely:

```bash
# Equivalent, marginally faster for literal-match queries:
grep -Fn '<CONTRACT id="NAME"' --include='*.ps1' --include='*.sh' --include='*.py'
```

The speedup is small per-query but compounds in scripted audit pipelines that run many queries in sequence. Free to adopt; no downside. Does not apply to Q3 (word-boundary regex) or Q4 (pattern with wildcard) — those genuinely need the regex engine.

**`--exclude-dir` for projects with heavy dependency trees.** The documented queries omit directory exclusions to keep the minimal form readable. Manual invocation on projects with `node_modules/`, `vendor/`, `.venv/`, or similar should add exclusions:

```bash
grep -rn '<CONTRACT id="NAME"' \
    --include='*.ps1' --include='*.sh' --include='*.py' \
    --exclude-dir='{.git,node_modules,vendor,.venv,logs}'
```

The helper scripts already exclude `logs/` and `.git/` internally (see the `Where-Object` filter in `verify-integrations.ps1` and the `find` predicate in `verify-integrations.sh`). Additional exclusions for project-specific dependency directories are a per-project concern and belong in a project-local wrapper, not in the upstream helpers.

---

## Extending the Contract Vocabulary

The format contract above (sections 3 and 4) is a vocabulary — a closed set of marker kinds with defined semantics. When a genuinely new marker kind is needed, follow these rules. They mirror `log_vocabulary.md`'s "Extending the Vocabulary" rules, because the governance problem is the same: vocabularies that accept additions without discipline become noise.

1. **Use the existing marker kinds first.** `<CONTRACT>` covers definition. `<USES>` covers consumption. `## <contract:>` and `### <change:>` cover the Integration Map. Before inventing a new kind, verify that none of the existing kinds covers the need.

2. **Use the existing attribute set first.** If you need to annotate a contract with a new property, consider whether an existing attribute covers it. `scope` covers enforcement tier. `version` covers breaking-change lineage. Adding a new attribute is cheaper than adding a new kind, and often cheaper still is using `SIDE_EFFECTS` or an equivalent existing field.

3. **Document cross-language substitutions.** If a new marker kind or attribute cannot be implemented consistently across all three languages, document the substitution explicitly at the point of introduction. Follow the `STACK_TRACE` precedent in `log_vocabulary.md`: the asymmetry is stated, not pretended away.

4. **Add to the format contract before committing the code.** A marker kind that exists in one script and not in this reference file is a papercut that hides from grep. The moment a kind proves useful, it graduates to section 3.

5. **Bump the contract-vocabulary version.** A new marker kind is a breaking change to the vocabulary. The version bump (currently `V5.0` — this file's launch version) ensures the helper scripts can version-gate their checks.

6. **Prefer extension over invention.** A proposed new marker kind should either (a) have at least two independent use cases in the current codebase, or (b) solve a problem the existing kinds structurally cannot. "It would be nice to have" is not sufficient. The value of the vocabulary is its closure; every addition dilutes that value unless it pulls its weight.

---

## Worked Templates

The templates below are illustrative — they show how the protocol unfolds in practice for each failure mode. They are not case studies; they are synthetic examples designed to teach the mechanics. Real case studies from actual debugging incidents belong in the "Case Studies" section below, governed by the real-incidents-only gatekeeping rule (see "How to Add a Case Study to This File" at the end of this document).

### Template 1 — Signature Change (Adding a Parameter)

**Starting state.** `get_user_token` currently accepts `(user_id, scope)`. The team needs to add an optional `tenant_id` parameter to support multi-tenant scenarios.

**Current contract (version 1):**

```python
# <CONTRACT id="get_user_token" version="1" scope="public">
#   params:
#     user_id  [str]        required
#     scope    [list[str]]  required
#   returns: dict
#     token       [str]
#     expires_at  [datetime]
#     scopes      [list[str]]
#   raises: AuthenticationError, NetworkError
# </CONTRACT>
def get_user_token(user_id: str, scope: list[str]) -> dict: ...
```

**Walkthrough:**

- **Step 1 (Identify).** Contract: `get_user_token`. Change: signature — new optional parameter. Current version: 1.
- **Step 2 (Enumerate).** Q2 returns 3 USES markers. Q3 returns 7 call sites (3 overlap with USES markers; 4 are bare calls).
- **Step 3 (Classify).** All 10 consumers are UNAFFECTED — the new parameter is optional with a default, and no existing consumer passes a tenant_id argument.
- **Step 4 (Resolve UNCLEAR).** Zero UNCLEAR; skip.
- **Step 5 (Gate).** Public contract, strict tier; all consumers classified; proceed.
- **Step 6 (Plan).** Add `tenant_id: str | None = None` to the signature. Update CONTRACT params. Version 1 → 2. No consumer updates needed.
- **Step 7 (Edit definition).** Change signature; update CONTRACT block.
- **Step 8 (Update consumers).** None required — all UNAFFECTED.
- **Step 9 (Map).** Update `## <contract:get_user_token>` section with new version and params summary. No CONSUMER entries change.
- **Step 10 (Log).** Append change entry noting "signature, added optional tenant_id, 0 consumers affected."
- **Step 11 (Verify).** `verify-integrations.sh` clean.

**Post-change contract (version 2):**

```python
# <CONTRACT id="get_user_token" version="2" scope="public">
#   params:
#     user_id    [str]        required
#     scope      [list[str]]  required
#     tenant_id  [str|None]   optional, default=None
#   returns: dict (unchanged from v1)
#     token       [str]
#     expires_at  [datetime]
#     scopes      [list[str]]
#   raises: AuthenticationError, NetworkError
# </CONTRACT>
```

**What this template teaches:** the protocol is cheap when the change is backward-compatible. The enumeration still happens; the classification happens; but the work is minutes, not hours. The protocol pays its small cost to *prove* there are no hidden breaks — which is the reason passes 2 and 3 don't happen.

### Template 2 — Return-Shape Change (Renaming a Field)

**Starting state.** `get_user_token` returns a dict with `scopes` (plural), but an upstream API change now returns the field as `granted_scopes`. The contract must be updated to match.

**Walkthrough:**

- **Step 1 (Identify).** Contract: `get_user_token`. Change: return-shape — field rename `scopes` → `granted_scopes`. Current version: 2.
- **Step 2 (Enumerate).** Q2 returns 3 USES markers. Q3 returns 7 call sites. Q4 filtered to `fields=".*scopes` returns 2 USES markers that declare dependency on the `scopes` field.
- **Step 3 (Classify).** Of 10 consumers: 2 AFFECTED (the two identified by Q4). 5 UNAFFECTED (do not read return fields). 3 UNCLEAR — consumers that have USES markers without a `fields` attribute, so the dependency is not declared.
- **Step 4 (Resolve UNCLEAR).** Read each of the 3 UNCLEAR consumers. Result: 1 is AFFECTED (reads `scopes` despite not declaring it in the marker — this is a documentation drift to fix), 2 are UNAFFECTED. Also, fix the one marker that was silently drifting — add `fields="scopes"` retrospectively so the USES marker matches reality.
- **Step 5 (Gate).** Public contract; zero UNCLEAR after resolution; proceed.
- **Step 6 (Plan).** Rename the field in the return dict. Update CONTRACT returns. Version 2 → 3. Update 3 AFFECTED consumers. Update their USES markers to `fields="granted_scopes"` (or `fields="token,granted_scopes"` etc.) and to `version="3"`.
- **Steps 7-11.** Execute.

**What this template teaches:** return-shape changes are the hardest failure mode, and USES markers are the mechanism that makes them tractable. The 1 consumer whose marker was drifting is exactly the kind of bug that would have been missed without the protocol — it looked fine at the syntactic level but was reading the renamed field. The protocol found it because step 4 required reading every UNCLEAR entry to classification certainty.

### Template 3 — Variable Rename (Module Constant)

**Starting state.** A module-level constant `DEFAULT_TENANT = "acme-corp"` is being renamed to `FALLBACK_TENANT` to better reflect its semantics — it is the fallback used when no tenant is specified, not a "default" in the strict sense.

**Walkthrough:**

- **Step 1 (Identify).** Contract: the constant `DEFAULT_TENANT`. Change: rename.
- **Step 2 (Enumerate).** Q1 for `<CONTRACT id="DEFAULT_TENANT"` finds the CONTRACT block wrapping the constant. Q3 for `\bDEFAULT_TENANT\b` finds 9 occurrences across 6 files.
- **Step 3 (Classify).** All 9 occurrences are AFFECTED — any use of the old name will break under the rename.
- **Step 4 (Resolve UNCLEAR).** Zero UNCLEAR; skip.
- **Step 5 (Gate).** Scope: let's say `internal` for this constant. Advisory tier, but zero UNCLEAR anyway.
- **Step 6 (Plan).** Rename the declaration. Update the CONTRACT id. Update all 9 occurrences. Bump version.
- **Step 7-11.** Execute. The map entry's heading changes from `## <contract:DEFAULT_TENANT>` to `## <contract:FALLBACK_TENANT>`. Log entry records the rename explicitly.

**What this template teaches:** CONTRACT blocks on constants (not just functions) are legitimate. The grep-anchoring that CONTRACT provides is most valuable for short names that collide with substrings — `DEFAULT_TENANT` might or might not, but if the name were shorter (`TENANT`, `ID`, `DEFAULT`) the CONTRACT marker would be the only way to reliably find the declaration site through grep. The marker exists for the grep discipline, not for syntactic correctness.

### Case Studies

*(This section is intentionally empty at V5.0 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule documented at the end of this file. Illustrative examples belong in "Worked Templates" above; this section is reserved for institutional memory of real incidents.

---

## Drift Defenses

The Integration Map has a drift risk: it only helps if it is current. This section documents the mechanisms that make drift *detectable*, so that a stale map is discovered immediately rather than lingering until it silently produces wrong answers.

### The Three Drift Directions

**Code ahead of map.** A new `<USES>` marker or CONTRACT block exists in the code but is not represented in `.integration-map.md`. Symptom: a consumer is invisible to the Integration Map's queries even though the code is correct.

**Map ahead of code.** A `CONSUMER:` entry in the map points to a file or line that no longer exists. Symptom: the map's answers are confidently wrong.

**Version mismatch.** A `<USES>` marker declares `version="N"` for a contract whose current `<CONTRACT>` definition is `version="M"` where M ≠ N. This is conceptually separate from the first two directions — the map may be fully current and still not catch this case, because the mismatch is between the consumer and the contract itself, not between the code and the map. Symptom: a consumer is silently using an outdated contract assumption.

All three directions are caught by the Q6 drift queries. The direction determines the fix: code-ahead-of-map means append to the map; map-ahead-of-code means reconcile the map with reality (usually by removing stale CONSUMER entries and re-running Q2+Q3 to rebuild the current consumer list); version mismatch means either update the consumer to the new version (preferred) or confirm the consumer's intent to pin to the older version (rare; should be the exception, not the pattern).

*Not checked in V5.0:* a case adjacent to map-ahead-of-code — where a `## <contract:NAME>` section in the map declares a version that no longer matches the code's current CONTRACT block version. The V5.0 helpers do not parse version numbers from map headings. This is a planned V5.1 extension; until then, treat map-side version records as advisory.

### When to Run Drift Detection

- **At the end of every Change Impact Protocol run** (step 11). This catches drift from the change that just happened.
- **At the start of a session that is resuming work on a project.** The skill's "read Development Notes before touching code" rule has an integration-tracking analog: run `verify-integrations` before trusting the Integration Map as current.
- **Before a significant refactor.** If the map is drifted, the refactor plan is working from wrong premises; fix the drift first.
- **On a schedule for long-lived projects.** A weekly or per-milestone run surfaces drift that accumulated from edits that skipped the protocol.

### The `CONTRACT_DRIFT` Log Prefix

`verify-integrations.ps1` and `verify-integrations.sh` emit structured logs matching the log format contract in `log_vocabulary.md`. The prefixes used:

- `INTEGRATION_MAP_UPDATED` (INFO) — the verify script ran and completed with zero drift.
- `CONTRACT_DRIFT` (ERROR) — drift was detected; details follow in key=value fields (direction, contract_id, location).

Any non-zero `CONTRACT_DRIFT` count blocks a clean verification exit.

### When Drift Is Expected

One situation legitimately produces drift: a refactor in progress. Partway through a multi-commit refactor, the markers and the map may be intentionally out of sync until the final commit reconciles them. The protocol handles this by allowing a `# DRIFT-EXPECTED: reason` comment at the top of the Integration Map during the refactor window. The verify scripts recognize this comment and downgrade `CONTRACT_DRIFT` to `WARN` level while it is present.

The comment must be removed as the *last step* of the refactor. A `DRIFT-EXPECTED` comment still present after the refactor is itself a drift — and the verify scripts flag that.

---

## Integration with Other Skill Standards

This reference composes with several existing sections of the skill. The compositions are intentional; contract-tracking is not an isolated discipline.

**`testing.md` Rule 2 — Mocks Must Exercise the Contract.** Rule 2 addresses contract integrity at test-time; this file addresses it at definition-and-consumption time. A test that uses `MagicMock(spec=...)` derives its safety from the real class's contract; that contract is the same one documented in the `<CONTRACT>` block. When a contract changes version, tests using `spec=` break automatically — which is the desired behavior and the reason spec-bound mocks exist.

**`troubleshooting.md` Development Notes.** A Change Impact Protocol run on a complex contract produces enough information to warrant a Development Notes entry. The entry records the classification outcome, any UNCLEAR resolutions, and the reasoning behind the chosen edit order. This is session-resumption anchor material for the next session touching the contract.

**`log_vocabulary.md` Format Contract.** The format contract in section 3 of this file follows the same governance pattern as `log_vocabulary.md`'s format contract. Both are format-as-contract systems; both require version discipline; both have "extending the vocabulary" sections with parallel rules. When in doubt about a marker format question, the answer is usually "what would `log_vocabulary.md` do?"

**SKILL.md Fail Fast and Prove-First.** The Change Impact Protocol is a Prove-First discipline applied to integration changes — prove the consumer set is fully enumerated before investing in the edit. The tiered enforcement gate is a Fail Fast mechanism — public contracts fail loudly on incomplete classification rather than silently shipping with unresolved consumers.

---

## How to Add a Case Study to This File

When a real integration-tracking incident occurs — a pass-2 or pass-3 regression that the protocol missed, or a protocol step that surfaced a bug that would otherwise have shipped — add it as a case study in the "Case Studies" section above.

**Gatekeeping rule — real incidents only.** A case study must document a real debugging incident from a project's build. Hypothetical scenarios, invented examples, and "this could happen" patterns are not allowed — they dilute the signal that makes case studies institutional memory rather than decoration. This matches the gatekeeping rule in `prove_first.md` and serves the same purpose.

Illustrative examples that teach protocol mechanics without a real incident belong in "Worked Templates" (section 8), explicitly marked as templates. Template content and case-study content are deliberately kept in separate sections so readers can tell at a glance which is which.

### The Schema

Each case study records:

1. **Situation** — what was being built, which contract was being changed, what the scope and version were.
2. **What went wrong** — the failure mode that occurred, including time lost, number of pass-2/pass-3 cycles, and whether the protocol was followed completely or shortcut.
3. **Root cause** — the specific protocol step that missed the issue, or the specific design gap that allowed the issue to slip through. State it plainly.
4. **What the protocol would have caught (if any step was skipped)** — or, if the protocol was followed completely, what the protocol gap is and what additional discipline would have caught it.
5. **Lesson encoded** — cross-reference to the skill_development log entry, memory entry, or protocol revision where the learning now lives.
6. **Generalizable rule** — the pattern other sessions should recognize.

The schema mirrors `prove_first.md`'s six-field schema. Consistency across the skill's case-study sections means a reader familiar with one is immediately oriented in the others.

### When Not to Add a Case Study

If the incident is a routine protocol success (the protocol caught the issue as designed, no lesson beyond "the protocol works"), a case study is not warranted. Routine successes belong in the run logs, not in institutional memory.

If the incident is a false positive from the verify scripts or a drift that was expected and documented, no case study is warranted.

If the incident reveals a bug in the verify scripts themselves, the bug goes in the verify scripts' Verification History section, not in the case studies — case studies document contract-tracking incidents, not tooling bugs.
