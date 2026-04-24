# Grep-First — Enumerating Consumers of Shared Textual Elements Before Change

Grep-First is the general discipline of enumerating all consumers of a shared textual element before modifying that element. `reference/integration-tracking.md` covers the most-developed specialization — function contracts with formal `<CONTRACT>` blocks, `<USES>` markers, and an Integration Map. This file covers the general form that applies across nine categories of shared textual element.

**Load this file when:** you are about to rename, retype, or restructure a shared textual element that is likely referenced from more than one location — error codes, log prefixes, config keys, API endpoints, constants, function or class names, type definitions, env var names, file paths. Also load when resuming work on a codebase where a rename has been half-applied and you need to find the stragglers.

**Do not load this file for:** purely local changes inside a single file; one-off utility scripts with no cross-file consumers; minimal scaffolds where the whole script fits on one screen.

---

## The Problem This File Solves

Shared textual elements — anything named once and referenced many times across a codebase — are the quiet failure mode of refactoring. A rename or restructure at the definition site must be matched at every consumer, or the build breaks, the tests flake, or worse: the code runs and produces wrong answers because a stale reference still resolves to *something*.

Claude Code sessions and human refactors share the same three-pass failure pattern. Pass 1 changes the definition and the obvious consumers — the ones in the same file, the ones the session happens to have open, the ones a first grep surfaced. Pass 2 is the test run or runtime that reveals a missed consumer. Pass 3 is the follow-on — fixing the missed consumer surfaces a *transitive* consumer that was hidden behind it.

Passes 2 and 3 are preventable. They happen because pass 1 proceeded without enumerating the full consumer set first. Grep-First formalizes the enumeration discipline: before the change, grep for every consumer using the canonical query for that category of shared element; classify every hit as AFFECTED, UNAFFECTED, or UNCLEAR; resolve UNCLEAR to certainty; then change; then re-grep to verify zero stragglers.

The discipline is scoped to categories where grep is a reliable enumeration mechanism. Dynamic dispatch, runtime string construction of names, and reflection-based access are out of scope — no textual tool finds those reliably, and Grep-First does not pretend to. For those cases, the enumeration mechanism is the type system, a debugger, or a test suite — not this protocol.

---

## Format Contract — Invariant Shape

The invariants G1–G9 defined in section 5 each specify a canonical grep pattern and authoring discipline for one category of shared textual element. They are **authoring-time invariants**, not runtime markers — they describe how to find consumers, not textual tags a consumer places in code. This distinguishes them from Integration Tracking's I1–I6, which specify runtime markers (`<CONTRACT>`, `<USES>`) that appear in source files.

Every G-invariant shares a uniform base and admits optional extensions where real variance warrants them. The uniformity makes the vocabulary scannable; the optional extensions prevent forced conformance where categories genuinely differ.

### Uniform base — every G-invariant specifies

- **Canonical grep pattern.** The query a consumer enumerator runs to find every reference to a named element of this category. Ripgrep-first form, portable grep fallback inline. See "rg-first authoring" below.
- **Collision-risk note.** The category's known false-positive and false-negative failure modes. Short names collide with substrings; language-specific syntax can hide references from naive patterns; convention-dependent categories behave differently per language.
- **Worked template.** One walkthrough applying the five-step Grep-First Protocol (section 4) to a realistic change in this category. Templates are synthetic — real case studies live in each category's empty Case Studies slot until incidents accumulate.
- **Empty Case Studies section.** Reserved per category for real incidents, governed by the gatekeeping rule in section 8. Launches empty per `<devlog:2026-04-22:illustrative-templates-launch>` precedent.

### Optional extensions — applied per category as variance warrants

- **Per-language notes.** Added when naming conventions differ materially across Bash, Python, and PowerShell. Function names follow different case conventions in each language; file paths follow different separator conventions; type definitions don't exist in the same form in Bash. Categories where all three languages behave uniformly skip this extension.
- **Cross-language substitution notes.** Added when a category does not apply uniformly across all three languages, following the `STACK_TRACE` precedent in `log_vocabulary.md`: document the asymmetry rather than pretend uniformity. Type definitions in Bash, for example, substitute to "documented-convention-only" since Bash lacks a type system.
- **False-positive guidance.** Added when a category has a known high false-positive rate. Short constant names collide with substrings in unrelated contexts; path fragments appear inside longer paths; function names can collide with method names in unrelated classes. This extension specifies post-filters or refined patterns that tighten the signal.

### rg-first authoring

Every canonical grep pattern is documented in ripgrep form first, with portable grep fallback inline. Ripgrep is 2–10x faster on large codebases, respects `.gitignore` by default, and offers type filters (`-t py`, `-t sh`) that align with Grep-First's category framing. The portable grep form is kept inline for environments without ripgrep — in particular, V5.0's helper scripts `verify-integrations.ps1` and `verify-integrations.sh` remain grep-portable per locked V5.0.1 decision. The V5.2 posture shift is scoped to `grep_first.md` authoring, not to shipped helpers.

### The Nine Categories

Grouped by grep-friendliness — the signal-to-noise ratio of the canonical pattern against a realistic codebase. The grouping informs which optional extensions a category typically requires.

**High grep-friendliness** — distinctive patterns, low collision risk:
- **G1** Error and exit codes
- **G2** Log prefixes

**Medium grep-friendliness** — conventions exist but collision risk is real:
- **G3** Configuration keys
- **G4** API endpoints and URL patterns
- **G5** Environment variable names

**Low grep-friendliness** — collision-prone or convention-dependent:
- **G6** Constants and enum values
- **G7** Function and class names
- **G8** Type definitions
- **G9** File paths referenced across scripts

Each invariant is specified in full in section 5, with its sub-section placing it in the grep-friendliness group it belongs to.

### Governance Rule for Format Changes

These invariants must not drift silently. If a canonical pattern, collision-risk note, or worked template needs to change:

1. Propose the change in the skill_development log.
2. Bump the Grep-First vocabulary version (a new top-level version in this file).
3. Update every worked template that demonstrates the affected invariant in a single commit.
4. Grep-test every updated template against its new canonical pattern before shipping — the L2 format-drift-in-self-authored-patches failure mode specifically targets this authoring axis.

The helpers shipped under `reference/integration-helpers/` do not implement Grep-First invariants at V5.2 (see `<devlog:2026-04-22:v5-2-no-helper-at-launch>`). Future helpers that do will be updated in the same commit as the invariant they implement.

---

## The Grep-First Protocol

Five steps. Run before any modification to a shared textual element. The protocol is parallel to `integration-tracking.md`'s Change Impact Protocol but lighter by design — Grep-First has no stateful artifacts (no `.integration-map.md` analog, no versioned contracts, no tiered enforcement gate), so the steps that maintain those artifacts in IT do not exist here.

### Step 1 — Grep

Run the canonical query for the category of shared element you are changing. Section 5 specifies the query per category. For most categories the query is one line of ripgrep; for a few it is two or three when the element crosses language-specific syntactic forms.

The query's hit set is the **candidate consumer set**. Every hit is a location in the codebase that references the element by its current name. This set is the input to classification — nothing gets modified until every member of this set has been classified.

If the hit count is zero, either the element is unused (verify by deleting it in a scratch branch and running the test suite — an unused element is a legitimate deletion), or the canonical query is wrong for the category. Re-read section 5 for that category before proceeding.

### Step 2 — Classify

For each hit in the candidate consumer set, mark exactly one of:

- **AFFECTED** — the consumer will break under the change. Requires update.
- **UNAFFECTED** — the consumer will continue to work unchanged. Common reasons: the reference is to a different element that happens to share a substring (false positive); the consumer reads the element through an indirection that insulates it from the rename; the consumer is in commented-out or dead code.
- **UNCLEAR** — the classification cannot be determined without reading the consumer in detail, or the consumer's behavior under the change is ambiguous.

The three-state classification is deliberate. Two states (affected / unaffected) force premature certainty; UNCLEAR is the honest answer when the information is not yet available. UNCLEAR entries do not block step 2 — they block proceeding past step 3.

**Classification involves semantic judgment.** The canonical grep pattern is a syntactic tool — it surfaces textual occurrences. AFFECTED vs UNAFFECTED is a semantic call: authoritative documentation vs narrative example, replay fixture vs hand-authored assertion, primary call site vs higher-order wrapper. The pattern *cannot* decide these — by design, not by limitation. Step 2 (this step) and step 3 (Resolve UNCLEAR) are where syntactic hits become semantic decisions, and the worked templates in section 5 demonstrate the judgment calls each category surfaces. Budget time for this — especially in 5C categories, where the classifier typically reads several consumers before marking them.

### Step 3 — Resolve UNCLEAR

For each UNCLEAR entry, take exactly one action:

1. Read the consumer's code until the classification is clear; reclassify as AFFECTED or UNAFFECTED.
2. Ask for guidance if the consumer's behavior under the change is semantically ambiguous and cannot be resolved from code alone.
3. If the consumer is deprecated or slated for removal, reclassify as AFFECTED and note the intent in the change plan.

**Exit criterion:** zero UNCLEAR entries remain. The protocol does not support advisory-tier enforcement the way IT does — IT's `scope="public"` / `scope="internal"` distinction applies to declared contracts, and Grep-First operates one level below that at the raw-textual-element layer. Every UNCLEAR entry must be resolved before the change proceeds.

### Step 4 — Change

Apply the modification across every AFFECTED consumer. The order of edits — definition first or consumers first — depends on the language, the tooling, and whether the change is backward-compatible at the textual level.

For backward-compatible changes (e.g., adding a new error code while keeping old codes valid), definition-first is usually simpler — consumers can be updated in a follow-up commit without breaking the build between commits. For breaking changes (e.g., renaming an error code), consumers-first avoids a window where the definition is renamed but consumers still reference the old name.

Record the rationale for edit order in the change's commit message or Development Notes. A consistent edit order across a codebase makes review easier; an inconsistent one forces reviewers to reconstruct the order from diffs.

### Step 5 — Grep-verify

Re-run the canonical query from step 1, now targeting the old name. The expected result is **zero hits** — every reference to the old name has been updated to the new name, or the reference was UNAFFECTED (a legitimate substring collision that was never the target).

If hits remain, classify each: either a new AFFECTED consumer that was missed in step 1 (fix it, then re-verify), or a UNAFFECTED false positive that the pattern cannot distinguish (acceptable — the pattern has known false positives documented in the category's collision-risk note).

Also re-run the canonical query targeting the **new** name. The hit count should match the number of AFFECTED consumers plus the definition site. If it doesn't, a consumer update was dropped, or a stray reference to the new name existed before the change (collision — investigate).

**Commit when step 5 is clean.** A change that passes steps 1–4 but not step 5 is not complete, regardless of how the intermediate state looks.

---

## Per-Category Invariants and Workflow

The nine invariants G1–G9 each specify the canonical grep pattern, collision-risk profile, and worked template for one category of shared textual element. Categories are grouped by grep-friendliness — the signal-to-noise ratio of the canonical pattern against a realistic codebase. Within each group, categories share similar extension profiles; across groups, the extension profile shifts.

Read a category in full before applying its protocol. The collision-risk note is not decoration — it names the specific false positives and false negatives the canonical pattern is known to produce, which is the information the classifier (step 2 of the protocol) needs to mark UNAFFECTED reliably.

---

### 5A — High Grep-Friendliness

Error/exit codes and log prefixes share a structural property: both use an enforced convention (`UPPER_SNAKE_CASE` with a distinctive prefix or context) that makes grep patterns highly specific. Collision risk is low; per-language variance is minimal; extensions are the lightest of any group.

### G1 — Error and Exit Codes

Named error codes and numeric exit codes shared across a codebase. Example forms: `E_CONN_LOST` in a Python exception hierarchy; `EXIT_INPUT_NOT_FOUND=10` in a Bash error-code block; `[int]$script:ExitProcessingFailed = 20` in PowerShell.

**Canonical grep pattern:**

```bash
# Named error code — rg (preferred):
rg -n '\bE_CONN_LOST\b' -t py -t sh -t ps1

# Numeric exit code used as a constant — rg:
rg -n '\bEXIT_INPUT_NOT_FOUND\b' -t py -t sh -t ps1

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    -E '\bEXIT_INPUT_NOT_FOUND\b' .
```

The `\b` word boundaries eliminate the primary false-positive class — longer identifiers that happen to contain the code's name as a substring. Type filters (`-t py -t sh -t ps1`) restrict the search to relevant file types, which in turn eliminates hits in log files, documentation, and test fixtures that happen to mention the code.

**Collision-risk note:**

- **Low false-positive rate.** The `UPPER_SNAKE_CASE` + word-boundary pattern is specific enough that false positives are rare in practice — the main source is deliberate references in documentation files (README, CHANGELOG) that a code-only type filter excludes.
- **False negatives possible through indirection.** A consumer that reads the code through a dictionary lookup (`ERROR_CODES['conn_lost']`) or dynamic attribute access (`getattr(errors, code_name)`) will not appear in the canonical query. These are out of scope for Grep-First per section 2 — the enumeration mechanism for dynamic dispatch is the type system or a test suite, not grep.
- **Raw numeric exit codes.** When a script uses `sys.exit(10)` or `exit 10` directly without a named constant, no grep can find the numeric reference semantically. The discipline here is upstream of Grep-First: require every exit code to be named, per the skill's error-code-block convention (see `SKILL.md § Fail Fast`). Raw numeric exits are an anti-pattern that Grep-First cannot remediate retroactively.

**Worked template — Renaming `E_CONN_LOST` to `E_UPSTREAM_UNAVAILABLE`:**

Assume the old name is defined in `src/errors.py` and referenced across 6 files.

- **Step 1 (Grep).** `rg -n '\bE_CONN_LOST\b' -t py` returns 9 hits: 1 definition, 8 references across 6 files.
- **Step 2 (Classify).** All 9 hits are named code references. 1 is the definition (AFFECTED — will rename). 8 are consumers (AFFECTED — raise-and-catch, equality checks, log emissions). Zero substring false positives; word-boundary caught them.
- **Step 3 (Resolve UNCLEAR).** Zero UNCLEAR.
- **Step 4 (Change).** Consumers-first for breaking rename: update the 8 consumers across 6 files to `E_UPSTREAM_UNAVAILABLE`. Then update the definition in `src/errors.py`. Commit in two steps for reviewability.
- **Step 5 (Grep-verify).** `rg -n '\bE_CONN_LOST\b' -t py` returns zero hits. `rg -n '\bE_UPSTREAM_UNAVAILABLE\b' -t py` returns 9 hits — matches expected (1 definition + 8 consumers). Clean.

**What this template teaches:** error codes are the easiest Grep-First category. The combination of enforced `UPPER_SNAKE_CASE` convention, `\b` word boundaries, and code-file type filters produces a pattern that is both precise and complete in the absence of dynamic dispatch. If Grep-First feels hard on your first attempt, start with error codes — the category is designed around grep's strengths.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G2 — Log Prefixes

Log prefix constants defined in `reference/log_vocabulary.md` and its per-script extensions. Example forms: `SCRIPT_START`, `UNIT_FAILED`, `RETRY_EXHAUSTED` — all `UPPER_SNAKE_CASE`, all emitted through a log helper.

**Canonical grep pattern:**

```bash
# Log prefix reference — rg (preferred):
rg -n '\bSCRIPT_START\b' -t py -t sh -t ps1

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    -E '\bSCRIPT_START\b' .

# Prefix emission (by call site to the log helper) — additional query for a rename:
rg -n 'log[^(]*\(\s*["'\'']SCRIPT_START' -t py -t sh -t ps1
```

Log prefixes are emitted through helpers (`log()`, `Write-Log`, `setup_logger()`), so the canonical query finds references by name. The secondary emission query catches string-literal usages inside helper calls when a prefix rename needs to update the emission sites specifically, not just the named constants.

**Collision-risk note:**

- **Low false-positive rate** when the prefix follows the `UPPER_SNAKE_CASE` convention. The word-boundary + type-filter combination is highly specific.
- **Documentation hits in `log_vocabulary.md` and SKILL.md** are legitimate references, not false positives — they document the vocabulary. Treat as UNAFFECTED (documentation will update as part of a rename change, but does not affect script runtime behavior).
- **Per-script one-off prefixes** (per `log_vocabulary.md § Extending the Vocabulary` rule 4) may exist in exactly one script with a header comment announcing them. The canonical query finds them; classifier marks as AFFECTED if the rename applies to the one-off prefix itself.
- **Cross-language substitution note** (per `log_vocabulary.md § STACK_TRACE`): Bash has no call-stack mechanism, so `STACK_TRACE` is emitted by Python and PowerShell but not Bash. The canonical query for a hypothetical `STACK_TRACE` rename returns zero hits in Bash files — expected, not a false negative. When renaming a prefix with a documented cross-language substitution, include the substitution's alternate emission in the change plan (Bash's `$LINENO` + `$BASH_COMMAND` pattern, in this case).

**Worked template — Renaming `PARTIAL_SUCCESS` to `DEGRADED_SUCCESS`:**

Assume the prefix is defined in `reference/log_vocabulary.md` and emitted from 3 scripts' processing phases.

- **Step 1 (Grep).** `rg -n '\bPARTIAL_SUCCESS\b' -t py -t sh -t ps1` returns 5 hits: 3 emission sites (one per script), 1 SKILL.md table reference, 1 log_vocabulary.md table row.
- **Step 2 (Classify).** 3 emission sites AFFECTED (will update). 2 documentation references AFFECTED (vocabulary table rows and the SKILL.md Partial Success Standard table both reference the prefix by name). Zero UNCLEAR.
- **Step 3 (Resolve UNCLEAR).** Skip.
- **Step 4 (Change).** Update the 3 emission sites first (runtime-critical). Update the 2 documentation references in the same commit for consistency. The vocabulary update is the authoritative site — other references cite it.
- **Step 5 (Grep-verify).** `rg -n '\bPARTIAL_SUCCESS\b' -t py -t sh -t ps1` returns zero hits. `rg -n '\bDEGRADED_SUCCESS\b' -t py -t sh -t ps1` returns 5 hits — matches expected.

**What this template teaches:** log prefixes live partly in code (emission sites) and partly in documentation (vocabulary tables). Both are consumers in the Grep-First sense; both require update. The canonical query surfaces both — the classifier just needs to mark documentation references as AFFECTED rather than dismissing them as "not code."

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### 5B — Medium Grep-Friendliness

Config keys, API endpoints, and env var names share a structural property: conventions exist but are not strongly enforced at the grep layer. Config keys are strings inside arbitrary containers; endpoints are path fragments embedded in longer URLs; env var names have distinct access syntax per language. Each needs a more specific canonical pattern than 5A's `UPPER_SNAKE_CASE + \b` form, plus explicit false-positive guidance.

### G3 — Configuration Keys

String keys used to read or write a value inside a configuration container — dict, hashtable, JSON object, YAML mapping, TOML table. Example forms: `config["database_url"]`, `$config['DatabaseUrl']`, `settings.get("timeout_seconds")`, `"timeout_seconds": 30` inside a JSON config file.

**Canonical grep pattern:**

```bash
# Quoted key form (catches most lookups and literal definitions) — rg:
rg -n '["'\'']database_url["'\'']' -t py -t sh -t ps1 -t json -t yaml -t toml

# Bracketed access form (tightens for dict/hash lookups specifically):
rg -n '\[["'\'']database_url["'\'']\]' -t py -t sh -t ps1

# Portable grep fallback (quoted key form):
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    --include='*.json' --include='*.yaml' --include='*.yml' --include='*.toml' \
    -E '["'\'']database_url["'\'']' .
```

The quoted-key pattern is the primary query — it catches both definition sites (in JSON/YAML/TOML) and consumer lookups (in Python/Bash/PowerShell). The bracketed-access pattern is a sharpening filter when the quoted-key pattern returns too many false positives; it restricts hits to `container[key]` lookups specifically.

File-type filters are broader than 5A's because config keys legitimately appear in data files (JSON/YAML/TOML), not just code.

**Collision-risk note:**

- **Medium false-positive rate** from substring matches inside longer keys (`"database_url"` substring-matches inside `"fallback_database_url"`). Word boundaries don't help here because quotes serve as the boundary.
- **False positives from documentation strings.** Comments, docstrings, and README examples that quote the key as an example will appear in the hit set. Classifier marks these AFFECTED if the documentation is authoritative (docs will update with the rename) or UNAFFECTED if the documentation is narrative (e.g., a historical example).
- **False negatives through config-object attribute access** in typed frameworks — `settings.database_url` (attribute) hides the string form and is invisible to the canonical query. When the config layer exposes attributes rather than dict access, supplement the canonical query with an attribute-access query (`\.database_url\b`), which has its own G7-style collision risks.
- **False-positive guidance.** Short keys (`"id"`, `"name"`, `"url"`) have unmanageable false-positive rates with the canonical pattern alone. For short keys, tighten the pattern with a container-specific prefix — `config\["id"\]`, `settings\.get\("name"\)` — or rename the short key before applying Grep-First, which is usually the cleaner fix.

**Worked template — Renaming `"database_url"` to `"primary_db_dsn"`:**

Assume the key is defined in `config/default.yaml`, overridden in `config/production.yaml`, and consumed across 4 Python files.

- **Step 1 (Grep).** `rg -n '["'\'']database_url["'\'']' -t py -t yaml` returns 12 hits: 2 YAML definitions, 6 Python lookups across 4 files, 3 docstring examples, 1 README quote.
- **Step 2 (Classify).** 2 YAML definitions AFFECTED. 6 Python lookups AFFECTED. 3 docstring examples — UNCLEAR until read (they might quote the key as illustrative, or as authoritative). 1 README quote AFFECTED (documentation authoritative).
- **Step 3 (Resolve UNCLEAR).** Read the 3 docstrings. 2 are authoritative references (module-level docstrings that document the config contract) — AFFECTED. 1 is a function docstring using the key as a narrative example — UNAFFECTED (the narrative doesn't break if the key renames; a follow-up edit for freshness is nice-to-have but not required).
- **Step 4 (Change).** Consumers-first: update 6 Python lookups, 2 authoritative docstrings, 1 README reference. Then update 2 YAML definitions. The YAML definition is the authoritative site; consumers-first avoids a window where the key is defined under the new name but looked up under the old.
- **Step 5 (Grep-verify).** `rg -n '["'\'']database_url["'\'']' -t py -t yaml` returns 1 hit — the narrative docstring that was marked UNAFFECTED. Expected. `rg -n '["'\'']primary_db_dsn["'\'']' -t py -t yaml` returns 11 hits (2 YAML + 6 Python + 2 docstrings + 1 README) — matches expected.

**What this template teaches:** config keys straddle code and data files, and their consumers include documentation. Classification requires actually reading UNCLEAR entries — the difference between "authoritative documentation that must update" and "narrative example that doesn't have to" is a judgment call the pattern cannot make for you.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G4 — API Endpoints and URL Patterns

URL paths shared across a codebase — route definitions in a web framework, fetch/request URLs in client code, URL patterns in tests, documentation references in OpenAPI specs. Example forms: `@app.route("/api/users/<id>")`, `requests.get(f"{base}/api/users/{id}")`, `paths: /api/users/{id}:` in OpenAPI YAML.

**Canonical grep pattern:**

```bash
# URL path fragment — rg (quoted form, catches most literal references):
rg -n '["'\''`]/api/users\b' -t py -t sh -t ps1 -t js -t ts -t yaml

# Route-definition form (framework-specific; tighten when the framework is known):
rg -n '@app\.route\(["'\'']/api/users' -t py

# Portable grep fallback (quoted form):
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' --include='*.js' \
    --include='*.ts' --include='*.yaml' --include='*.yml' \
    -E '["'\''`]/api/users\b' .
```

The opening quote or backtick plus leading slash anchors the pattern to URL-shaped literals. Trailing `\b` ensures the match ends at a path segment boundary, preventing `/api/users` from substring-matching inside `/api/users_archived`.

**Collision-risk note:**

- **False-positive rate depends on path specificity.** `/api/users` is specific enough that false positives are rare. A shorter path like `/v1/` will substring-match inside `/v1/users`, `/v1/orders`, etc. — useless as a canonical pattern.
- **Path fragments inside longer URLs** are the primary false-negative risk. A rename of `/api/users` to `/api/accounts` must also catch `/api/users/{id}/profile`, `/api/users/search`, and any other sub-path. The canonical query's `\b` word boundary handles this — but only if the intent is to rename the full prefix. For partial renames (rename `/api/users` but leave `/api/users/{id}` alone), the pattern needs refinement per change.
- **URL construction via string concatenation or f-strings** hides the path from grep when the path is built from multiple fragments (`f"{BASE_PATH}{sub}/users"`). These are out of scope for Grep-First — the discipline here is upstream: prefer full-path literals over constructed URLs when the path is stable.
- **False-positive guidance.** Documentation files (`docs/`, `README.md`, OpenAPI specs) contain endpoint references that are authoritative for the rename. Treat as AFFECTED, not as false positives. Test fixtures and recorded HTTP responses (`.vcr`, `.har`, recorded JSON) may reference the old path — these are historical data, not consumers; mark UNAFFECTED unless the tests are expected to regenerate fixtures under the new path.

**Worked template — Renaming endpoint `/api/users` to `/api/accounts`:**

Assume the route is defined in `src/routes/users.py` and consumed by 3 client files plus an OpenAPI spec.

- **Step 1 (Grep).** `rg -n '["'\''`]/api/users\b' -t py -t ts -t yaml` returns 11 hits: 1 route definition, 4 client calls in 3 files, 2 OpenAPI path definitions, 3 test fixture references, 1 README example.
- **Step 2 (Classify).** 1 route + 4 client calls + 2 OpenAPI paths + 1 README = 8 AFFECTED. 3 test fixtures UNCLEAR (depends on whether tests regenerate fixtures or assert against stored responses).
- **Step 3 (Resolve UNCLEAR).** Read the fixture files and their tests. 2 fixtures are replay-style recordings that will regenerate on next `--record` run — UNAFFECTED (the path on next record will naturally be new). 1 fixture is a hand-authored test case that asserts the exact URL — AFFECTED.
- **Step 4 (Change).** Consumers-first: update 4 client calls, 2 OpenAPI paths, 1 README, 1 hand-authored test fixture. Then update the route definition. OpenAPI spec is documentation authoritative to the contract; it updates in lockstep with the route.
- **Step 5 (Grep-verify).** `rg -n '["'\''`]/api/users\b' -t py -t ts -t yaml` returns 2 hits — the 2 replay-style fixtures marked UNAFFECTED. Expected. `rg -n '["'\''`]/api/accounts\b' -t py -t ts -t yaml` returns 8 hits — matches expected.

**What this template teaches:** URL patterns live in more file types than most categories (code, docs, specs, tests, fixtures). Each file type has different semantics for "is this a consumer." Fixture files in particular force an explicit judgment about how the tests interact with recorded data — a judgment Grep-First itself cannot make for you.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G5 — Environment Variable Names

Environment variable names referenced across a codebase. Example forms: `DATABASE_URL`, `API_TOKEN`, `LOG_LEVEL`. Access conventions differ per language — this is the category in 5B where per-language notes apply materially.

**Canonical grep pattern:**

```bash
# Name reference — rg (catches most cases):
rg -n '\bDATABASE_URL\b' -t py -t sh -t ps1

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    -E '\bDATABASE_URL\b' .
```

The canonical pattern is G1-shaped — `UPPER_SNAKE_CASE + \b` — because env var names follow the same convention as error codes. The per-language variance is in *how* the variable is accessed, not in its name.

**Per-language notes:**

- **Python:** `os.environ["DATABASE_URL"]`, `os.environ.get("DATABASE_URL")`, `os.getenv("DATABASE_URL")`. The canonical query catches all three — the variable name is the quoted string, which `\bDATABASE_URL\b` matches inside the quotes.
- **Bash:** `$DATABASE_URL`, `"${DATABASE_URL}"`, `${DATABASE_URL:-default}`. The canonical query catches all three — `$` is not a word-boundary character and `\b` matches between `$` and `D`.
- **PowerShell:** `$env:DATABASE_URL`. Here the env var name is prefixed by `$env:` — the canonical query still catches the name via `\b`, but a sharpening query (`\$env:DATABASE_URL\b`) is tighter when verifying PowerShell-only scripts.

**Collision-risk note:**

- **Low false-positive rate** from the `UPPER_SNAKE_CASE + \b` pattern — same as 5A. The primary exception is hits inside documentation files that name the env var as an example (authoritative — treat as AFFECTED).
- **False negatives through indirect access.** A Python consumer that reads env vars through a config layer (`config.database_url`, loaded once at startup from `os.environ`) will not appear in the canonical query. The config layer itself is the only site that references the env var name directly. This is the design pattern that makes Grep-First easy for env vars — keeping direct `os.environ` / `$env:` access in one or two well-known places means a rename touches only those places plus the env var's declaration in `.env` / deployment config.
- **`.env`, `docker-compose.yml`, and deployment manifests** reference env var names as keys. The canonical query catches these when the type-filter includes the relevant extensions; add `-t yaml -t toml` and a `--include='.env'` form when the project uses these.

**Worked template — Renaming env var `DATABASE_URL` to `PRIMARY_DB_URL`:**

Assume the env var is declared in `.env`, `docker-compose.yml`, and a Kubernetes manifest, and consumed by a Python config layer that exposes it as `config.database_url` to the rest of the code.

- **Step 1 (Grep).** `rg -n '\bDATABASE_URL\b' -t py -t sh -t yaml --glob='.env*'` returns 5 hits: 1 `.env`, 1 `docker-compose.yml`, 1 Kubernetes manifest, 1 Python config layer (`os.environ.get("DATABASE_URL")`), 1 README example.
- **Step 2 (Classify).** All 5 AFFECTED. The Python consumers of `config.database_url` (the attribute, not the env var name) are out of scope — if the env var is being renamed, the config attribute may or may not follow. The classifier's concern is the 5 direct references to the env var name.
- **Step 3 (Resolve UNCLEAR).** Zero UNCLEAR.
- **Step 4 (Change).** Deployment-manifests-first (they are read at container start; a worker restarting on the new name fails fast if the config layer still reads the old name). Then config layer. Then `.env` and `docker-compose.yml` for local dev parity. README last.

  Note the judgment call here: if the config layer also exposes `config.database_url`, the attribute rename is a separate change — a G7 (function/class names) or G6 (constants) application depending on how the attribute is defined. Grep-First handles one category at a time; crossing categories means running the protocol again with the new category's pattern.

- **Step 5 (Grep-verify).** `rg -n '\bDATABASE_URL\b' -t py -t sh -t yaml --glob='.env*'` returns zero hits. `rg -n '\bPRIMARY_DB_URL\b' -t py -t sh -t yaml --glob='.env*'` returns 5 hits — matches expected.

**What this template teaches:** env vars are G1-shaped at the pattern level but admit per-language access variance that affects how consumers are structured. Projects that route all env var access through a single config layer make Grep-First on env vars trivial — direct references are few and authoritative. Projects that access `os.environ` or `$env:` scattered across the codebase pay the cost on every rename.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### 5C — Low Grep-Friendliness

Constants, function/class names, type definitions, and file paths share a structural property: none of them enjoys the combination of enforced convention and distinctive pattern that 5A categories have, and their false-positive rates range from manageable-with-care (G6) to requiring language-specific patterns (G7, G8) to high-by-default (G9). Every category in this group carries per-language notes; G8 also carries a cross-language substitution note (Bash lacks a type system entirely); G6, G7, and G9 carry explicit false-positive guidance.

Read the per-category collision-risk notes carefully before applying the protocol in this group. The time budget at step 3 (Resolve UNCLEAR) is materially larger than for 5A or 5B categories — plan accordingly.

### G6 — Constants and Enum Values

Named constants and enum members used across a codebase. Example forms: `MAX_RETRIES = 5` (Python module constant), `readonly int $MAX_RETRIES = 5` (PowerShell), `readonly MAX_RETRIES=5` (Bash), `class Status(Enum): PENDING = "pending"` (Python enum member).

**Canonical grep pattern:**

```bash
# Named constant reference — rg:
rg -n '\bMAX_RETRIES\b' -t py -t sh -t ps1

# Enum member access — rg (dotted form, typical Python):
rg -n '\bStatus\.PENDING\b' -t py

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    -E '\bMAX_RETRIES\b' .
```

The canonical pattern is G1-shaped — `UPPER_SNAKE_CASE + \b` — for module-level constants. Enum member access adds the enum-name prefix (`Status.PENDING`), which sharpens the pattern against collisions with other `PENDING` constants in unrelated scopes.

**Per-language notes:**

- **Python:** module-level `MAX_RETRIES`, class-level `cls.MAX_RETRIES`, enum member `Status.PENDING`. Word-boundary `\b` in rg matches across the `.` of dotted access, so a canonical query for `\bMAX_RETRIES\b` catches both bare and class-qualified references.
- **Bash:** `readonly MAX_RETRIES=5` at declaration; `$MAX_RETRIES` or `${MAX_RETRIES}` at reference. The `\bMAX_RETRIES\b` pattern catches both forms because `\b` anchors at `$` for references and at the `=` for declarations.
- **PowerShell:** `$script:MaxRetries`, `Set-Variable -Option Constant -Name MaxRetries -Value 5`. PowerShell's convention is PascalCase for constants (matching language convention), so the canonical query for a PowerShell-native constant is `\bMaxRetries\b` — not `\bMAX_RETRIES\b`. Cross-language projects that mirror constant names between Python and PowerShell must pick one form per shared constant and document it in the project's coding conventions.

**Collision-risk note:**

- **Medium false-positive rate** from substring matches inside longer constants (`\bMAX_RETRIES\b` doesn't collide, but a shorter constant like `\bMAX\b` collides with every variable ending in `.MAX`, `MAX_` prefix matches, etc.). Word boundaries help for moderately-long names; for short names, rename before applying Grep-First or tighten the pattern with a scope prefix.
- **False negatives through import aliasing** — `from constants import MAX_RETRIES as MAX` produces a local alias invisible to `\bMAX_RETRIES\b`. Aliasing is uncommon enough to ignore by default; when a codebase uses aliasing heavily, supplement with an alias query (`as\s+MAX_RETRIES`) during enumeration.
- **Enum-member collisions.** Two enums in different modules that share a member name (`Status.PENDING` and `ApprovalState.PENDING`) produce identical `\bPENDING\b` matches. The dotted-form sharpening query (`\bStatus\.PENDING\b`) disambiguates when the prefix enum is known.
- **False-positive guidance.** Short constant names and generically-named enum members (`OK`, `ERROR`, `NONE`, `DEFAULT`) produce unmanageable false-positive rates with word-boundary alone. Three practical options in descending preference: rename the constant to something more specific before Grep-First is applied; tighten the pattern with a module-or-class prefix (`constants\.OK`, `Status\.OK`); accept the false-positive cost and spend additional step-3 time reading UNCLEAR entries. The first option is usually the cleanest fix when the short name was a legacy decision.

**Worked template — Renaming `MAX_RETRIES` to `MAX_RETRY_ATTEMPTS`:**

Assume the constant is defined in `src/config/constants.py` and referenced across 5 Python files plus 1 Bash script that sources a `.env`-style file containing `MAX_RETRIES=5`.

- **Step 1 (Grep).** `rg -n '\bMAX_RETRIES\b' -t py -t sh` returns 8 hits: 1 Python definition, 4 Python consumers (retry helpers, test configuration, a CLI flag default, a log message), 1 Bash consumer (a sourced env file), 1 Bash script that reads the env file, 1 README reference.
- **Step 2 (Classify).** 1 definition AFFECTED. 4 Python consumers AFFECTED. 1 Bash env-file line AFFECTED (it defines the same-named constant for shell usage). 1 Bash script that reads `$MAX_RETRIES` AFFECTED. 1 README reference AFFECTED. Zero UNCLEAR.
- **Step 3 (Resolve UNCLEAR).** Skip.
- **Step 4 (Change).** Consumers-first: update 4 Python consumers, 1 Bash consumer, 1 README reference. Then definitions: update Python constant declaration, update Bash env-file line. Two declaration sites in different languages is a cross-language synchronization point — a mismatch between them causes silent behavior divergence (Python retries 5 times; Bash retries 3 because someone updated one file without the other). Both update in the same commit.
- **Step 5 (Grep-verify).** `rg -n '\bMAX_RETRIES\b' -t py -t sh` returns zero hits. `rg -n '\bMAX_RETRY_ATTEMPTS\b' -t py -t sh` returns 8 hits — matches expected.

**What this template teaches:** constants often have multiple declaration sites in cross-language projects — a Python module plus a Bash env file, or a TypeScript `const` plus a generated Python stub. Each declaration is a consumer in its own right; the canonical query surfaces both; both must update in the same commit or the project develops silent divergence across languages.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G7 — Function and Class Names

Named functions and classes called from more than one location. Example forms: `def get_user_token()` / `class UserToken`: / `function Get-UserToken` / `get_user_token()`. This is the category where IT's Integration Tracking discipline applies most directly — cross-file-called functions are the specialization IT covers. G7 scopes the general Grep-First form for function/class names that do not (yet) have formal `<CONTRACT>` blocks.

**Canonical grep pattern:**

```bash
# Name reference — rg (word-boundary, catches calls and definitions):
rg -n '\bget_user_token\b' -t py -t sh -t ps1

# Python-specific: the name inside parentheses or after 'def' (tightens when the name is common):
rg -n '\bdef\s+get_user_token\b|\bget_user_token\s*\(' -t py

# PowerShell-specific (verb-noun convention):
rg -n '\bGet-UserToken\b' -t ps1

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    -E '\bget_user_token\b' .
```

The per-language canonical patterns use each language's naming convention — Python's `snake_case`, Bash's `snake_case`, PowerShell's `Verb-Noun`. Cross-language projects that mirror function names between languages (e.g., generated bindings) follow the G6 cross-language synchronization pattern — both declaration sites update together.

**Per-language notes:**

- **Python:** `def get_user_token(...)` definition; `get_user_token(...)` calls; `@staticmethod\ndef get_user_token(...)` inside classes; `functools.partial(get_user_token, ...)` as higher-order use; `@decorator` forms above the definition. The `\b` pattern catches all of these because `get_user_token` is word-characters-only. Method names on classes use dotted form (`user.get_token()`) — a separate sharpening pattern (`\.get_token\b`) when the method name is common.
- **Bash:** `get_user_token()` definition; `get_user_token "$arg"` calls. No class method form. Local scope is per-function and does not affect grep; a function name is global within its source file unless wrapped in a subshell.
- **PowerShell:** `function Get-UserToken { ... }` definition; `Get-UserToken -UserId $u` calls; `$result = Get-UserToken ...` assignment form. The verb-noun convention (`Get-`, `Set-`, `New-`, `Remove-`, etc.) is strongly enforced by community style and PowerShell's discovery mechanism (`Get-Command`). A G7 rename that changes the verb is a semantic change, not just a textual rename — consumers calling the old verb may have different user expectations than consumers of the new verb.

**Collision-risk note:**

- **Method-name collisions across unrelated classes.** A function `get_token()` defined at module level shares a grep pattern with any method `obj.get_token()` across any class. Word-boundary alone does not disambiguate. The Python-specific sharpening (`\bdef\s+get_token\b|\bget_token\s*\(`) reduces collision but cannot eliminate method-name collisions entirely when the method name is the same as the function name.
- **Dunder and decorator collisions.** `__init__`, `__str__`, and decorator names (`@property`, `@staticmethod`) are overloaded across a codebase. Do not apply G7 Grep-First to dunder methods; the pattern cannot distinguish a rename of one class's `__str__` from another class's `__str__`. Scope the change by class name first (`class UserToken:`), then apply targeted edits within the class's line range.
- **False negatives through dynamic dispatch** — `getattr(obj, method_name)`, `obj.__class__.__name__`, `importlib.import_module` — hide function/class references from grep. Out of scope per section 2.
- **False-positive guidance.** Short function names (`run`, `get`, `main`, `init`) have unmanageable false-positive rates. The three options from G6 apply: rename before Grep-First, tighten with a module prefix (`module\.run`), or accept the step-3 cost.

**Worked template — Renaming function `get_user_token` to `fetch_user_token`:**

Assume the function is defined in `src/auth.py` and called from 6 files, with no formal `<CONTRACT>` block (if a CONTRACT block existed, IT's Change Impact Protocol would apply instead of G7's general protocol).

- **Step 1 (Grep).** `rg -n '\bget_user_token\b' -t py` returns 14 hits: 1 definition, 11 call sites across 6 files, 2 docstring references (one in the function's own docstring, one in a module docstring that lists exported names).
- **Step 2 (Classify).** 1 definition AFFECTED. 11 call sites AFFECTED. 1 function-own-docstring reference AFFECTED (self-reference in its own docstring — rename in the same edit). 1 module docstring AFFECTED.

  But: inspect the call sites. One of them is `get_user_token_cached = functools.lru_cache(get_user_token)` — the function is being wrapped, and the wrapping-reference is a legitimate consumer. AFFECTED (the wrapping line needs to name `fetch_user_token`). Another is `help(get_user_token)` inside a test — also AFFECTED. Neither is a surprise, but both illustrate that "call site" includes more than just bare invocations.
- **Step 3 (Resolve UNCLEAR).** Zero UNCLEAR in this template, but a real codebase often produces UNCLEAR entries at this step for reflection-style uses. Time budget at step 3 is typically larger for G7 than for 5A or 5B categories.
- **Step 4 (Change).** Consumers-first: 11 call sites + 1 wrapping line + 1 `help()` call + 2 docstrings. Then definition. Commit in two steps.
- **Step 5 (Grep-verify).** `rg -n '\bget_user_token\b' -t py` returns zero hits. `rg -n '\bfetch_user_token\b' -t py` returns 14 hits — matches expected.

**What this template teaches:** "call site" in G7 includes more than bare invocations — wrapping references, `help()` and `inspect` calls, docstring self-references. The canonical pattern surfaces all of them; the classifier recognizes each as a legitimate consumer that must update. When a function has a formal `<CONTRACT>` block, the IT specialization applies with additional artifacts (USES markers, Integration Map); when it doesn't, the general G7 form covers the rename safely.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G8 — Type Definitions

Named types shared across a codebase. Example forms: `class UserToken:` (Python), `type UserToken = ...` (TypeScript), `[PSCustomObject]@{ ... }` (PowerShell — ad hoc) or class-based PowerShell types. Bash has no type system and substitutes per the `STACK_TRACE` precedent.

**Canonical grep pattern:**

```bash
# Python type reference — rg (class name in annotations and imports):
rg -n '\bUserToken\b' -t py

# Python-specific tightened forms (definition, annotation, isinstance):
rg -n 'class\s+UserToken\b|:\s*UserToken\b|isinstance\([^,]+,\s*UserToken\)' -t py

# PowerShell class reference — rg:
rg -n '\[UserToken\]|class\s+UserToken\b' -t ps1

# Portable grep fallback (general form):
grep -rn --include='*.py' --include='*.ps1' -E '\bUserToken\b' .
```

The general `\bUserToken\b` query is the primary enumerator — it finds the class in imports, annotations, `isinstance` checks, and bare type references. The tightened forms sharpen when the general pattern produces too many false positives (e.g., when the type name is a common word like `Status` or `Result`).

**Per-language notes:**

- **Python:** class definitions, type annotations (`def f() -> UserToken:`, `x: UserToken = ...`), generic parameters (`List[UserToken]`), `isinstance` checks, `TYPE_CHECKING` imports. The `\b` pattern catches all of these; the tightened forms are refinements for common-name disambiguation.
- **PowerShell:** classes defined via `class UserToken { ... }` are referenced as `[UserToken]` in type literals and parameter attributes. The canonical query combines both forms.
- **Bash:** **cross-language substitution.** Bash has no type system. The substitute discipline is documented conventions — a Bash function that produces a particular stdout shape documents that shape in its CONTRACT block (see `reference/bash.md § CONTRACT Block for Cross-File Units`) and in its caller's USES marker. Renaming a "type" in Bash means renaming the documented shape, which is a composite operation across G3 (keys in the documented structure) and G1 (error codes that reference the shape). Bash consumers of a type do not appear in a `rg '\bUserToken\b' -t sh` query — the absence of hits is expected, not a false negative. Follow the `STACK_TRACE` substitution precedent in `log_vocabulary.md`: document the asymmetry rather than pretend uniformity.

**Collision-risk note:**

- **Type-name collisions with unrelated module-level identifiers.** A type named `Result` collides with variables, functions, and other types named `Result` across the codebase. For common type names, tighten with `class\s+Result\b|:\s*Result\b` to restrict to definition and annotation sites.
- **TYPE_CHECKING imports.** Python's `if TYPE_CHECKING:` block imports types only for static analysis. These imports look textually identical to runtime imports but are semantically different — a rename that misses a `TYPE_CHECKING` import causes type-check failures without runtime failures. Classifier marks both AFFECTED.
- **Generic parameters and forward references.** `List["UserToken"]` (forward reference as string), `TypeVar('UserTokenT', bound=UserToken)`. Forward references in strings are invisible to the bare `\bUserToken\b` pattern; the canonical query with quoted form `["'\'']UserToken["'\'']` catches them but produces documentation-string false positives.

**Worked template — Renaming type `UserToken` to `BearerToken`:**

Assume the class is defined in `src/auth/tokens.py` and referenced across 8 Python files as type annotations, imports, and `isinstance` checks. No Bash or PowerShell consumers.

- **Step 1 (Grep).** `rg -n '\bUserToken\b' -t py` returns 22 hits across 9 files: 1 class definition, 4 imports, 12 type annotations, 3 `isinstance` checks, 2 forward-reference strings (`List["UserToken"]`).
- **Step 2 (Classify).** All 22 AFFECTED. The forward-reference strings require the quoted-form query to catch reliably — classifier notes this and confirms both forward references are in the hit set.
- **Step 3 (Resolve UNCLEAR).** Zero UNCLEAR.
- **Step 4 (Change).** Consumers-first: imports, annotations, `isinstance`, forward references. Then definition. Python's import system does not allow the class to be renamed at the definition before import sites are updated — a mid-refactor state with the definition renamed breaks every import.
- **Step 5 (Grep-verify).** `rg -n '\bUserToken\b' -t py` returns zero hits. `rg -n '\bBearerToken\b' -t py` returns 22 hits — matches expected. Also verify forward-reference strings specifically: `rg -n '["'\'']BearerToken["'\'']' -t py` returns 2 hits.

**What this template teaches:** type-definition renames produce the largest candidate consumer set of any category in 5C because types appear in annotations on almost every consumer. Forward references in string form require a secondary verification query — the bare word-boundary pattern catches the class in most forms, but not inside string literals.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

### G9 — File Paths Referenced Across Scripts

File paths referenced from multiple scripts — input/output paths, config-file paths, log directories, helper-script locations. Example forms: `/var/log/myapp/run.log`, `./config/default.yaml`, `$PROJECT_ROOT/scripts/helper.sh`, `src/auth/tokens.py` as an import path.

**Canonical grep pattern:**

```bash
# Quoted path fragment — rg (catches most literal references):
rg -n '["'\''`]/var/log/myapp/' -t py -t sh -t ps1 -t yaml -t json

# Path fragment with leading directory anchor (tightens against substring collisions):
rg -n '\bconfig/default\.yaml\b' -t py -t sh -t ps1 -t yaml

# Portable grep fallback:
grep -rn --include='*.py' --include='*.sh' --include='*.ps1' \
    --include='*.yaml' --include='*.yml' --include='*.json' \
    -E '/var/log/myapp/' .
```

Paths are the highest-false-positive category of any in this file. A fragment like `config/default.yaml` substring-matches inside any longer path ending in the same fragment (`shared/config/default.yaml`, `vendor/config/default.yaml`). The `\b` word-boundary pattern is less useful here because path separators (`/`) aren't word characters — bare `\bconfig\b` matches every occurrence of the word "config" in prose, which is far too loose.

**Per-language notes:**

- **Python:** paths typically appear as strings (`"config/default.yaml"`) or `pathlib.Path` constructors (`Path("config/default.yaml")`). The quoted-string canonical query catches both.
- **Bash:** paths appear unquoted (`source ./config/default.yaml`), double-quoted (`"$HOME/config/default.yaml"`), or constructed from variables (`"${CONFIG_DIR}/default.yaml"`). The quoted canonical query catches the first two; constructed paths are invisible and the canonical query for the fragment (`config/default.yaml`) catches them only when the full fragment appears literally.
- **PowerShell:** paths appear in `-Path` parameters, `Join-Path` calls, and string concatenations. Separator convention is a per-platform concern: `/` works on PowerShell 7+ cross-platform; `\` is Windows-only. The canonical query pattern uses `/`; a Windows-specific query uses `\\` in regex (escape `\\\\` for shell) to catch the backslash form.

**Collision-risk note:**

- **High false-positive rate** by default. Short path fragments (`src/`, `logs/`, `lib/`) match inside longer paths across the codebase. The sharpening disciplines: use the longest unique path fragment (`src/auth/tokens.py` rather than `tokens.py`); include the leading directory anchor (`\bconfig/default\.yaml\b`); include the quote or backtick boundary (`["'\''`]config/default\.yaml`).
- **Cross-platform separator issues.** A path written with `/` in a cross-platform codebase may also exist written with `\` in a Windows-specific module. The canonical query misses the `\`-separated form. Verify with a secondary query when the codebase includes Windows-specific paths.
- **Path construction via variables.** `Path(CONFIG_DIR) / "default.yaml"`, `"$HOME/" + relative_path`, `Join-Path $env:HOME $filename`. These are invisible to the canonical query when the full literal path doesn't appear. Out of scope for Grep-First — the discipline is upstream: prefer full-path literals when the path is stable.
- **Documentation and README references.** Path references in READMEs are authoritative when the path is a user-facing convention (e.g., "config files go in `config/`"). Classifier marks AFFECTED when the documentation describes the new location.
- **False-positive guidance.** The three standard options apply: rename path to something more specific, tighten with directory-anchor boundaries, or accept the step-3 cost. For paths, there is a fourth option specific to this category: introduce a constant that captures the path (`CONFIG_FILE = "config/default.yaml"`), which converts future renames from G9 (high false-positive) to G6 (moderate false-positive). When the path is referenced from 5+ sites, the constant pays for itself on the first rename.

**Worked template — Relocating `logs/run.log` to `/var/log/myapp/run.log`:**

Assume the old path is referenced from 3 Python scripts, 2 Bash scripts, 1 docker-compose volume mount, and 1 README section.

- **Step 1 (Grep).** `rg -n '["'\''`]logs/run\.log\b' -t py -t sh -t yaml` returns 6 hits: 3 Python references, 2 Bash references, 1 docker-compose volume mount. The README reference uses the fragment without surrounding quotes (narrative prose), so the canonical quoted-form query misses it — a secondary query `rg -n '\blogs/run\.log\b' -t md` catches it. 7 hits total.
- **Step 2 (Classify).** 6 AFFECTED in code and compose. 1 README AFFECTED. Zero UNCLEAR.
- **Step 3 (Resolve UNCLEAR).** Skip.
- **Step 4 (Change).** Definitions-first here: update the docker-compose mount to the new path. Then code consumers (Python and Bash). Then README. The compose mount is the infrastructure anchor — a mismatch between compose and code produces a runtime mount failure that fails fast (acceptable; the protocol aims for zero mismatch, but fail-fast mismatches are self-correcting during verification).
- **Step 5 (Grep-verify).** Both queries return zero hits for the old path. `rg -n '["'\''`]/var/log/myapp/run\.log\b' -t py -t sh -t yaml` returns 6 hits; the README query for the new path returns 1 hit. Matches expected.

**What this template teaches:** paths are exceptional among V5.2 categories in that (a) the canonical query needs more than one form to catch all consumers (quoted literal + narrative prose), and (b) moving infrastructure anchors (mount points, working directories) follow a definitions-first ordering rather than the consumers-first default. When paths appear frequently across a codebase, the G6-style discipline of naming them (constants, config keys) is usually a higher-leverage fix than repeated G9 applications.

**Case Studies**

*(This section is intentionally empty at V5.2 launch.)*

Real case studies from actual debugging incidents will be added here as they occur, following the gatekeeping rule in section 8.

---

## Relationship to Integration Tracking

Integration Tracking (`reference/integration-tracking.md`) applies the Grep-First discipline to function contracts specifically — tracking parameters, return shapes, and renames through formal `<CONTRACT>` blocks, `<USES>` markers, and an Integration Map artifact at project root. It is the most-developed specialization of Grep-First.

When function contract changes are in scope, use Integration Tracking's Change Impact Protocol. When any other shared textual element is in scope, use the general Grep-First protocol defined here.

**What Integration Tracking adds beyond this file:**

- **Runtime markers** (`<CONTRACT>`, `<USES>`) that consumers place in source code. Grep-First operates at the textual level without requiring consumers to declare their usage.
- **Consumer-field granularity.** USES markers with `fields="..."` attributes surface return-shape dependencies that are otherwise invisible to grep — a consumer reading `.Token` and `.ExpiresAt` off a contract's return declares those fields explicitly. The general G7 form does not provide this; it surfaces call sites but does not distinguish which return fields each consumer uses.
- **An integration-map artifact.** `.integration-map.md` at project root consolidates contracts and consumers in one auditable place. Grep-First has no stateful artifact — the canonical query against the current codebase is the single source of truth, which iterates more cheaply but lacks the historical audit trail the integration map provides.
- **Tiered enforcement gates.** `scope="public"` contracts enforce strict classification (zero UNCLEAR consumers); `scope="internal"` contracts allow explicit-acknowledgment proceeding. Grep-First operates one level below declared contracts and does not distinguish enforcement tiers.
- **Runnable drift detectors.** `verify-integrations.ps1` / `verify-integrations.sh` detect three classes of drift between code markers and the integration map. Grep-First at V5.2 ships no helper (see `<devlog:2026-04-22:v5-2-no-helper-at-launch>`); the canonical query is run directly against the codebase as needed.

**When to graduate from Grep-First to Integration Tracking:** a function that was initially handled by G7 should receive a formal `<CONTRACT>` block once it crosses the cross-file-called public-contract threshold documented in `integration-tracking.md`. After the CONTRACT block is in place, subsequent changes to that function follow IT's Change Impact Protocol rather than G7's general form.

**Cross-reference asymmetry.** This file names Integration Tracking as a specialization; `integration-tracking.md` itself does not reference Grep-First in its V5.2 form. The asymmetry is deliberate — IT shipped self-contained in V5.0 and V5.2 does not retroactively reshape IT's content. A natural future edit cycle of IT (e.g., when its Case Studies section receives its first real incident) is the appropriate place for a light back-reference to appear, if warranted then.

---

## Extending the Grep-First Vocabulary

The nine invariants G1–G9 cover the shared-textual-element categories that were in scope at V5.2 launch. When a genuinely new category is needed, follow these rules. They mirror `reference/integration-tracking.md`'s "Extending the Contract Vocabulary" and `reference/log_vocabulary.md`'s "Extending the Vocabulary" because the governance problem is the same: vocabularies that accept additions without discipline become noise.

1. **Use the existing category set first.** Before proposing a G10, verify that none of G1–G9 covers the textual element in question. Many candidates that feel new map onto existing categories — a "route prefix" is G4 (API endpoints); a "database table name" is G3 (config keys) or G6 (constants) depending on how it's referenced; a "secret key name" is G5 (env var names) when stored in environment, G6 when stored as a named constant.

2. **Require a real incident before adding a category.** The gatekeeping rule for invariants mirrors the gatekeeping rule for case studies in section 8: hypothetical categories ("we might someday have...") are not accepted. A new invariant must be motivated by an actual codebase where an existing invariant was insufficient and the resulting rename failure is documented.

3. **New category must have a canonical grep pattern, collision-risk note, and worked template.** Every invariant in section 5 provides all three. A proposal that can specify only the pattern without a worked template is incomplete — the worked template is the L2 check that the pattern actually surfaces the consumers it claims to.

4. **Grep-test the worked template against the canonical pattern before proposal.** The L2 format-drift-in-self-authored-patches failure mode specifically targets the author-writes-pattern-and-example-together axis. Run the pattern against the template's identifiers and confirm every reference is caught. If the pattern misses a reference, either the pattern is wrong or the example uses a form outside the invariant's scope — either way the proposal is not ready.

5. **Bump the Grep-First vocabulary version.** A new invariant is a vocabulary extension, which per the governance rule in section 3 requires a version bump. V5.2 is version 1 of the vocabulary; a V5.3+ that adds G10 bumps the Grep-First vocabulary version and documents the addition in the skill_development log.

6. **Document cross-language substitutions.** If a new invariant cannot be implemented uniformly across Bash, Python, and PowerShell, follow G8's precedent (itself following `STACK_TRACE` in `log_vocabulary.md`): document the asymmetry rather than pretend uniformity.

7. **Prefer extension over invention.** A proposed new invariant should either (a) have at least two independent real incidents demonstrating need, or (b) cover a textual-element category that G1–G9 structurally cannot accommodate. "It would be nice to formalize..." is not sufficient. The value of the vocabulary is its closure; every addition dilutes that value unless it pulls its weight.

**Revising an existing invariant** follows a similar but distinct process. Changes to a canonical pattern, collision-risk note, or worked template must update every example in the file in a single commit (per section 3's Governance Rule), and must pass the L2 grep-test against the revised pattern before shipping. A partial revision — new pattern, old examples — is worse than the original because the examples no longer demonstrate what the pattern claims.

---

## How to Add a Case Study to This File

Each per-category sub-section in section 5 reserves a Case Studies slot. Real case studies are added to the appropriate slot as incidents accumulate. This file launches with every Case Studies slot intentionally empty per `<devlog:2026-04-22:illustrative-templates-launch>` precedent — the Worked Templates in section 5 teach the protocol mechanics; Case Studies are reserved for real institutional memory.

**Gatekeeping rule — real incidents only.** A case study must document a real event from a codebase's actual development — a rename that failed and traced back to a missed consumer, a rename that the protocol caught that would otherwise have shipped broken, or a protocol step that surfaced a category-specific lesson. Hypothetical scenarios, invented examples, and "this could happen" patterns are not allowed — they dilute the signal that makes case studies institutional memory rather than decoration. This rule mirrors `reference/prove_first.md`'s and `reference/integration-tracking.md`'s gatekeeping and serves the same purpose.

### The Six-Field Schema

Each case study records:

1. **Situation.** What was being renamed, in which category (G1–G9), across what codebase scope. State the language(s), approximate consumer count if known, and whether formal `<CONTRACT>` markers were present (which routes the case to Integration Tracking instead).
2. **What went wrong.** The failure mode that occurred — missed consumer, false-positive misclassification, UNCLEAR entry that should have been AFFECTED, step-5 verification that passed but shouldn't have. Include time lost and whether the protocol was followed completely or shortcut at some step.
3. **Root cause.** The specific protocol step that missed the issue, or the specific category characteristic that enabled the failure. State it plainly. "Grep missed a consumer" is a symptom; the root cause is usually one of: dynamic dispatch (out of scope — acknowledge and move on); pattern scope too narrow (document refinement); classifier mis-assessed semantic role (add to the category's classification-judgment guidance).
4. **What the protocol would have caught, or what the protocol gap is.** If a step was skipped, name it. If the protocol was followed completely and the failure still occurred, the gap is a real architectural finding — flag for dev-log capture.
5. **Lesson encoded.** Cross-reference to the skill_development log entry, the category's collision-risk note update, or the protocol revision where the learning now lives.
6. **Generalizable rule.** The pattern other sessions should recognize. One or two sentences that stand alone without the incident.

The schema mirrors `prove_first.md`'s and `integration-tracking.md`'s six-field schemas. Consistency across the skill's case-study sections means a reader familiar with one is immediately oriented in the others.

### When Not to Add a Case Study

If the incident is a routine protocol success (the protocol caught the issue as designed with no category-specific lesson), a case study is not warranted — routine successes belong in commit messages or Development Notes, not in institutional memory.

If the incident reveals a bug in the canonical pattern itself (the pattern as written doesn't do what the invariant claims), that is a format-contract drift incident: fix the pattern under section 3's Governance Rule, grep-test the revised pattern against every worked template, capture the fix in the skill_development log. Case studies document *application* of the protocol, not drafting errors in the file itself.

If the incident is specific to Integration Tracking's function-contract scope (cross-file-called public contracts with formal markers), the case study belongs in `reference/integration-tracking.md § Case Studies`, not here. Category G7 is the Grep-First form for function/class names without formal contracts; once CONTRACT blocks are in place, Integration Tracking is the specialization that applies.
