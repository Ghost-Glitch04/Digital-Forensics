# Log Prefix Vocabulary — Full Reference

This file holds the complete log prefix table, useful grep patterns, and rules for extending the vocabulary. SKILL.md keeps only the core prefixes every script needs; load this file when you are adding new prefixes, writing advanced grep queries, or auditing an existing script's logging discipline.

**Every log entry uses a consistent prefix so logs are greppable and self-describing.** Use these exact prefixes — don't invent new ones without adding them to this table. A one-off prefix invented for a single script is a papercut that compounds across the codebase; every grep that misses it is a debugging round the next session pays for.

---

## Full Prefix Table

| Prefix | Level | Meaning |
|---|---|---|
| `SCRIPT_START` | INFO | Script has begun; user, host, and version follow |
| `SCRIPT_COMPLETE` | INFO | Script finished successfully; total duration follows |
| `SCRIPT_FAILED` | FATAL | Unhandled error terminated the script |
| `ENV_SNAPSHOT` | INFO | Runtime environment captured (OS, version, working dir) |
| `PARAMS` | INFO | All parameter values at time of execution |
| `PHASE_START` | INFO | A named phase has begun |
| `PHASE_SUMMARY` | INFO | What the phase produced, logged before PHASE_END |
| `PHASE_END` | INFO | Phase complete; phase duration follows |
| `PHASE_GATE` | INFO | Script stopped cleanly at a requested phase boundary |
| `UNIT_START` | INFO | A named unit has begun; key inputs follow |
| `UNIT_END` | INFO | Unit complete; duration follows |
| `UNIT_FAILED` | ERROR | Unit failed; error, inputs, line number, exit code follow |
| `DEPENDENCY_MISSING` | FATAL | A required upstream unit did not run or produced no output |
| `VERIFY_OK` | INFO | A verification check passed |
| `VERIFY_FAILED` | ERROR | A verification check failed; path/detail follows |
| `VERIFY_WARN` | WARN | Verification passed but with an unexpected condition |
| `RECORD_FAILED` | ERROR | A specific record failed processing; record ID follows |
| `RETRY` | DEBUG | An operation is being attempted (attempt N of N) |
| `RETRY_WAIT` | WARN | An attempt failed; waiting before next retry |
| `RETRY_EXHAUSTED` | ERROR | All retry attempts failed |
| `STACK_TRACE` | DEBUG | Full exception stack trace — Python (`traceback.format_exc()`) / PowerShell (`$_.ScriptStackTrace`); Bash has no stack-trace mechanism, emits `$LINENO` + `$BASH_COMMAND` in the ERR trap instead. File always; console only in debug mode |
| `[DRY-RUN]` | INFO | Action that would have occurred in a live run |
| `FULL_SUCCESS` | INFO | All records in a collection processed successfully |
| `PARTIAL_SUCCESS` | WARN | Some records failed, but within the configured threshold |
| `FAILURE` | ERROR | Record failure rate exceeded configured threshold |
| `CONTRACT_DRIFT` | ERROR | Drift detected between `<CONTRACT>`/`<USES>` markers in code and `.integration-map.md` entries. Direction, contract_id, and location follow in key=value fields. Downgraded to WARN when `# DRIFT-EXPECTED:` is present at the top of the map. Emitted by `verify-integrations.ps1` / `verify-integrations.sh`. |
| `INTEGRATION_MAP_UPDATED` | INFO | Integration Map verified as current — zero drift across all three directions (code-ahead-of-map, map-ahead-of-code, version-mismatch). Emitted by the same helpers on a clean verification run. |

---

## Useful Grep Patterns

Every standard script in this codebase responds to the patterns below. Copy-paste as needed.

```bash
# All failures in a run — the fastest triage query:
grep -E "UNIT_FAILED|RECORD_FAILED|VERIFY_FAILED|RETRY_EXHAUSTED|FAILURE" run.log

# Phase timing profile — where did the script spend its time?
grep "PHASE_END" run.log

# Every record that failed processing:
grep "RECORD_FAILED" run.log

# Partial-success outcome classification:
grep -E "FULL_SUCCESS|PARTIAL_SUCCESS|FAILURE" run.log

# Full trace for one named unit (lifecycle + any failures):
grep "validate_input" run.log

# Every retry attempt and its wait:
grep -E "RETRY|RETRY_WAIT|RETRY_EXHAUSTED" run.log

# All verification outcomes (good and bad):
grep -E "VERIFY_OK|VERIFY_FAILED|VERIFY_WARN" run.log

# Dry-run trace — what would have happened in a live run:
grep "\[DRY-RUN\]" run.log

# Everything FATAL — the script couldn't recover:
grep -E "SCRIPT_FAILED|DEPENDENCY_MISSING" run.log

# Script entry/exit only — quick "was this run OK?" glance:
grep -E "SCRIPT_START|SCRIPT_COMPLETE|SCRIPT_FAILED|PHASE_GATE" run.log
```

**Cross-language note.** These patterns rely on consistent level names across Python, Bash, and PowerShell. Python's `logging` module ships with `WARNING` and `CRITICAL` as default level names, which break `grep -E "WARN|FATAL"` across mixed-language logs. Normalize with two lines at Python import time:

```python
import logging
logging.addLevelName(logging.WARNING, "WARN")
logging.addLevelName(logging.CRITICAL, "FATAL")
```

Bash and PowerShell already emit `WARN`/`FATAL` directly. Without the Python normalization, a triage grep would silently miss every Python warning in a mixed-language run — a silent-failure mode the minimal scaffold in `minimal_scripts.md` now fixes by default.

---

## Extending the Vocabulary

When a new prefix is needed, follow these rules:

1. **Use `UPPER_SNAKE_CASE` exclusively.** No lowercase prefixes, no mixed case, no spaces. The regex pattern `^[A-Z][A-Z0-9_]+:` should match every prefix in every log this skill produces.

2. **One concept per prefix.** If you're tempted to invent `UNIT_FAILED_RETRY`, you don't need a new prefix — emit `RETRY_EXHAUSTED` followed by `UNIT_FAILED`. Prefixes compose in the log by adjacency, not by hyphenation.

3. **Add to this table before you commit the code.** A prefix that exists in one script and not in the vocabulary reference is a papercut that hides from grep. The moment a prefix proves useful in a second script, it graduates to this table.

4. **One-off prefixes must be documented in the script header.** If a script legitimately needs a domain-specific prefix (e.g., a certificate-scanner script that emits `CERT_EXPIRED`), keep it scoped to that script but state it explicitly at the top of the script so cold readers aren't surprised.

5. **Prefer extension over invention.** Before adding a new prefix, check if an existing one fits. `VERIFY_WARN` covers "check passed with an unexpected condition" — you don't need `VERIFY_ANOMALY`. `PARTIAL_SUCCESS` already covers "some worked, some didn't" — you don't need `MIXED_RESULT`.

6. **Document cross-language substitutions.** If a prefix can't be implemented consistently across all three languages — because the language genuinely lacks the underlying mechanism — annotate the prefix's row in the full table with the substitution. Triage greps that expect the prefix universally will silently miss one language otherwise. Example: `STACK_TRACE` is emitted by Python (`traceback.format_exc()`) and PowerShell (`$_.ScriptStackTrace`) but not by Bash (which has no call-stack mechanism; Bash emits `$LINENO` + `$BASH_COMMAND` in the ERR trap instead). Both are correct for their language; the asymmetry must be documented rather than pretended away.

---

## Format Contract

Every prefixed log line follows this shape:

```
[YYYY-MM-DD HH:MM:SS] [LEVEL] PREFIX: key=value | key=value | ...
```

- The **timestamp** and **level** appear in square brackets, separated by a single space.
- The **prefix** is immediately followed by a colon and a single space.
- **Fields** are separated by ` | ` (space-pipe-space). No trailing pipe.
- **Values containing spaces** are not quoted — readability wins over machine parseability at this level. If you need machine-readable output, emit a separate JSON artifact alongside the human log.

### Field Styles

Two field styles are both valid; pick whichever fits the field:

- **Identifier form — `key=value`.** Use for data-like fields that triage greps will target directly: paths, IDs, counts, durations-as-numbers, flag states. Keys are **lowercase_snake_case** regardless of the source language's naming convention, so cross-language greps work uniformly. A PowerShell script logs `inputpath=$InputPath`, not `InputPath=$InputPath`, even though PowerShell's native convention is PascalCase.
- **Label form — `Label: value`.** Use for human-readable summaries where the reader is scanning the log top-to-bottom: user names, host names, durations-with-unit-word, status strings. Label is written in natural case (`User:`, `Host:`, `Total Duration:`) — readability is the priority for these fields.

Within a single log line, mixing the two styles is fine (the examples below do it). Don't pick one style and force it on fields where the other reads better.

Examples:

```
[2026-04-11 09:14:02] [INFO] SCRIPT_START: minimal_example.py | User: talos | Host: htb-box
[2026-04-11 09:14:02] [INFO] UNIT_START: validate_input | path=/tmp/in.csv
[2026-04-11 09:14:03] [ERROR] UNIT_FAILED: validate_input | path=/tmp/in.csv | reason=file_not_found | exit=10
[2026-04-11 09:14:03] [FATAL] SCRIPT_FAILED: Unhandled error | duration=1.204s
```

The log helper in each language reference file (`python.md`, `bash.md`, `powershell.md`) implements this format exactly. If you're writing a script outside those three languages, replicate the format — don't invent a new one.

---

## Why This File Exists Separately from SKILL.md

V4_4 carried the full 25-row table inside SKILL.md, where it loaded on every session even when nobody was auditing log output. The table is a **reference**, not a rule the session needs to internalize — most of these prefixes are emitted automatically by the log helpers. Hoisting the full table into this file and keeping only ~8 core prefixes in SKILL.md is a context-budget discipline: load-on-demand content stays out of the per-session tax.

If a future session finds itself actually using the full table more than once per week, reconsider the hoist. Otherwise, this file is the right home for it.
