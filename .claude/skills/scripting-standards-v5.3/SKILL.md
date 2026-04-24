---
name: scripting-standards
description: Apply Ghost's scripting standards to any PowerShell, Bash, or Python script work — new scripts, extensions, debugging, refactoring, and associated test code. Emphasizes prove-first development, minimal-first scaffolding, fail-fast design, phased deployment, structured logging, dry-run mode, idempotency-aware retry, result verification, and session-resumable Development Notes. Apply even when the user doesn't explicitly ask.
---

# Scripting Standards

Ghost's philosophy: **code you can trust is code you can see — and verify**. Every script should be auditable, self-documenting, designed to surface its own failures immediately, and able to prove its outputs are what they claim to be.

Apply these standards to all PowerShell, Bash, and Python work — and to associated test code — unless Ghost explicitly says otherwise.

---

## How This Skill Is Organized

SKILL.md contains principles and decision rules. The reference files hold copy-paste implementations and deep examples — load them on demand.

| Reference file | Load when |
|---|---|
| [minimal_scripts.md](./reference/minimal_scripts.md) | Starting a new script (3-language minimal scaffolds — 30–80 lines each) |
| [python.md](./reference/python.md) / [bash.md](./reference/bash.md) / [powershell.md](./reference/powershell.md) | Writing or debugging in that language — each file holds both the helper functions and the **full phased template** (preflight / collection / processing / output / verification) that a minimal script grows into when it outgrows the scaffold |
| [prove_first.md](./reference/prove_first.md) | An unverified assumption is about to drive multiple units |
| [testing.md](./reference/testing.md) | Writing or debugging tests |
| [grep_first.md](./reference/grep_first.md) | Renaming or restructuring any shared textual element — error codes, log prefixes, config keys, API endpoints, constants, function/class names, type definitions, env var names, file paths |
| [integration-tracking.md](./reference/integration-tracking.md) | Changing a function's parameters, return type, return shape, or a shared variable/constant — especially when called from multiple files |
| [troubleshooting.md](./reference/troubleshooting.md) | An approach failed twice, or resuming an existing script |
| [log_vocabulary.md](./reference/log_vocabulary.md) | Adding log prefixes, writing grep queries, auditing log discipline |

**Context discipline:** reference files are substantial. A session that loads every reference up front has wasted a significant portion of its context budget before writing a line of code.

**Skill development memory:** a separate `skill_development/` tree carries institutional memory about the skill's own evolution (developer log, lessons learned). Almost never loaded during normal work. See "Skill Development Memory" below.

---

## CLAUDE.md Precedence

When a project-level `CLAUDE.md` rule contradicts or extends anything here, **CLAUDE.md wins**. This skill is the general standard; CLAUDE.md is the project-specific specialization (log directories, forbidden tools, non-standard error codes). Respect the project.

---

## When NOT to Write a Script

Some tasks are correctly solved by a single command, not a 40-line script with a unit timer and an error-code block. Over-engineering a trivial task into ceremony is a failure mode of this skill.

**Use a direct command when:** the task is a one-off you won't repeat; the logic fits in a single readable line with no side effects worth guarding; the failure mode is obvious from the tool's own output; you are exploring, not building.

**Write a script when:** you will run it more than twice (or someone else will); the task has side effects that need a dry-run guard; the task has multiple steps worth auditing independently; the failure mode is silent or delayed and needs structured logging; the output needs verification before a downstream step consumes it.

**Rule of thumb:** if the dry-run scaffolding costs more lines than the work itself and the task is a one-off, the script is ceremony. Write the command, run it, move on. The standards below are tools for scripts that deserve to exist — not a reason to promote every command into one.

---

## Preflight: Permissions and Capabilities

Before writing functional code, surface the needed permissions and external access to Ghost: log file writes, elevated rights (`sudo`, `Set-ExecutionPolicy`), access to external systems or paths, tool dependencies that must be installed. In agent sessions, if CLAUDE.md or prior conversation has already granted these, verify they're still current rather than asking again. The rule is *don't assume access* — not *always ask*.

---

## The Minimal Script

**Start here.** Most scripts do not need phase gates, verification units, and a Main block. A minimal script is 30–80 lines and includes: header comment, error code block, log helper (file always, console gated by `--debug`), argument parsing (at minimum `--dry-run` and `--debug` when there are side effects), environment snapshot + `SCRIPT_START`, fail-fast input validation, the work itself with `[DRY-RUN]` guards on any write, and `SCRIPT_COMPLETE` with total duration.

A minimal script that follows these rules is a complete, standard-compliant answer. See [reference/minimal_scripts.md](./reference/minimal_scripts.md) for copy-paste scaffolds in all three languages. Both the minimal scaffolds and the full phased templates in `python.md`, `bash.md`, and `powershell.md` have been verified by end-to-end execution; each reference file documents which bugs were caught during verification in its own Verification History section.

---

## When to Grow into the Full Script

Grow from minimal to the full phased template when the script has **two or more** of: external service calls; multi-step data transformations with intermediate state worth verifying; file outputs whose correctness is not obvious; long enough runtime that restarting from scratch is costly; will be run by operators other than the author; will compose into a larger pipeline.

Growing means adding phase gates (`--stop-after-phase`), per-unit timers, result verification units, a retry helper, and the full Main block. **Do not grow prematurely** — a 40-line utility script with phase gates is not more professional, it is harder to read and carries ceremony with no diagnostic value. The full template is a growth path, not a starting point.

---

## Structure: Units

Break scripts into clearly bounded **units** — discrete, named sections that each do one thing completely. Each unit is labeled with a header comment, self-contained enough to read/test/swap independently, and documented with purpose, inputs, outputs, and dependencies. Header format is the same across languages:

```
# ============================================================
# UNIT: validate_input_files
# Purpose : Ensure required input files exist and are readable
# Inputs  : input_path
# Outputs : None (raises / exits on failure)
# Depends : None
# ============================================================
```

---

## Phased Deployment and Phase Gates

Scripts past minimal are built in **phases** — ordered groups of units representing a discrete, verifiable stage of work. Typical shape: **Preflight → Collection → Processing → Output**. Define phases based on what makes sense to test independently, not to hit a fixed number.

Every phase boundary has a **phase gate** (`--stop-after-phase` / `-StopAfterPhase`) that stops the script cleanly at the end of that phase. **Stopping at a gate is exit code 0.** It lets Ghost run one phase at a time, inspect results, then proceed. Each phase tracks its own duration and the gate logs both phase and total duration unconditionally.

```
[INFO] PHASE_START:   Preflight
[INFO] PHASE_SUMMARY: Preflight | Connection: verified | Input records: 847
[INFO] PHASE_END:     Preflight | Phase Duration: 3.2s
[INFO] PHASE_GATE:    Stopping cleanly after phase 'Preflight' | Total Duration: 3.2s
```

See the language reference files for `Invoke-PhaseStart` / `invoke_phase_start` / `invoke_phase_gate` implementations.

---

## Fail Fast

Units must fail immediately and loudly. Never let a failure silently pass and corrupt downstream steps. Validate inputs at the start of each unit. On failure, log `UNIT_FAILED` with context, emit a distinct exit code, stop. Dependencies are especially critical — a quiet failure in a dependency produces a hard-to-trace chain.

Use distinct, documented exit codes. Keep a reference block at the top of every script — typical scheme: `0` success, `10` input not found, `11` input unreadable, `20` processing failure, `30` connection failed, `40` verification failed, `50` retry exhausted, `99` unhandled error.

**Fail Fast is NOT "exit on any error."** For collection processing where some per-record failures are expected and non-fatal, see **Partial Success Standard** below. Fail Fast applies to unrecoverable failures: corruption, missing dependencies, connection loss, contract violations.

---

## Prove-First Development

The most expensive rework comes from building multiple units on top of an untested assumption, then discovering the assumption was wrong after significant time has been spent. **Prove the core assumption before investing in full unit construction.**

**The rule.** Any function, feature, or tool integration resting on an unverified assumption must have a minimal proof-of-concept tested before the full unit is built around it. "Minimal" means the smallest standalone test that confirms or disproves the assumption — relative to the cost of the full unit, not an absolute line count.

**Recognizing the moment.** **"I'm about to write a test (or unit) that imports N modules and sets up M fixtures to assert something I've never verified in isolation."** That is the moment to stop and prove. Common patterns: asserting on a framework's internal behavior you've never inspected (Celery request context, SQLAlchemy autoflush, Jinja2 autoescape); calling an external API whose response shape you know only from docs; parsing a data file whose format you've assumed; wrapping a CLI tool whose output or **runtime** you've never captured directly.

**Method.** In an agent session, "minimal standalone test" means a one-off Bash-tool invocation — `python -c`, `inspect.getsource`, a `curl`, a scratch file in `/tmp`, a `REPL` session. The time budget is usually **under a minute of wall time**. If proving the assumption is going to take longer than the rework you'd avoid, skip it.

**When proving is unnecessary.** The operation is well-understood from prior work; the assumption is trivially verifiable within the unit itself (e.g., file existence); the unit is simple enough that rework costs less than a proof step.

Prove-first is the preventive counterpart to **Fail Fast** (catches bad assumptions at runtime) and **When Something Isn't Working** (recovers from failed approaches retrospectively). For case studies — including one where a 60-second `time wpscan ...` run would have prevented a silent timeout from masquerading as a stub bug — see [reference/prove_first.md](./reference/prove_first.md).

---

## Logging

Logging is the primary tool for understanding why code behaved the way it did.

**Log every unit's lifecycle.** Entry: unit name and key inputs. Exit: completion and what it produced. Errors: message, inputs in scope, line reference, exit code.

**Log levels.** `DEBUG` is detailed trace — file always, console only with `--debug` (parameter values inside a unit, per-record processing, stack traces). `INFO` is normal progress (`PHASE_START`/`_END`, `UNIT_START`/`_END`, `VERIFY_OK`, `SCRIPT_START`/`_COMPLETE`). `WARN` is unexpected but recoverable (row count mismatch, retry wait, `PARTIAL_SUCCESS`). `ERROR` is a unit failure (`UNIT_FAILED`, `RECORD_FAILED`, `VERIFY_FAILED`, `RETRY_EXHAUSTED`). `FATAL` is script cannot continue (connection lost, `DEPENDENCY_MISSING`, `SCRIPT_FAILED`).

**Rule of thumb:** if a line appears more than once per record in a collection, it is probably `DEBUG`. If it appears once per phase or script, it is probably `INFO`.

**Log helper requirements.** Always implement logging as a reusable helper (`Write-Log`, `log()`, `setup_logger()`). It must write all levels to the log file always, suppress `DEBUG` from console unless `--debug` is active, and apply consistent timestamp/level formatting. Python's `logging` module defaults level names to `WARNING`/`CRITICAL` — normalize them to `WARN`/`FATAL` at import time with `logging.addLevelName()` so cross-language greps work. The minimal scaffolds in `reference/minimal_scripts.md` do this by default.

---

## Helper Functions

When the same logic appears more than once, extract it into a named helper with a single clear responsibility. Define helpers in a `# HELPERS` section after configuration but before any executable code (required in PowerShell and Bash; good discipline in Python). Include a brief comment describing purpose, inputs, outputs. Apply the same fail-fast principle as units.

---

## Exception Capture

A catch block that logs only the error message is half a diagnosis. Every catch block must record: error message, unit name, input values in scope, stack trace or line reference, exit code. Stack traces go at `DEBUG` level — always to the log file, console only in debug mode. See the language reference files for the unit-timer / exception-capture pattern.

---

## Dry-Run Mode

Every script that writes files, calls APIs, or modifies systems must support a `--dry-run` / `-DryRun` flag. In dry-run mode the script runs all validation and connection verification normally, logs every action it *would* take prefixed with `[DRY-RUN]`, skips all writes and mutations, and exits cleanly. Log `DRY-RUN MODE ACTIVE` prominently at script start.

Dry-run is the single most useful tool for confirming a script will behave correctly before it does anything real.

---

## Debug Verbosity Flag

Every script must support a `--debug` / `-DebugMode` flag that promotes `DEBUG` entries to the console without editing the script. By default `DEBUG` writes to the log file only. Log `DEBUG MODE ACTIVE` at script start when the flag is set.

---

## Retry Logic for Transient Failures

Network blips, rate limits, and token expiry are transient — they may succeed after a short wait. Failing fast on these wastes a full run. Use `Invoke-WithRetry` / `invoke_with_retry` for any operation that touches an external service: configurable attempt count and initial delay, exponential backoff (delay doubles each attempt), log each attempt at `DEBUG` and each wait at `WARN`, log `RETRY_EXHAUSTED` with exit code 50 when all attempts fail.

### Idempotency Rule

**Retry is safe only for idempotent operations:** reads, stable-ID updates, deletes, and operations the remote system deduplicates via an idempotency key. A bare `POST /charges`, `POST /send-email`, or `POST /webhook` is **not safe** to retry blindly.

For unsafe operations: (1) use idempotency keys when the API supports them (Stripe, AWS, most modern APIs) — this converts an unsafe retry into a safe one; (2) if no idempotency key is available, retry only when the server's error response proves the operation did not take effect (a 4xx received before processing, connection refused before the request body was sent); (3) otherwise, do not retry — fail fast and let the operator decide.

A retry wrapper that doubles payments or sends duplicate emails is worse than no retry at all. The idempotency check is not optional.

---

## Environment Snapshot at Startup

Log immediately after `SCRIPT_START`, before any units run. Capture: runtime version, OS, user, host, working directory, script path, and all parameter values (`PARAMS` prefix). Every log file should be self-contained — someone reading it cold should be able to reconstruct the exact conditions the script ran under without asking.

---

## Result Verification

Completing a unit is not the same as confirming it worked. Verify outputs before the next unit runs.

**Connection verification.** Always verify a connection is live and authenticated before dependent work — authenticated identity, correct tenant/scope, required permissions. Log the verified identity; the audit trail should show *who* the script ran as.

**Output file verification.** After writing any file, verify it before moving on. A file that exists but is empty is a silent failure. Check: exists, size > 0, row/line count matches expected, CSV headers and column counts correct. Every verification logs `VERIFY_OK` or `VERIFY_FAILED`.

**Verification as a dedicated unit.** When output verification is non-trivial, give it its own named unit: `[UNIT: Export-Results]` writes the file; `[UNIT: Verify-Results]` confirms it.

---

## Record-Level Error Logging

When a unit processes a collection and one record fails, the log must identify the specific record — ID and display name at minimum — using the `RECORD_FAILED` prefix. Without this, reproducing the failure requires re-running the full script and hoping the same record appears. For fault-tolerant units, collect failures into a list and log the full set at the end rather than stopping on the first one.

---

## Partial Success Standard

When a script processes a collection and some records succeed while others fail, the outcome must be explicitly categorized. Define a failure threshold in the script's configuration block (e.g. `FAILURE_THRESHOLD_PCT = 10`), then at the end of each processing unit, evaluate and log one of three explicit labels:

| Outcome | Log level | Exit | Meaning |
|---|---|---|---|
| `FULL_SUCCESS` | INFO | 0 | All records processed successfully |
| `PARTIAL_SUCCESS` | WARN | 0 | Some failures, within threshold |
| `FAILURE` | ERROR | 20 | Failure rate exceeded threshold |

This makes "a few expected failures" versus "something systematic is wrong" auditable rather than implicit.

---

## Testing Standards

Test code follows the same standards as the script, plus rules specific to testing — patch targets, mock fidelity, handling behavior changes, canary tests, fixture discipline, prove-first applied to calling conventions, test naming, and forward-stability (assertions on contract, not implementation). **Load [reference/testing.md](./reference/testing.md) when writing or debugging tests.** The full rules live there; SKILL.md does not duplicate them.

---

## Grep-First Protocol

Before renaming or restructuring any shared textual element called from more than one location, enumerate the full consumer set via grep *before* the change lands. This prevents the 2-3 pass regression cycle that dominates cross-file renames — pass 1 changes the obvious consumers, pass 2 is the failing test that reveals a missed consumer, pass 3 is the transitive consumer hidden behind it. Grep-First formalizes the enumeration discipline so passes 2 and 3 don't happen.

**Triggers — load [reference/grep_first.md](./reference/grep_first.md) when renaming or restructuring any of:**
- Error codes and exit codes (G1)
- Log prefixes (G2)
- Configuration keys (G3)
- API endpoints and URL patterns (G4)
- Environment variable names (G5)
- Constants and enum values (G6)
- Function and class names without formal `<CONTRACT>` blocks (G7)
- Type definitions (G8)
- File paths referenced across scripts (G9)

**The Protocol (5 steps):** grep for all consumers using the category's canonical query → classify each as AFFECTED / UNAFFECTED / UNCLEAR → resolve every UNCLEAR to certainty → apply the change → re-grep to verify zero stragglers. Full per-category canonical queries, collision-risk notes, and worked templates in `grep_first.md`.

**Relationship to Integration Tracking.** `integration-tracking.md` covers the most-developed specialization of Grep-First — function contracts with formal `<CONTRACT>` blocks, `<USES>` markers, and an Integration Map. When changing a function that already has a CONTRACT block, use Integration Tracking's Change Impact Protocol. When changing any other shared textual element — or a function without a CONTRACT block — use the general Grep-First protocol in `grep_first.md`.

---

## Integration Tracking

When modifying any function contract — signature, return type, return object shape, or a shared variable/constant — follow the Change Impact Protocol before editing. This prevents the 2-3 pass regression cycle that otherwise dominates integration changes, especially when Claude Code is the one making the change.

**Triggers — load [reference/integration-tracking.md](./reference/integration-tracking.md) when:**
- Changing function parameters (add, remove, reorder, rename, retype)
- Changing a function's return type or return object shape
- Renaming a shared variable, constant, or configuration key
- Reviewing or resuming work on a project that already carries `<CONTRACT>` or `<USES>` markers, or a `.integration-map.md` file at its root

**Artifacts maintained:**
- `<CONTRACT>` blocks above cross-file-called function definitions — grep-findable via `<CONTRACT id="`
- `<USES contract="..." fields="...">` markers at consumer sites that depend on specific return fields
- `.integration-map.md` at project root — single source of truth for cross-file contracts and their consumers
- Contract Change Log (section within `.integration-map.md`) — audit trail of contract changes

**Enforcement tiers:**
- `scope="public"` contracts: strict — all consumers must be classified before the edit proceeds
- `scope="internal"` contracts: advisory — unresolved consumers require explicit acknowledgment, logged in the Change Log

Full protocol, marker syntax, grep queries, drift detection, and worked templates: [reference/integration-tracking.md](./reference/integration-tracking.md). Runnable drift detectors: `reference/integration-helpers/verify-integrations.ps1` and `verify-integrations.sh`.

---

## When Something Isn't Working + Session Resumption

Repeating the same approach expecting a different result is not debugging — it is spinning.

**The Two-Failure Rule.** If an approach has failed twice, do not try it a third time. Stop, document what was tried and why it failed, then shift to a genuinely different strategy. "Different" means different at the level of approach, not parameters. Changing a timeout value is a tweak. Switching from direct API calls to a batched queue is a different approach.

**The Pivot Sequence.** (1) Name the failure clearly — what did the error say? (2) Identify the assumption that was wrong. (3) Generate at least two alternatives before choosing one. (4) Pick the alternative most likely to surface new information — a partial success that reveals the root cause is more valuable than another clean failure.

### Development Notes — The Session Resumption Anchor

Every non-trivial script carries a `## Development Notes` block at the top (or in a companion `.notes.md` file). It serves two roles: debugging log while the script is being built, and session-resumption anchor after context compaction or in a new session. Each entry records date, attempt number, what was tried, result, root cause, and (for failures) what the next attempt will change:

```text
## Development Notes

### [2026-04-11] Attempt 1 — Direct API call with default timeout
Tried : Single POST to /api/export with default 30s timeout
Result: FAILED — timeout on payloads > 5MB
Reason: Default timeout insufficient; large payloads exceed 30s consistently
Next  : Switch to chunked requests with configurable timeout param
```

**Resumption protocol:** when resuming work on an existing script — new session, after context compaction, or after stepping away — **read the Development Notes block before touching the code.** It captures failures and edge cases not obvious from the current state of the script. Skipping this is how previously-ruled-out approaches get re-tried.

See [reference/troubleshooting.md](./reference/troubleshooting.md) for full pivot examples and the expanded schema.

---

## Log Prefix Vocabulary (Core)

Every log entry uses a consistent prefix so logs are greppable and self-describing. The **full 25-prefix table**, grep patterns, format contract, and rules for extending the vocabulary live in [reference/log_vocabulary.md](./reference/log_vocabulary.md) — load it when adding new prefixes or auditing an existing script. The core prefixes below cover the lifecycle every script emits:

| Prefix | Level | Meaning |
|---|---|---|
| `SCRIPT_START` | INFO | Script has begun; user, host, version follow |
| `SCRIPT_COMPLETE` | INFO | Script finished successfully; duration follows |
| `SCRIPT_FAILED` | FATAL | Unhandled error terminated the script |
| `UNIT_START` | INFO | A named unit has begun; key inputs follow |
| `UNIT_END` | INFO | Unit complete; duration follows |
| `UNIT_FAILED` | ERROR | Unit failed; error, inputs, line, exit code follow |
| `VERIFY_OK` | INFO | A verification check passed |
| `VERIFY_FAILED` | ERROR | A verification check failed; path/detail follows |
| `PHASE_START` | INFO | Phase has begun; phase name follows |
| `PHASE_END` | INFO | Phase complete; duration follows |

Other prefixes — `PHASE_SUMMARY`, `PHASE_GATE`, `ENV_SNAPSHOT`, `PARAMS`, `DEPENDENCY_MISSING`, `VERIFY_WARN`, `RECORD_FAILED`, `RETRY`, `RETRY_WAIT`, `RETRY_EXHAUSTED`, `STACK_TRACE`, `[DRY-RUN]`, `FULL_SUCCESS`, `PARTIAL_SUCCESS`, `FAILURE` — are emitted automatically by the helpers in the language reference files and documented in `reference/log_vocabulary.md`.

A few prefixes have **language substitutions** where the underlying mechanism doesn't exist in all three languages — `STACK_TRACE` is the notable case (Python/PowerShell emit it; Bash substitutes `$LINENO` + `$BASH_COMMAND` in the ERR trap instead). See the `log_vocabulary.md` full table for substitution notes on the affected prefixes.

**Fast grep starter:** `grep -E "UNIT_FAILED|VERIFY_FAILED|SCRIPT_FAILED|FAILURE" run.log` catches the common failure lines across any standard script.

---

## How This Skill Evolves

This skill is a living document. When a future session discovers a new gotcha or safety rule that would have saved time, propose an addition — don't let the lesson stay trapped in an individual session's memory.

**What to add:** concrete, actionable rules with a stated trigger; real case studies in the appropriate reference file; new log prefixes with a clear meaning. **What not to add:** rules without a trigger ("be careful with X" is not a rule — "do Y before Z because X" is); language-specific nuance that belongs in the language reference file; duplicates of existing rules with different wording. Keep rules short — long rules lose their edge. If a rule needs more than a paragraph, the principle goes in SKILL.md and the expanded explanation goes in a reference file.

For file-specific extension rules, consult the reference file being edited: `reference/prove_first.md` "How to Add a Case Study to This File" (case study schema and gatekeeping rule) and `reference/log_vocabulary.md` "Extending the Vocabulary" (prefix-extension rules, cross-language substitution policy). SKILL.md gives the general editorial standards above; the reference files own the per-artifact rules.

**Versioning convention.** The skill uses informal `V<major>_<minor>` tags for milestone references (e.g., V4_5, V4_6). Major number increments for structural reorganizations or new reference files; minor number increments for content additions — new rules, case studies, prefixes, verification passes. Tag the state in commit messages or session notes, not in the files themselves (the files describe what is, not when it became so). The Verification History sections in each language reference file are the durable record of what changed and why at each bump.

### A Note on Voice

This skill was authored session-by-session by different instances of the same assistant, and the prose carries one author's register — direct, occasionally blunt, structured around the rule-and-why pattern. **Preserve it by default.** It's consistent across the file and that consistency helps the next reader build a mental model faster than freshly-rewritten sections would.

If a section ever feels alien — prose that actively gets in the way of the rule it's trying to communicate — rewrite that section in your own register rather than working around it. A minor-version bump for tonal rewrites is fine; the cross-session reality of authoring this skill means voice drift is real and occasionally legitimate. The constraint is: don't change the rule while changing the voice, and don't rewrite what is merely unfamiliar.

**Testable criterion.** Before rewriting any section for voice, read it and restate the rule it conveys in one sentence. If you can restate the rule unchanged, the prose works — the unfamiliarity is stylistic, not comprehension-blocking, and the rewrite isn't needed. Only rewrite when you find yourself having to reread the section to reconstruct what rule it's actually stating. That's the objective test for "blocks comprehension" vs. "feels off."

### Worked Example — Adding a New Case Study

Adding a rule or case study is usually a small edit to the matching reference file. To add a prove-first case study, append to the bottom of `reference/prove_first.md` following the six-field schema (Situation / What went wrong / Root cause / Prove-first step / Lesson encoded / Generalizable rule). **The case study must be a real incident from this project's build** — that is the rule `prove_first.md` itself enforces, and it applies to the worked example below.

```diff
--- reference/prove_first.md
+++ reference/prove_first.md
@@ (end of file) @@
+## Case Study 7 — masscan Silently Returns Nothing on Loopback
+
+**Situation.** An integration probe for a Docker-hosted target wrapped
+`masscan --range 127.0.0.1/32 -p <port>` and asserted the mapped port
+would appear in the output.
+
+**What went wrong.** The probe returned `found=0` with exit code 0 and
+zero error output. The target was confirmed up via `curl` and `nmap`.
+Time spent chasing a suspected wrapper parsing bug.
+
+**Root cause.** masscan uses raw SYN packet injection at the kernel level;
+the kernel handles loopback and Docker bridge interfaces internally and
+silently drops the raw packets. No error is reported — the scan simply
+finds nothing. Documented afterward in CLAUDE.md.
+
+**Prove-first step (30 seconds).** `masscan --range 127.0.0.1/32 -p 22`
+against a known-open loopback port, before wrapping it. One run would
+have returned `found=0` despite SSH being open — surfacing the kernel
+behavior before the wrapper was built.
+
+**Generalizable rule.** Before wrapping any packet-level scanning tool
+(masscan, zmap, hping) in a probe, run it once against a known-good
+target in your actual test environment. Raw-socket tools have
+environment-specific blind spots that docs often omit.
```

No SKILL.md edit is needed for most additions — the principle lives here, the specifics live in the reference. Only touch SKILL.md when the addition changes a decision rule, not when it adds an example of an existing one.

### Worked Example — Adding a New Rule

Rules are less schematic than case studies but still follow a pattern: **trigger** (what condition makes this rule fire), **action** (what to do when it fires), **rationale** (why, usually a one-sentence incident summary). Add rules where the trigger is — if the trigger is a safety-critical decision every script makes, SKILL.md; if it's language-specific, the language reference file; if it's about a specific helper, adjacent to that helper's definition.

The Idempotency Rule (added alongside the retry helper) is a good template:

```diff
--- SKILL.md
+++ SKILL.md
@@ after "Retry Logic for Transient Failures" section @@
+**Idempotency Rule.** `invoke_with_retry` / `Invoke-WithRetry` are safe
+only for operations that can be retried without duplicating side effects:
+reads, stable-ID updates, deletes, operations with an idempotency key.
+A bare `POST /charges` or `POST /send-email` is NOT safe to retry blindly
+— a transient failure that doubled a payment or sent duplicate email is
+worse than no retry at all. Wrap non-idempotent calls in an explicit
+idempotency key, or use a different pattern (circuit breaker, dead-letter
+queue).

--- reference/python.md, bash.md, powershell.md
+++ reference/python.md, bash.md, powershell.md
@@ inside the helper header comment for invoke_with_retry @@
+# IDEMPOTENCY: only use this helper for operations safe to retry —
+# reads, stable-ID updates, deletes, or operations with an idempotency
+# key. A bare POST /charges, POST /send-email, or POST /webhook is NOT
+# safe to retry blindly; a retry that doubles payments or sends duplicate
+# emails is worse than no retry at all. See SKILL.md "Idempotency Rule".
```

Notice the pattern: the rule appears in **two places** — in SKILL.md where the decision is made (should I use retry?), and adjacent to the helper in each language file where the decision is implemented (am I using retry correctly?). Safety-critical rules are the one place where duplication is correct. For non-safety rules, pick one location — duplicate rules drift.

**What not to do when adding a rule:** don't state it as a general principle without a trigger ("be careful with retries" is not a rule); don't bury it in a narrative paragraph where a skimming reader will miss it; don't restate an existing rule with different wording to fit a new context (either the existing rule applies and should be cited, or the new context is different enough to warrant an entirely different rule).

### Worked Example — Adding a New Contract

When a function graduates from single-file internal helper to cross-file-called utility, add a `<CONTRACT>` block above its unit header and register it in `.integration-map.md`. The addition is two coordinated edits — the block in code, the entry in the map — made in a single commit to prevent drift.

```diff
--- src/tokens.ps1
+++ src/tokens.ps1
@@ above the Get-UserToken unit header @@
+# <CONTRACT id="Get-UserToken" version="1" scope="public">
+#   PARAMS:
+#     UserId    [string]   required
+#     Scope     [string[]] required
+#   RETURNS: [PSCustomObject]
+#     Token      [string]
+#     ExpiresAt  [datetime]
+#     Scopes     [string[]]
+#   THROWS: AuthenticationException, NetworkException
+# </CONTRACT>
 # ============================================================
 # UNIT: Get-UserToken
```

```diff
--- .integration-map.md
+++ .integration-map.md
@@ (append) @@
+## <contract:Get-UserToken>
+
+**Defined:** src/tokens.ps1:42
+**Version:** 1
+**Scope:** public
+
+- CONSUMER: src/api/client.ps1:87 — fields: Token — via: USES
+- CONSUMER: src/api/client.ps1:134 — fields: Token,ExpiresAt — via: USES
```

The CONTRACT block and the map entry are the same information in two forms — the block is the runtime definition (what the code provides); the map entry is the cross-cutting index (who depends on it). Both must be present before the contract counts as tracked. See `reference/integration-tracking.md` for the Format Contract governing the exact field syntax and the Change Impact Protocol governing how contracts change over time.

**Mechanical enforcement — V5.3+.** The editorial standards above — worked examples, case studies, contract blocks, integration map entries — are grep-anchored format contracts. Drift between a canonical pattern and its worked template is the failure mode documented in `<lesson:2026-04-22:format-drift-in-self-authored-patches>` and `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>`. V5.3 ships a pre-commit hook at `skill_development/authoring-helpers/` that enforces the L2 grep-test mechanically across the 15 invariants in `reference/grep_first.md` (G1–G9) and `reference/integration-tracking.md` (I1–I6). Install with `git config core.hooksPath skill_development/authoring-helpers/`; see that directory's `README.md` for the L2-covered invariant set, installation details, and the regression suite.

---

## Skill Development Memory

A small directory tree captures institutional memory of the skill's own evolution. These files are **not** loaded during normal scripting work — they are read on-demand when resuming development on the skill itself or recognizing a pattern that might have prior experience.

| File | Load when |
|---|---|
| `skill_development/developer_log/log.md` | Resuming work on the skill; considering a design decision similar to one potentially already made; onboarding to the skill's history |
| `skill_development/lessons_learned/lessons.md` | Recognizing a familiar pattern and wanting to check for prior experience; authoring a new lesson and verifying it doesn't duplicate an existing one |

The tree uses its own schemas — see each folder's `README.md` for details. Entries are strictly gatekept: dev log entries require decisions with alternatives considered; lessons require real incidents (inheriting `prove_first.md`'s gatekeeping rule).

For lessons about *using* this skill on project work — debugging incidents, tool quirks, architectural surprises in the projects the skill supports — see Ghost's general `lessons-learned` skill. The `skill_development/` tree here is scoped strictly to this skill's own development. Cross-references between the two are explicit and one-directional: this tree may point outward to `lessons-learned`; the general skill does not depend on this one.

---

## Reference Files

See the "How This Skill Is Organized" table at the top for the full list and load-when triggers. Load on demand. Context is budget — spend it on the task at hand, not on pre-loading reference material you may not need.
