# Lessons Learned — Index

Grep target. Each row is self-contained: tags, description (under 120 chars,
frontloaded), source pointer to phase file, and type classification.

| Primary lookup | Command |
|---|---|
| Search all tags + descriptions | `grep -i "keyword1\|keyword2" INDEX.md` |
| Search AI file topics | `grep -i "keyword" ai/_overview.md` |
| Follow source pointer | `grep -A 20 "^### N\." phase{N}_{name}.md` |

---

## Quick Reference — AI Subject Files

| File | Rules | Topics / keywords |
|---|---|---|
| [ai/powershell.md](ai/powershell.md) | 10 (1 superseded) | powershell, string-escape, byte-scan, performance, parse-check, file-encoding, ascii, bom, dotnet-version, ps51, redistribution, strictmode, pipeline-unroll, pattern-classification, in-source-data, extensibility, audit-trail |
| [ai/forensic_triage.md](ai/forensic_triage.md) | 4 | false-positive, keyword-list, immutability, copy-then-analyze, fixture-pairing, encrypted-package, silent-wrong-answer |
| [ai/process.md](ai/process.md) | 5 | prove-first, plan-mode, askuserquestion, benchmark-first, switch-design, cli-ergonomics, retry, call-site-audit |

---

## Tag Vocabulary

Canonical tags used across this project's lessons. Additions require a
reflection entry noting the new tag and its meaning.

- **powershell** — PowerShell language semantics, cmdlets, idioms
- **string-escape** — string-literal escape sequences and their traps
- **byte-scan** — searching/matching within byte arrays or binary content
- **performance** — runtime speed concerns, benchmarking, hot paths
- **parse-check** — syntax / AST validity before execution
- **false-positive** — detectors that fire on benign inputs
- **keyword-list** — plain-substring detection patterns
- **immutability** — source-file read-only contracts
- **copy-then-analyze** — analyze-a-copy safety pattern
- **fixture-pairing** — real + synthetic test file pairing
- **prove-first** — validating an assumption before committing to it
- **plan-mode** — plan-first workflow discipline
- **askuserquestion** — extracting user decisions via structured Q&A
- **benchmark-first** — measuring before choosing among algorithms
- **contract-in-log** — proving safety contracts via log emissions
- **skill-drift** — skill reference files out of sync with SKILL.md

---

## Active Index

Rules and insights from the most recent reflections. New entries start here.

| Tags | Description | Source | Type |
|---|---|---|---|
| powershell, string-escape | PowerShell has NO `\x` hex escape — `"\x00"` is a 4-char string, not a null byte; use `` `0 `` or byte arrays | phase01:7 | bug |
| powershell, byte-scan, performance | Interpreted PS byte-scan loops run ~1M bytes/sec; `[Array]::IndexOf` + tail-verify is ~68× faster | phase01:8 | rule |
| powershell, parse-check | For PowerShell scripts >500 lines, write in one pass and `[Parser]::ParseFile` before first execution | phase01:5 | rule |
| powershell, performance, benchmark-first | Benchmark any PS scan over >1MB data against alternatives before committing — 10-100× speedups routinely hide | phase01:8 | rule |
| false-positive, keyword-list | False-positive tools must regression-test every keyword against one known-clean file per target format before shipping | phase01:6 | rule |
| false-positive, keyword-list, ooxml | Plain-substring URL detection false-positives on OOXML xmlns URIs — gate URL matching to Target=/src= attributes in .rels files | phase01:6 | bug |
| immutability, copy-then-analyze | When a script must never modify input X, route all downstream work through a copy of X; re-hash X at exit | phase01:10 | rule |
| immutability, contract-in-log | Prove safety contracts at runtime with a log line citing the captured value — not by code inspection | phase01:3 | rule |
| fixture-pairing | Pair real-world file + synthetic positive when testing pattern detectors — each catches what the other misses | phase01:4 | rule |
| prove-first, powershell | 30-second one-liner before implementing a byte-level primitive catches encoding / escape errors pre-code | phase01:2 | rule |
| plan-mode, askuserquestion | 4 discriminating plan-mode questions before drafting cut downstream decision churn by ~80% | phase01:1 | rule |
| skill-drift | Verify a skill's referenced files exist before invoking it on real work — dead pointers cost ~10 min each | phase01:9 | insight |
| switch-design, cli-ergonomics | Condition artifact-preservation switches on the verdict that makes preservation useful, not on orthogonal always/never flags | phase01:11 | rule |
| skill-drift | lessons-learned_V3_5 shipped with 4 missing reference files; gap resolved mid-session via user upload | phase01:12 | insight |
| powershell, file-encoding, bom, ps51 | SUPERSEDED by phase01:15 rule - BOM fix solves local author case but breaks under redistribution; strict-ASCII is durable fix | phase01:13 | rule |
| powershell, file-encoding, ascii, ps51, redistribution | Strict-ASCII .ps1 source is durable cross-runtime; BOM alone is fragile because copy tools strip it silently | phase01:15 | rule |
| powershell, strictmode, pipeline-unroll | Wrap Sort-Object/Select-Object -Unique output in @() under StrictMode - pipeline unrolls to scalar on 1 element, $null on 0 | phase01:16 | bug |
| false-positive, pattern-classification, signal-vs-noise | Separate detection pattern list into suspicious-tier + known-benign allow-list; classify at emit time to demote expected noise to INFO | phase01:16 | rule |
| powershell, in-source-data, extensibility, audit-trail | Structured hashtable arrays with HOW-TO block + TEMPLATE entry + required Rationale field let non-authors extend in-source data lists safely | phase01:17 | rule |
| powershell, dotnet-version, ps51 | `[Encoding]::Latin1` is .NET Core/5+ only; use `::GetEncoding(28591)` for PS 5.1 / .NET Framework 4.x cross-runtime compat | phase01:13 | rule |
| retry, idempotency, call-site-audit | When adding retry to a resource, grep every call-site that touches the same resource — wrapping one site is a partial fix | phase01:14 | rule |
| false-positive, encrypted-package, cfbf, silent-wrong-answer | Check for EncryptedPackage / EncryptionInfo UTF-16LE stream names before claiming CLEAN on CFBF input — encrypted OOXML routes to CFBF path | phase01:14 | rule |

---

## Foundation Index

Rules reinforced across multiple phases, or universal concerns (security,
validation). Graduate from Active when proven durable (2+ phases).

_(Empty — graduation happens at phase transitions. See SKILL.md §4d.)_

---

## Reference Index

Rules from completed, stable work areas. Tag inactive for 2+ phases AND
work area complete.

_(Empty — no phases have aged into Reference yet.)_
