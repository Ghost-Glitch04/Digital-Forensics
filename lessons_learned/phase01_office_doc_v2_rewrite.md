# Phase 01 — Invoke-OfficeDocAnalysis v1 → v2 Rewrite

**Tags:** office-forensics, powershell, rewrite, triage, false-positive
**Date:** 2026-04-24
**Format:** canonical

---

## Overview

Full rewrite of `OfficeFiles/Invoke-OfficeDocAnalysis.ps1` from a
partially-broken 768-line v1 into a standards-compliant 1278-line v2
that triages SentinelOne false positives on business-critical Office
documents without ever mutating the source file. Rewrite exercised
prove-first twice (UTF-16LE encoding check; byte-scan benchmark),
fixed the critical `\x00` string-literal bug that silenced v1's CFBF
OLE-stream detection for over a year, added RTF / template-injection
/ XLM detection paths, and proved source immutability via SHA-256
round-trip assertion emitted to the log on every exit.

---

## Applied Lessons

Project has no prior lessons_learned/ directory; this is phase 01. Source
column cites sibling skills (closest available prior art) rather than
in-project AI files.

| Rule (source → heading) | Outcome | Note |
|---|---|---|
| scripting-standards-v5.3:powershell.md → "Write-Log / phase helpers" | applied | Copied signatures verbatim; re-declared `$script:PhaseTimer` in Config block to avoid v1's strict-mode scope leak |
| scripting-standards-v5.3:SKILL.md → "Prove-First Development" | applied proactively | Two explicit invocations — 30-sec UTF-16LE encoding check before writing `Find-BytePattern`; 2-min byte-scan algorithm benchmark before shipping naive loop |
| scripting-standards-v5.3:SKILL.md → "Fail Fast + Exit Codes" | applied | Adopted 0 / 10 / 11 / 20 / 30 / 40 / 50 / 99 scheme exactly; added exit 99 for the source-mutation-detected case |
| scripting-standards-v5.3:SKILL.md → "Dry-Run Mode" | applied | Implemented but **contract narrowed**: `-DryRun` skips JSON write only; extraction still runs (analyst needs the workspace to inspect). Documented the narrowing in `.PARAMETER` help |
| scripting-standards-v5.3:SKILL.md → "Idempotency Rule" | applied | Added explicit `# IDEMPOTENT:` comment near Main block as a contract for future automation wrappers |
| scripting-standards-v5.3:troubleshooting.md → "Development Notes schema" | applied | Created `Invoke-OfficeDocAnalysis.notes.md` with three dated attempts, edge cases, invariants, and scope boundaries |
| scripting-standards-v5.3:SKILL.md → "Two-Failure Rule" | N/A | No approach failed twice this session |
| github-security-standards_V4:SKILL.md → "Gitignore-First" | in place | Root `.gitignore` already drafted in earlier session; script's `$env:TEMP` output dir sits outside repo so no new entries needed |
| github-security-standards_V4:SKILL.md → "Three-Layer Model (env / config / code)" | N/A | Script requires no credentials or organization identifiers |
| lessons-learned_V3_5:SKILL.md → "Check 12 — reference pointer resolution" | discovered | Found 3 missing reference files in the skill itself — see Design Decisions §3 |

---

## Missed Lessons

Rules that a hindsight-grep against INDEX.md would have suggested but
weren't consulted at authoring time. Discovered only now.

| Rule (source → heading) | Why missed | Consequence |
|---|---|---|
| NEW (this phase): "False-positive tools must be regression-tested against known-clean files before shipping" | No such rule existed in this project yet. First benign .docx run surfaced 12 false positives from xmlns URI substrings | Had to reopen the analysis phase of the rewrite, revise keyword list semantics, re-test three benign files before progressing. Cost: ~10 minutes, one reversible code rev |
| NEW (this phase): "Benchmark PS byte-scan algorithms against realistic file sizes before wiring them into a hot path" | No such rule existed. Naive loop was adequate for 4KB synthetic needle; not tested against any multi-MB file before the full MSI run surfaced 11s latency | Same rewrite-phase reopening as above. Cost: ~5 minutes to benchmark, ~2 minutes to land fix |

---

## What Went Well

### 1. Plan-mode discriminators extracted 6 binding decisions before drafting

Used `AskUserQuestion` twice in plan mode to extract six unambiguous
user decisions (rewrite strategy, output formats, new detections, temp
handling, file layout, artifacts). Each choice directly cut the design
space — e.g. "full rewrite to standards template" eliminated a whole
class of "preserve v1 structure where possible" sub-questions. The
approved plan survived contact with reality with zero scope revisions.

**Lesson:** For multi-option architectural work, spend 2 minutes of plan
mode asking 4 discriminating multi-choice questions before drafting —
answers shape 80% of the downstream decisions and prevent mid-session
"should this be X or Y?" context switches.

### 2. Prove-first caught two failure modes that code review would not

Ran the UTF-16LE encoding sanity check (one PowerShell one-liner, 30
seconds) before writing `Find-BytePattern`. Confirmed `[Encoding]::Unicode.GetBytes('VBA')`
= `56-00-42-00-41-00` and that `[Array]::IndexOf` lands on the expected
offset in a toy haystack. Without that, the whole CFBF OLE-stream fix
would have inherited v1's class of error (assuming string semantics
that don't hold).

Separately, before replacing the naive loop with something more exotic,
benchmarked three candidate algorithms on a 5MB random buffer with a
known needle. Numbers: 1152ms / 42ms / 17ms. Evidence picked the
algorithm; no argument from authority.

**Lesson:** A 30-second `python -c` / PowerShell one-liner before
implementing a byte-level detection primitive is cheaper than any code
review; cite `Prove-first Case Studies` in scripting-standards-v5.3
reference/prove_first.md for the general pattern.

### 3. Source-immutability proof via hash round-trip from log, not code

The script captures SHA-256 at Preflight start, re-hashes the source at
every exit path (`PHASE_GATE`, `SCRIPT_COMPLETE`, outer catch), and
writes `VERIFY_OK: Source file immutability confirmed — SHA-256 unchanged
from script start to end ({hash})` on match. An analyst reading the log
sees the contract proved; they don't have to trust the code. Verified
across 5 end-to-end runs: every run emitted the line and the hash-before
equaled hash-after.

**Lesson:** For safety-critical contracts ("never mutates X"), assert
the contract at runtime AND emit a log line that proves it — code
inspection alone is not evidence; a log line with a specific captured
value is.

### 4. Pairing real + synthetic fixtures caught non-overlapping classes

Tested against (a) a real 5.4MB CFBF MSI and (b) a synthetic 5KB CFBF
fragment with a UTF-16LE `VBA` needle at a known offset. The real file
surfaced the 11s performance regression. The synthetic file proved
centerpiece correctness (`offset=0x1010` detected). Either alone would
have missed what the other caught — real files don't contain the needle,
synthetic files don't stress performance.

**Lesson:** When testing pattern-based detectors, pair a real-world file
(for perf + false-positive discovery) with a synthetic positive (for
correctness proof of the needle-match code path). Single-source testing
systematically misses one of those two classes.

### 5. Full-file write in one pass — appropriate for PowerShell

PowerShell requires whole-file parse validity; I drafted the entire
~1000-line rewrite in one `Write` call, then ran a
`[Parser]::ParseFile()` check before any execution. Zero parse errors
on first try. Iterating unit-by-unit would have churned on re-parse
failures. (Compare: a Python rewrite could have been unit-at-a-time
with a module-level import after each.)

**Lesson:** For PowerShell scripts above ~500 lines, plan the full-file
rewrite in one Write call and run `[Parser]::ParseFile` before first
execution — piecemeal edits amplify parse-error feedback loops.

---

## Bugs and Pitfalls

### 6. xmlns URI substrings produced false positives on every benign OOXML file

The v1 keyword list included `http://`, `https://`, `ftp://` as
plain-substring `SuspiciousKeyword` patterns. Every OOXML file declares
XML namespaces like `xmlns="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`
in virtually every .xml part. First real-file test against a benign
`Phase2_Triage.docx` produced 12 false positives (one per .xml part),
verdict = SUSPICIOUS.

This is exactly the false-positive class the tool exists to disprove
about third-party tooling (SentinelOne). Shipping the same failure mode
would have invalidated the premise.

Fix: separated `$Script:UrlSchemes` from the main keyword list. In the
OOXML path, URLs are only flagged when matched inside value attributes
(`Target=`, `src=`, `Source=`) of `.rels` files or in specific content
parts (`word/document.xml`, `xl/sharedStrings.xml`). In the CFBF path,
URL schemes remain plain-substring because that format lacks the xmlns
namespace problem and VBA-embedded URLs are a real IOC.

After fix, three benign Word/Excel files all returned CLEAN with 0 findings.

**Lesson:** For a false-positive-reduction tool, regression-test every
keyword against at least one known-clean representative of each target
format before shipping; keyword lists that look conservative in
isolation may interact with format structure (e.g., OOXML xmlns URIs)
in ways that invert their semantics.

### 7. `"\x00"` in PowerShell double-quoted strings is a literal five-character string, not a null byte

v1's `Analyze-CFBFOLEStreams` unit used regex patterns like
`"V\x00B\x00A\x00"` to match UTF-16LE stream names in CFBF binary
content. PowerShell does not support `\x` hex escapes in double-quoted
strings — those are five literal characters: backslash, x, 0, 0. Result:
the regex never matched a single real CFBF stream name. The unit was a
silent no-op since v1.0. `Equation Native` happened to work only because
it's ASCII (no null bytes).

Fix: `Find-BytePattern` helper with UTF-16LE-encoded `[byte[]]` needles
(`[System.Text.Encoding]::Unicode.GetBytes('VBA')` →
`56-00-42-00-41-00`), searching a byte-array haystack. Proved correct on
synthetic CFBF fragment: `[ALERT] OLEStream 'Macros (VBA)' offset=0x1010`.

**Lesson:** PowerShell has NO `\x` hex escape in string literals — use
`` `0 `` for null or `[System.Text.Encoding]::Unicode.GetBytes("...")`
for a byte array. Any `\x00`-looking literal in PS strings is a
five-character string and every regex that relies on it silently fails.

### 8. Naive PowerShell byte-scan loop was 68× slower than `[Array]::IndexOf`

First implementation of `Find-BytePattern` used a PowerShell-interpreted
nested for-loop to find needle offsets in a byte-array haystack. Against
a real 5.4MB MSI with ~25 needle scans per Analysis phase, total took
11.2s — unacceptable for a triage tool that must return results in ~1s.

Benchmark on 5MB random buffer with known needle:

| Algorithm | Time | Relative |
|---|---|---|
| Naive PS nested loop | 1152ms | baseline |
| Latin-1 string + `IndexOf` | 42ms | 27× faster |
| `[Array]::IndexOf` + tail-verify | 17ms | 68× faster |

Fix: replaced nested loop with `[Array]::IndexOf($Haystack, $Needle[0], $pos)`
to jump to candidate first-byte positions, then verify remaining bytes
in a tight loop that only runs on candidates. Post-fix MSI total
duration: 1.12s (10.7× faster end-to-end); Analysis phase alone: 473ms
(23.7× faster than 11.227s).

**Lesson:** For any PowerShell scan over >1MB byte arrays, the
PS-interpreted inner loop dominates; `[Array]::IndexOf` with a first-byte
jump + tail-verify is ~68× faster and should be the default. Benchmark
on a realistic file size before committing any byte-scan approach.

---

## What Went Badly

### 9. Reference-material gap discovered mid-reflection

Started the reflection expecting to find `templates.md` and `bootstrap.md`
in `.claude/skills/lessons-learned_V3_5/reference/`. Neither exists — only
`drift_intake.md`, `evidence.md`, `invariants.md`, `lookup.md`,
`meta_classification.md` are present. SKILL.md points to the missing files
~15 times (grep confirmed). Had to synthesize phase-file format from
`invariants.md` INV-PHASE-* rules plus the Quick Reference card in SKILL.md.

Not a bug in the session's primary work — the work completed. But it cost
~10 minutes of context discovery and forced a reflection that is
format-correct by construction rather than format-correct by convention.
Documented under Design Decisions §3 as a meta-question for future
skill-development work.

**Lesson:** When a skill SKILL.md references files in its `reference/`
directory, verify those files exist BEFORE invoking the skill on real
work — dead pointers cost ~10 minutes of unplanned inference per
reference, multiplied across the session.

---

## Design Decisions

### 10. Copy-then-analyze over stream-only-read

Options considered:
- **Stream source via read-only FileStream** — lower disk I/O, source opened
  but never written. Risk: any transient read error mid-analysis leaves
  partial results; analyst can't re-run on the copy.
- **Single copy to `$env:TEMP`, all downstream reads target the copy** ← selected
- **Copy + preserve on alert** — superset of selected option via `-KeepTempOnAlert`

Selected copy-then-analyze because it provides a stable working set the
analyst can inspect (via `-KeepTempOnAlert` + MALICIOUS verdict) and makes
the source-immutability contract mechanical rather than policy-driven — the
source handle is opened once for hashing, then never touched again.

Proven by log: every run emits `VERIFY_OK: Source file immutability confirmed`
at `SCRIPT_COMPLETE`; no run has ever emitted `SOURCE_MUTATED`.

**Lesson:** When a script's contract is "does not modify input X", make
the contract mechanical by routing all downstream work through a copy of
X and re-hashing X at exit — the copy pattern is cheaper than auditing
every read-path code site for write intent.

### 11. `-KeepTempOnAlert` switch, not `-KeepTemp`

Considered three options: always keep, never keep, keep-iff-MALICIOUS.
Selected conditional preservation because:
- Always-keep fills $env:TEMP on analysts who run the script in a loop
- Never-keep forces re-running against the source when an analyst wants to
  `olevba` the extracted `vbaProject.bin`
- MALICIOUS-only keeps only when preservation has documented value
  (analyst needs the artifacts for escalation)

Also exposes a secondary affordance: if the analyst wants an unconditional
keep, they can `-DebugMode` which preserves workspace on any failure
path via the outer `catch` block.

**Lesson:** For "artifact-preservation" switches, condition on the
verdict that makes preservation useful rather than exposing three
orthogonal flags — downstream analysts don't read the doc; they read
the switch name.

### 12. lessons-learned_V3_5 skill had 4 missing reference files (RESOLVED in-session)

Skill drift observation logged during this reflection: `bootstrap.md`,
`templates.md`, `verify.md`, and `retroactive.md` were referenced ~10×
each from SKILL.md and `invariants.md` but were missing from
`.claude/skills/lessons-learned_V3_5/reference/`. Only `drift_intake.md`,
`evidence.md`, `invariants.md`, `lookup.md`, `meta_classification.md`
were present. Check 12 (reference pointer resolution) would fire.

The gap forced format synthesis from `invariants.md` INV-PHASE-* rules
plus SKILL.md Quick Reference alone, which produced two drift patterns
that Check 13 caught once `templates.md` became available:

1. Header block used `**Scope:**` / `**Date:**` where templates.md
   specifies `**Tags:**` + `## Overview` section.
2. INDEX source pointers used section-prefixed identifiers
   (`phase01:B2`, `phase01:WW5`, `phase01:TW3`) where templates.md §INDEX
   Row Format specifies monotonic single-integer `{phase_id}:{N}`.

**Resolution:** The user uploaded the four missing reference files
mid-reflection. Drift was corrected in the same session — header
restructured, entries renumbered monotonically 1-12, INDEX and AI
source pointers rewritten to canonical form.

**Lesson:** A skill that teaches self-review checks should pass those
checks on itself; mid-session correction of drift is possible once the
canonical reference becomes available, but the initial synthesis cost
~10 minutes of unplanned format-inference work that the reference files
would have prevented.

---

### 13. Two distinct PS 5.1 compatibility surfaces surfaced during pre-production CF-5

Added 2026-04-24 via lightweight capture after executing Units 1.1 and 1.2
of the pre-production plan (CFs 5-9). v2 was developed and verified
exclusively on PowerShell 7.6 / .NET 8. First run on Windows-inbox
PowerShell 5.1.26100 surfaced two independent failure modes that both
produce silent-wrong-answer behavior when they fire:

1. **File encoding — no UTF-8 BOM.** Script contained 50 em-dashes
   (U+2014) in `.NOTES`, log strings, and comment banners. PS 5.1 reads
   `.ps1` files as Windows-1252 when no BOM is present; each em-dash
   (UTF-8 bytes `E2 80 94`) was decoded as three garbage characters,
   corrupting the token stream. The parser emitted 20 cascading errors
   starting at line 496, but the true fault was upstream at line 4.
   Fix: prepend `EF BB BF` UTF-8 BOM via
   `[System.IO.File]::WriteAllText($p, $content, [System.Text.UTF8Encoding]::new($true))`.

2. **.NET API availability — `::Latin1` is .NET Core only.**
   `[System.Text.Encoding]::Latin1` (static property added in .NET 5)
   does not exist on .NET Framework 4.x (the runtime under PS 5.1).
   Parser accepted the line (statics resolve at runtime) but the use
   site at Extract-CFBFBinary threw
   `"The property 'Latin1' cannot be found on this object"` and exit 20.
   Fix: replace with `[System.Text.Encoding]::GetEncoding(28591)` —
   code page 28591 is ISO-8859-1 (canonical name for Latin-1), available
   on both .NET Framework 4.x AND .NET 8 and producing identical
   byte-to-char mapping.

Post-fix verification on both runtimes:

| Runtime | Parse | .docx | .xlsx | CFBF MSI | Synthetic VBA |
|---|---|---|---|---|---|
| PS 5.1.26100 | OK | CLEAN 3.7s | CLEAN 1.4s | SUSPICIOUS 9.2s | MALICIOUS @0x1010 0.5s |
| pwsh 7.6.0  | OK | CLEAN 1.8s | CLEAN 1.1s | SUSPICIOUS 1.0s | MALICIOUS @0x1010 0.5s |

Note PS 5.1's 9× slower MSI analysis — acceptable for triage latency
but worth noting: .NET Framework 4.x `[Array]::IndexOf` is materially
slower than .NET 8's implementation.

**Lesson:** Any PowerShell script with `#Requires -Version 5.1` and
non-ASCII content must be verified on `powershell.exe` (inbox 5.1) not
just `pwsh.exe` (7+); the two runtimes diverge on file-encoding
tolerance (BOM required on 5.1 for UTF-8 multi-byte content) and
.NET API availability (`.NET Core 5+` statics like `[Encoding]::Latin1`
throw at runtime on `.NET Framework 4.x`).

---

### 14. Retry-wrapping a single call-site is insufficient when multiple sites read the same resource

Added 2026-04-24 via lightweight capture after executing Units 2.1 and 2.2
of the pre-production plan (CFs 7-8). First implementation of CF-7 added
`Invoke-WithRetry` around the single `Copy-Item` call in `Copy-SourceSafely`.
The locked-source test harness still failed — because `Compute-SourceHashes`
runs FIRST in Preflight and also reads the source (three `Get-FileHash`
calls). With a 5-second lock and the retry only on Copy-Item, the script
failed out at Compute-SourceHashes before reaching the wrapped Copy-Item.

The fix was to wrap BOTH call-sites: Compute-SourceHashes reads the source
three times (SHA-256, SHA-1, MD5), and Copy-SourceSafely copies once. Both
are idempotent reads. Without retry on Compute-SourceHashes, the carefully-
wrapped copy helper never ran.

**Separately (CF-8),** added a Detect-EncryptedPackage unit to the CFBF
analysis path. Password-protected OOXML is wrapped in a CFBF outer
container with an `EncryptedPackage` stream — so when the analyst points
the script at a password-protected .docx, magic bytes (`D0-CF-11-E0`)
route it to the CFBF path, not OOXML. Without this detection, encrypted
content produced a falsely CLEAN verdict because the OLE-stream / keyword
scans found nothing in ciphertext. New unit runs first (before expensive
scans), byte-pattern-matches UTF-16LE `EncryptedPackage` / `EncryptionInfo`
/ `DataSpaces` needles, emits SUSPICIOUS + escalation note on hit.

Verified with synthetic CFBF fixture:
```
SYNTH CFBF header (16B) + pad (4096B) + UTF-16LE 'EncryptedPackage' + fake ciphertext (2KB)
→ VERDICT: SUSPICIOUS | [EncryptedPackage] Password-protected or encrypted document
```

**Lesson:** When wrapping a transient-failure-prone operation in retry,
audit ALL call-sites that touch the same resource — not just the one
that matched the originating symptom. `grep -n "Get-FileHash.*\$FilePath"`
finds every source-read site; every match needs the same retry policy
or the retry is only a partial fix. For Invoke-OfficeDocAnalysis the
full list was: `Compute-SourceHashes` (3 reads), `Copy-SourceSafely`
(1 copy), and `Assert-SourceUnchanged` (1 read at script-end — already
had catch-and-WARN demotion, acceptable without retry).

---

### 15. BOM-required encoding is a latent hazard; strict-ASCII source is the durable fix (v2.0.1)

Added 2026-04-24 after v2.0.1 was cut in response to a user's first
live run on PowerShell 5.1 producing the same "Try missing Catch/Finally"
parse errors that phase01:13 had nominally closed.

The v2.0.0 fix (phase01:13) added a UTF-8 BOM to the script. That
closed the symptom in the author's environment. But it left a latent
hazard: the file's PS 5.1-parseability depended on **every subsequent
copy operation** preserving the 3-byte BOM prefix. Many common
workflows don't:
- Text editors that save as UTF-8 without BOM (VS Code default on
  Linux/macOS, Notepad++ depending on setting, Vim with fileencoding=utf8)
- PowerShell round-trips via `Get-Content | Set-Content` without
  `-Encoding UTF8BOM` (the `-Encoding UTF8` value differs between PS
  5.1 and PS 7 — PS 5.1 writes WITH BOM, PS 7 writes WITHOUT)
- Some download tools that strip BOM for "normalization"
- A user's deliberate BOM-stripping via any .NET-free copy workflow

The user hit exactly this: they copied the script to `C:\Windows\TEMP`
via some path that stripped the BOM, and PS 5.1 emitted the same parse
errors v2.0.0 was supposed to have fixed. Error shape: `Try statement
missing its Catch or Finally block` and `Missing closing '}'` at random-
looking line numbers — the classic BOM-stripping signature.

v2.0.1 fixes this at the source by making the script content strict
ASCII: replaced all 59 em-dash characters (U+2014) with ASCII hyphens,
and the single right-arrow (U+2192) with `->`. Comment readability
loses nothing meaningful; BOM-independence gains everything. BOM is
retained as defense-in-depth (it signals UTF-8 to editors and serves
as a canary if non-ASCII is re-introduced in future edits).

Stress test performed before shipping: deliberately strip the BOM from
a copy, parse that copy on PS 5.1. Before v2.0.1: cascade of parse
errors. After v2.0.1: `PARSE OK`.

**Lesson:** For any PowerShell script that must run on both PS 5.1 and
PS 7+, and that will be redistributed through copies / downloads /
editor round-trips, strict ASCII source content is more reliable than
depending on UTF-8 BOM preservation. The BOM is a contract that every
tool in the distribution chain must respect; many don't. ASCII content
has no such contract. Keep the BOM as belt-and-suspenders but never
depend on it alone for correctness.

---

### 16. URL-finding signal improvement (v2.1.0) and the Sort-Object-Unique array-unroll trap

Added 2026-04-24 after a user's live triage on a real front-desk business
doc (ABN.doc, 47KB CFBF, 2016-vintage) returned SUSPICIOUS driven by a
single `[ExternalUrl] URL scheme 'http://'` finding. Manual extraction
revealed the URL was `http://schemas.openxmlformats.org/drawingml/2006/main`
- a benign XML namespace URI that appears in virtually every Office doc
containing a drawing or shape.

The v2.0.x URL detection was doing half the job:
- **CFBF path** checked only for scheme *substring* presence; didn't
  extract the URL. Analyst had no idea what URL was found.
- **OOXML path** extracted the URL into the finding Detail but didn't
  classify benign namespace URIs separately, so any namespace URL in
  Target/src attributes would still drive a SUSPICIOUS verdict.

v2.1.0 closed both gaps:
1. New `$Script:UrlRegex` captures full URLs (scheme + host + path) not
   just scheme prefix
2. New `$Script:BenignUrlPatterns` lists known XML namespace roots
   (schemas.microsoft.com, openxmlformats.org, w3.org, etc.)
3. New `Test-UrlIsBenign` helper pattern-matches a URL against the list
4. Both CFBF and OOXML URL detectors now emit `INFO` severity for benign
   namespace URIs and `SUSPICIOUS` severity for everything else - with
   the actual URL in the finding Detail

Effect on the user's case: VERDICT: SUSPICIOUS (1 suspicious + 1 info)
-> VERDICT: CLEAN (2 info) with both findings visible in the report.
Real IOCs (tested with `http://evil.example.com/payload.exe` in a
synthetic fixture) still surface as SUSPICIOUS with the malicious URL
in the finding Detail.

**Bug caught during implementation:** `Sort-Object -Unique` unrolls its
output to a scalar when there's exactly one result, and returns $null
when there are zero results. Under `Set-StrictMode -Version Latest`,
calling `.Count` on a string or $null throws "The property 'Count'
cannot be found on this object." Fix: force array context with `@()`:

```powershell
# WRONG (fails on 0 or 1 matches under StrictMode):
$uniqueUrls = $matches | ForEach-Object { $_.Value } | Sort-Object -Unique
$uniqueUrls.Count   # throws on scalar/null

# RIGHT (always an array, even for 0 or 1 element):
$uniqueUrls = @($matches | ForEach-Object { $_.Value } | Sort-Object -Unique)
$uniqueUrls.Count   # 0, 1, or N consistently
```

**Lesson:** Adding a new analysis unit or enhancing an existing one in
a standards-compliant phased script is usually a config + helper +
small-edit operation. The v2 architecture (helpers, Add-Finding, phase
structure) meant this URL enhancement required zero structural changes
- only a new config list, a new 7-line helper, and ~15 lines of logic
replacement. Extensibility is not free; it's paid for by the upfront
investment in small, composable primitives. Also: any PowerShell
pipeline that ends in `Sort-Object -Unique` or `Select-Object -Unique`
must be wrapped in `@()` when the downstream code uses `.Count` under
`Set-StrictMode -Version Latest`. This pattern ate one verification
cycle in this session.

---

## Carry-Forward Items

| CF-ID | Summary | Opened | Notes |
|---|---|---|---|
| CF-1 | Implement Phase 7 of the approved plan: Pester 5 tests + fixtures in `OfficeFiles/tests/` | phase01 | Synthetic VBA-needle fixture pattern already proven; fold into Pester test scaffold. Blocker: approved plan separated into Session 1 (script) and Session 2 (tests+artifacts) — user confirmed stopping at Session 1 |
| CF-2 | Implement Phase 8 of the approved plan: `OfficeFiles/README.md` + repo-root `CLAUDE.md` + verify `.gitignore` covers test outputs | phase01 | Same blocker as CF-1 |
| CF-3 | XLM-macro UTF-16LE false-positive review — current XLM indicator list may over-fire on benign .xls workbooks that legitimately reference `Macro1` in formula text or `veryHidden` in worksheet XML | phase01 | No MSI surfaced it; need a real .xls corpus run before tuning |
| CF-4 | OOXML keyword list review — current plain-substring match against `CreateObject`, `Shell`, `Base64` etc. may still false-positive on benign documents with those literal words in body text | phase01 | Not observed in 3 test files but only tested against IR report docs — broader corpus needed |
| CF-5 | PowerShell 5.1 compatibility test (Windows-default runtime) | phase01 | **RESOLVED 2026-04-24** via Unit 1.1 + 1.2 of pre-prod plan. Two surfaces fixed: (a) file had no UTF-8 BOM → PS 5.1 read as Windows-1252, mis-decoded 50 em-dashes, parser emitted 20 cascading errors — fixed by adding `EF-BB-BF` BOM prefix; (b) `[System.Text.Encoding]::Latin1` static is .NET Core/5+ only — replaced with `::GetEncoding(28591)` (ISO-8859-1 code page) for cross-runtime compat. Both runtimes now pass all 4 fixtures with immutability assertion; MSI analysis is 9s on PS 5.1 vs 1s on PS 7 (acceptable) |
| CF-6 | SentinelOne self-flagging risk assessment + allowlist | phase01 | **Critical — blocks production trial.** `$Script:SuspiciousKeywords` contains literal LOLBin names (mshta, regsvr32, certutil, bitsadmin, CreateObject, Shell.Application, WScript.Shell etc.). SentinelOne may string-scan the script on disk. Submit v2 SHA-256 to SentinelOne console for allowlist; characterize any detections before analyst deployment. User-controlled workflow (requires SentinelOne console access) |
| CF-7 | Copy-Item retry wrapper for locked sources | phase01 | **RESOLVED 2026-04-24.** Added `Invoke-WithRetry` helper from scripting-standards-v5.3 reference/powershell.md. Wrapped BOTH `Copy-Item` in `Copy-SourceSafely` AND `Get-FileHash` in `Compute-SourceHashes` — initial implementation wrapped only the copy, but Compute-SourceHashes runs first in Preflight and also reads the source. Both are idempotent reads, safe to retry. Verified via locked-source harness: file held with exclusive lock for 5s, script retries at t=0/2/6s and succeeds on third attempt at ~7s total. Both runtimes green |
| CF-8 | Password-protected / encrypted-package detection | phase01 | **RESOLVED 2026-04-24.** New `Detect-EncryptedPackage` unit in CFBF analysis path, runs first before expensive keyword/OLE scans. Uses `Find-BytePattern` to search raw bytes for UTF-16LE `EncryptedPackage` / `EncryptionInfo` / `DataSpaces` stream names. On hit emits SUSPICIOUS finding + `VERIFY_WARN` escalation note (escalate to olevba / MSOFFCRYPTO-tool with password). Verified with synthetic CFBF fixture containing the UTF-16LE EncryptedPackage needle at known offset. Both runtimes green |
| CF-9 | Deployment-workflow documentation: Mark-of-the-Web + ExecutionPolicy + script hash | phase01 | Merges with CF-2 README.md. Add: `Unblock-File` one-liner for post-GitHub-download; `powershell.exe -ExecutionPolicy Bypass -File ...` invocation; SHA-256 of v2 script for integrity verification; SentinelOne allowlist guidance conditional on CF-6 outcome |

---

## What Would Help Me Grow — Tooling Wishlist

### TW-1. lessons-learned_V3_5 had 4 missing reference files
**Sub-type:** meta-question
**Step 6 outcome:** RESOLVED OUT-OF-BAND — user uploaded the four missing
reference files (`bootstrap.md`, `templates.md`, `verify.md`,
`retroactive.md`) mid-reflection. Phase file subsequently corrected to
canonical formats per the newly-available `templates.md` (monotonic
single-integer entry numbering; `**Tags:**` + `## Overview` header
block). Drift dispatched in-session; no follow-up skill-development
reflection required.

Original observation: SKILL.md pointed to `bootstrap.md`, `templates.md`,
`verify.md`, `retroactive.md` in reference/ but none existed. Reflection
authors had to reconstruct formats from `invariants.md` + quick-reference
card, producing drift that Check 13 caught once templates.md became
available.

### TW-2. PowerShell `\x` hex-escape trap needs a skill rule
**Sub-type:** meta-fix
**Step 6 outcome:** APPLIED — added "String escape gotchas" section to
`.claude/skills/scripting-standards-v5.3/reference/powershell.md` with
case-study reference back to this phase file (phase01 §Bugs 2).

scripting-standards-v5.3/reference/powershell.md did not previously warn
about PowerShell's lack of `\x` hex escapes — this trap ate the entire
v1 CFBF OLE-stream detection unit and is non-obvious (every other
mainstream language supports the escape). A one-paragraph rule in the
PowerShell reference saves the next author from the same bug.

### TW-3. Benchmark-first rule for PS byte-scan hot paths
**Sub-type:** meta-fix
**Step 6 outcome:** APPLIED — added "Performance patterns" section to
`.claude/skills/scripting-standards-v5.3/reference/powershell.md` with
the `[Array]::IndexOf + tail-verify` reference implementation and the
case-study benchmark (1152ms → 17ms on 5MB buffer) cited back to this
phase file (phase01 §Bugs 3).

Related to TW-2 but distinct: no prior skill rule stated "benchmark any
PS interpreted-loop scan over >1MB data before committing." A
PowerShell-specific "PS interpreter is 1M bytes/sec" rule crystallized
the pattern that the ad-hoc benchmark surfaced mid-session.

---

## Metrics

| Metric | Value |
|---|---|
| Session duration (wall clock) | ~2 hours |
| Script line count: v1 → v2 | 768 → 1278 (+66%) |
| New helper functions | 7 (Write-JsonReport, New-TempWorkspace, Copy-SourceSafely, Find-BytePattern, Assert-SourceUnchanged, Add-Finding, Initialize-Script) |
| Format paths: v1 → v2 | 2 (OOXML, CFBF) → 3 (+ RTF) |
| New detection units | 4 (TemplateInjection, XLMMacros, RTFObjects, RTFEquationEditor, RTFEmbeddedExe) — 5 units implementing 4 detection categories |
| v1 bugs found by review | 7 (catalogued in Plan Context) |
| v1 bugs fixed in v2 | 6 (all except "$matches shadow" stylistic one — became non-issue after rewrite) |
| New bugs introduced and fixed in session | 2 (xmlns false-positive, naive-loop perf) |
| End-to-end verification runs | 7 (1 Preflight gate + 3 clean OOXML + 1 real CFBF + 2 synthetic CFBF) |
| Source-mutation failures across all runs | 0 |
| JSON round-trip failures | 0 |
| Parse failures | 0 |
| User decisions harvested via plan-mode AskUserQuestion | 6 |
| Prove-first invocations | 2 (UTF-16LE encoding; byte-scan benchmark) |
