# Process — Methodology Rules

Rules about how work gets done — planning, prove-first, measurement
discipline. Apply regardless of the specific technology being used.

---

### Prove-first with a 30-second one-liner before implementing a byte-level primitive
<!-- tags: prove-first, byte-scan -->

**When:** About to implement a primitive that depends on a low-level
semantic you haven't personally verified in this environment — byte
encoding, string escape behavior, locale handling, regex engine
quirks, integer overflow wrap.

**Not when:** The semantic is documented and the doc has been cited
from a previous verified use in the same environment within the last
few sessions.

**Rule:** Before writing the primitive (which usually imports several
modules, sets up fixtures, and codifies the assumption into structure),
write a 30-second standalone test that proves or disproves the
assumption in isolation. The bar is wall-clock time: if proving costs
more than the rework you'd avoid, skip it. Otherwise always run it.

```powershell
# Example: before implementing Find-BytePattern, verify the encoding assumption
$needle = [System.Text.Encoding]::Unicode.GetBytes('VBA')
Write-Host ([System.BitConverter]::ToString($needle))
# Expected: 56-00-42-00-41-00 (UTF-16LE: each ASCII char + null byte)
# If output differs, STOP — the whole Find-BytePattern design rests on this
```

**Why:** Invoke-OfficeDocAnalysis v1 shipped a CFBF OLE-stream
detection unit that was a no-op for over a year because its author
assumed `"\x00"` in a PS string equaled a null byte (it does not).
A 30-second check would have caught it. v2 ran the check before
writing the primitive; the primitive worked first try. The prove-first
discipline catches an entire class of "assumption encoded into
structure before validation" failures.

**Companions:** powershell.md → "Never use \\x hex escapes in PowerShell string literals", process.md → "Benchmark hot-path scans before committing"

*Source: phase01:2*

---

### Extract binding decisions via plan-mode AskUserQuestion before drafting
<!-- tags: plan-mode, askuserquestion, plan-first, discriminator-questions -->

**When:** Starting multi-option architectural work where the design
space admits multiple defensible answers (rewrite strategy, output
format choice, scope of new features, file layout).

**Not when:** The task is linear (one-bug-one-fix), or the user's
earlier message already specified the binding choices explicitly, or
the work is trivial enough that a wrong choice is cheap to revert.

**Rule:** In plan mode, before drafting the plan file, use
`AskUserQuestion` with 1-4 multi-choice questions that each discriminate
a single design axis. Put the recommended option first with
"(Recommended)" when one exists. Answers collapse the design space
before any code runs.

Good discriminators:
- "Priority ordering" (bugs first vs. features first vs. rewrite)
- "Output formats" (which artifacts ship — often multi-select)
- "Scope extensions" (which new detections / capabilities)
- "Integration mode" (replace / sidecar / rename-old)

**Why:** Invoke-OfficeDocAnalysis v2 plan phase used six multi-choice
questions to extract six binding decisions (rewrite strategy, output
formats, new detections, temp handling, file layout, artifacts).
Each choice cut downstream ambiguity by a factor — "full rewrite to
standards template" eliminated a whole class of "preserve v1
structure where possible" sub-questions. The approved plan survived
contact with reality with zero scope revisions, meaning the 2 minutes
spent on questions saved an unknown but non-zero amount of
mid-session reconsideration.

**Companions:** process.md → "Prove-first with a 30-second one-liner", powershell.md → "Validate parseability before first execution of PowerShell scripts >500 lines"

*Source: phase01:1*

---

### Benchmark hot-path scans before committing an algorithm
<!-- tags: benchmark-first, performance, prove-first -->

**When:** Choosing between semantically-equivalent algorithms for a
hot-path operation — byte-scan, regex match, bulk data transform.

**Not when:** Only one viable algorithm exists, or the operation runs
once over trivial data where even 100× overhead is <10ms total.

**Rule:** Run a 2-minute benchmark comparing at least 2 candidate
algorithms on a realistic-sized input before committing one. The
algorithm with the measured best time wins. No argument from
authority, no "this should be faster because..." — numbers decide.

```powershell
$buf = <allocated to realistic production size>
$sw = [System.Diagnostics.Stopwatch]::StartNew()
# Algorithm A
$sw.Stop(); $timeA = $sw.Elapsed.TotalSeconds

$sw.Restart()
# Algorithm B
$sw.Stop(); $timeB = $sw.Elapsed.TotalSeconds

# Pick by measurement
```

**Why:** Invoke-OfficeDocAnalysis v2's byte-scan primitive had three
candidate algorithms. Intuition would have picked "native PS loop" as
"clean and simple." Benchmark on 5MB buffer: naive PS loop 1152ms,
Latin-1 IndexOf 42ms, `[Array]::IndexOf` + tail-verify 17ms. The
measured winner was 68× faster than the intuitive choice — a speedup
impossible to justify on a priori reasoning, but trivial to verify
with 2 minutes of wall clock.

**Companions:** powershell.md → "Benchmark PowerShell byte-scans against [Array]::IndexOf", process.md → "Prove-first with a 30-second one-liner"

*Source: phase01:8*

---

### Condition artifact-preservation switches on the verdict that makes preservation useful
<!-- tags: switch-design, cli-ergonomics -->

**When:** Designing a CLI switch whose purpose is to preserve
intermediate artifacts (temp dirs, extracted payloads, cached
responses) for post-hoc inspection.

**Not when:** The preservation is trivially cheap (a few KB) and
always useful — in that case, always preserve and offer a `-Clean`
switch to remove instead.

**Rule:** Condition the switch on the verdict / outcome that makes
preservation actually useful, not on an orthogonal always/never flag.
`-KeepTempOnAlert` means "keep when preservation is an escalation
affordance"; `-KeepTemp` unconditionally fills the temp directory for
every analyst who runs the script in a loop. The switch name should
communicate the condition, not just the action.

**Why:** Invoke-OfficeDocAnalysis v2 considered three options for
workspace preservation: always keep (fills $env:TEMP on looped runs),
never keep (forces re-run against source for escalation), or keep-iff
verdict=MALICIOUS. The conditional form is the only one that preserves
exactly when an analyst needs the artifact (escalation case) and
doesn't when they don't (routine CLEAN / SUSPICIOUS case). A secondary
affordance exists via `-DebugMode` for unconditional preservation in
post-mortem contexts — two switches, each with a specific use.

**Companions:** process.md → "Extract binding decisions via plan-mode AskUserQuestion before drafting"

*Source: phase01:11*

---

### When adding retry to a transient-failure-prone resource access, wrap every call-site
<!-- tags: retry, idempotency, call-site-audit -->

**When:** Adding retry logic around an operation that reads or copies
a resource whose transient unavailability is the triggering symptom
(file locks, network blips, API rate limits).

**Not when:** The symptom is produced by a single well-known call-site
and no other code path touches the same resource — then single-site
wrap is sufficient.

**Rule:** Before landing the retry, grep for every call that touches
the same resource. Wrap each one (or consolidate them behind a single
helper that wraps once). A retry wrapper on one of N call-sites is a
partial fix that looks complete in testing that doesn't exercise the
earlier sites. Name the full call-site list in the commit message or
Development Notes so reviewers can verify coverage.

```powershell
# Before shipping a retry wrapper, grep the source for every site that
# reads the same resource:
Select-String -Path *.ps1 -Pattern 'Get-FileHash.*\$FilePath|Copy-Item.*\$FilePath|Get-Item.*\$FilePath'
# Then wrap each or consolidate behind one helper.
```

**Why:** `Invoke-OfficeDocAnalysis` CF-7 initially wrapped only the
`Copy-Item` call in `Copy-SourceSafely`. The locked-source harness
still failed because `Compute-SourceHashes` (3 × `Get-FileHash`) runs
earlier in Preflight and also reads the source. The wrapped copy
helper never executed. Fix required a second Invoke-WithRetry wrap
in Compute-SourceHashes. A pre-landing grep for `Get-FileHash.*FilePath`
would have surfaced the gap in 30 seconds.

**Companions:** powershell.md → "Benchmark hot-path scans before committing an algorithm", forensic_triage.md → "Prove source immutability via hash round-trip in the log"

*Source: phase01:14*
