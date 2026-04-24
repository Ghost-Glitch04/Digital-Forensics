# PowerShell — Language Semantics and Performance Rules

Rules specific to PowerShell syntax, idioms, and runtime behavior. Apply
when writing or debugging PowerShell scripts.

---

### Never use `\x` hex escapes in PowerShell string literals
<!-- tags: powershell, string-escape, hex-escape, byte-scan -->

**When:** Writing a PowerShell string literal or regex pattern that
needs to contain null bytes or specific byte values.

**Not when:** The project has confirmed it's a PowerShell Core 7+
environment AND uses a pattern that's been tested to match actual null
bytes (no known exception exists — see Why).

**Rule:** PowerShell (all versions through 7.x) does NOT support `\x`
hex escapes in string literals. A literal `"\x00"` in source is the
five-character string backslash-x-zero-zero — not a null byte. For null
bytes use the backtick-zero escape `` `0 ``; for byte-pattern matching
against binary content, build a `[byte[]]` explicitly:

```powershell
# WRONG — "V\x00B\x00A\x00" is a 9-character string; matches no null bytes
$pattern = "V\x00B\x00A\x00"
if ($content -match $pattern) { ... }   # always false against real CFBF

# RIGHT — use Encoding to build the byte sequence
$needle = [System.Text.Encoding]::Unicode.GetBytes('VBA')  # UTF-16LE: 56-00-42-00-41-00
$offset = Find-BytePattern -Haystack $bytes -Needle $needle

# RIGHT — use backtick-zero for inline null in a string
$nullByte = "`0"
```

**Why:** Every mainstream language except PowerShell supports `\x` hex
escapes, so copying a regex pattern from Python/Bash/C# silently fails
in PS. Error is silent — the regex simply never matches. Ate an entire
CFBF OLE-stream detection unit in Invoke-OfficeDocAnalysis v1 (the unit
was a no-op for 1+ year before v2 rewrite caught it).

**Companions:** powershell.md → "Benchmark PowerShell byte-scans against [Array]::IndexOf"

*Source: phase01:7*

---

### Benchmark PowerShell byte-scans against [Array]::IndexOf
<!-- tags: powershell, byte-scan, performance, array-indexof, interpreted-loop -->

**When:** About to write a scan over a byte array (or Latin-1 string
projection of a byte array) larger than 1MB, especially in a hot path
called multiple times per phase.

**Not when:** The scan runs once over a file guaranteed to be under
100KB (e.g., scanning a config file or a single XML part). The
interpreted-loop overhead is invisible at that size.

**Rule:** PowerShell-interpreted nested for-loops scan ~1M bytes/sec.
For byte-pattern needles in multi-MB files, use `[Array]::IndexOf` to
jump to candidate first-byte positions, then verify remaining bytes in
a short tight loop. Typical speedup: 50-100× on 5MB buffers.

```powershell
function Find-BytePattern {
    param([byte[]]$Haystack, [byte[]]$Needle)
    if ($Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) { return -1 }
    $maxStart = $Haystack.Length - $Needle.Length
    $first    = $Needle[0]
    $pos      = 0
    while ($pos -le $maxStart) {
        $found = [Array]::IndexOf($Haystack, $first, $pos)
        if ($found -lt 0 -or $found -gt $maxStart) { return -1 }
        $match = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$found + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { return $found }
        $pos = $found + 1
    }
    return -1
}
```

**Why:** Measured on 5MB random buffer with known needle — naive PS
loop: 1152ms; `[Array]::IndexOf` + tail-verify: 17ms (68× faster).
`[Array]::IndexOf` compiles to a native .NET span search; the PS
interpreter is avoided except for the short tail-verify loop.

**Companions:** powershell.md → "Never use \\x hex escapes in PowerShell string literals", process.md → "Benchmark hot-path scans before committing"

*Source: phase01:8*

---

### Validate parseability before first execution of PowerShell scripts >500 lines
<!-- tags: powershell, parse-check -->

**When:** Finishing a large PowerShell script write (>500 lines) and
about to run it for the first time.

**Not when:** The script is under ~200 lines AND was edited unit-by-unit
with successful execution after each unit.

**Rule:** Run
`[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)`
before any execution. Parse errors fail immediately with line numbers
and specific messages; they're much cheaper to fix from a parse dump
than from a runtime partial execution.

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors) | Out-Null
if ($errors) {
    $errors | ForEach-Object { Write-Host "Line $($_.Extent.StartLineNumber): $($_.Message)" }
    exit 1
}
Write-Host "PARSE_OK: no syntax errors"
```

**Why:** PowerShell requires whole-file parse validity. A runtime
execution of a script with a syntax error in a late unit will execute
all earlier units (making side-effecting changes) before failing at
the parser when control reaches the broken section — parse-first
catches the error before any side effect.

**Companions:** process.md → "Plan-mode discriminators before drafting"

*Source: phase01:5*

---

### Benchmark PS hot-path scans before committing an algorithm
<!-- tags: powershell, performance, benchmark-first -->

**When:** About to implement a hot-path scan (byte-pattern search,
regex over large content, bulk-record iteration) in PowerShell.

**Not when:** The operation runs once per script invocation over data
<100KB, or the algorithm is demonstrably I/O-bound rather than
CPU-bound.

**Rule:** Before committing a scan implementation, run a 2-minute
benchmark comparing naive loop, `[Array]::IndexOf`, Latin-1 string
`IndexOf`, and `[regex]::Matches` on a buffer sized to the realistic
production case. Pick by measurement; no argument from authority.

```powershell
$buf = New-Object byte[] (5MB)
(New-Object System.Random(42)).NextBytes($buf)
# ... place known needle at known offset ...

$sw = [System.Diagnostics.Stopwatch]::StartNew()
# Algorithm A
$sw.Stop(); "A: $($sw.Elapsed.TotalSeconds)s"

$sw.Restart()
# Algorithm B
$sw.Stop(); "B: $($sw.Elapsed.TotalSeconds)s"
```

**Why:** PowerShell's interpreted loops hide 10-100× speedups behind
semantically-equivalent alternatives. Intuition from other languages
(C#, Python with C-backed libs) does not transfer — the interpreter
is the bottleneck, not the algorithm's big-O. Specific measured
results: naive loop 1152ms vs `[Array]::IndexOf` 17ms on a 5MB buffer
with a 6-byte needle (68× faster).

**Companions:** powershell.md → "Benchmark PowerShell byte-scans against [Array]::IndexOf", process.md → "Prove-first with a 30-second one-liner"

*Source: phase01:8*

---

### Keep .ps1 source strict ASCII when cross-runtime (PS 5.1 + PS 7) use is expected
<!-- tags: powershell, file-encoding, ascii, ps51, redistribution -->

**When:** Writing a PowerShell script that (a) must run on both Windows
PowerShell 5.1 AND PowerShell 7+, AND (b) will be redistributed through
copies, downloads, git clones, or editor round-trips between the author
and end users.

**Not when:** The script is internal-only and author-maintained, where
the author controls the distribution path and can guarantee UTF-8 BOM
preservation through every hop. Then non-ASCII content (em-dashes,
curly quotes, Unicode bullets) is fine with a UTF-8 BOM.

**Rule:** Restrict `.ps1` source to strict ASCII content (code + comments
+ log messages + string literals). Keep a UTF-8 BOM as defense-in-depth
(and as a canary for future non-ASCII re-introduction), but do not depend
on it alone for parseability. BOM preservation is a fragile contract that
many editors and copy tools break silently; ASCII content has no such
contract.

```powershell
# Audit for any non-ASCII in a script:
$p = 'MyScript.ps1'
$content = [System.IO.File]::ReadAllText($p, [System.Text.UTF8Encoding]::new($true))
$bad = 0
for ($i = 0; $i -lt $content.Length; $i++) {
    if ([int][char]$content[$i] -gt 127) { $bad++ }
}
"Non-ASCII chars: $bad"

# Stress-test that parsing still works if the BOM is stripped:
$stripped = Join-Path $env:TEMP 'no-bom-test.ps1'
$bytes = [System.IO.File]::ReadAllBytes($p)
[System.IO.File]::WriteAllBytes($stripped, $bytes[3..($bytes.Length - 1)])
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($stripped, [ref]$null, [ref]$errors) | Out-Null
if ($errors) { 'FAIL - script depends on BOM; remove non-ASCII content' } else { 'OK - BOM-independent' }
```

Common non-ASCII characters that look innocent but break this:
- em-dash `—` (U+2014) -> replace with `-` or `--`
- en-dash `–` (U+2013) -> replace with `-`
- right-arrow `→` (U+2192) -> replace with `->`
- left-arrow `←` (U+2190) -> replace with `<-`
- curly-quote `"` `"` (U+201C / U+201D) -> replace with `"`
- curly-apostrophe `'` `'` (U+2018 / U+2019) -> replace with `'`
- ellipsis `…` (U+2026) -> replace with `...`
- bullet `•` (U+2022) -> replace with `*` or `-`
- non-breaking space ` ` -> replace with regular space
- byte-order mark in the MIDDLE of a file (editor bug) -> remove

**Why:** Invoke-OfficeDocAnalysis v2.0.0 initially fixed PS 5.1
parseability by adding a UTF-8 BOM to a script containing 59 em-dashes
+ 1 right-arrow (phase01:13). That worked in the author's environment
but left the script dependent on every subsequent copy preserving the
3-byte BOM prefix. A user's first production run copied the script via
a path that stripped the BOM and reproduced the original parse errors
on PS 5.1 — the same symptom the BOM fix had supposedly closed.
v2.0.1 restricted the script to strict ASCII content as the durable
fix. Stress-tested: BOM-stripped copy now parses cleanly on PS 5.1.

**Supersedes:** powershell.md -> "Save .ps1 files with a UTF-8 BOM if they contain any non-ASCII characters"
**Supersession reason:** narrowed

**Companions:** powershell.md -> "Prefer .NET Framework 4.x-compatible APIs for cross-runtime PowerShell scripts", powershell.md -> "Validate parseability before first execution of PowerShell scripts >500 lines"

*Source: phase01:15*

---

### Save .ps1 files with a UTF-8 BOM if they contain any non-ASCII characters
<!-- tags: powershell, file-encoding, bom, ps51 -->

**Superseded by:** powershell.md -> "Keep .ps1 source strict ASCII when cross-runtime (PS 5.1 + PS 7) use is expected"
**Supersession reason:** narrowed - the BOM fix solves the local-author case
but leaves the redistribution / copy-operation case still broken. The
ASCII rule solves both.


**When:** Authoring or editing a `.ps1` file that contains any characters
outside the ASCII range — em-dashes, curly quotes, accented letters,
mathematical symbols, Unicode bullets, any non-Latin script.

**Not when:** The script is strict ASCII (no smart-quote auto-corrections
from the editor, no em-dashes in comments, no non-English identifiers).
A BOM is unnecessary in that case and some Unix-adjacent tooling prefers
BOM-free UTF-8.

**Rule:** Write `.ps1` files as UTF-8 with BOM (`EF BB BF` prefix) when
any non-ASCII character is present. Windows PowerShell 5.1 (the inbox
default on Windows 10/11) reads `.ps1` files as Windows-1252 when no
BOM is present; every multi-byte UTF-8 character decodes to multiple
garbage characters, corrupting the token stream. PowerShell 7+ reads
UTF-8 by default and tolerates missing BOMs.

```powershell
# Apply BOM to an existing file:
$content = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($path, $content, [System.Text.UTF8Encoding]::new($true))
```

Or in PS 5.1-native idiom: `Set-Content -Path $path -Value $content -Encoding UTF8`
(on PS 5.1 this writes WITH BOM; on PS 7 this writes WITHOUT BOM —
version-dependent, so prefer the explicit .NET form above for portability).

**Why:** `Invoke-OfficeDocAnalysis.ps1` was authored on PS 7.6 (cleanly
parses UTF-8 without BOM) and contained 50 em-dashes in comments and log
strings. First run on PS 5.1 emitted 20 cascading parse errors starting
at line 496. Root cause: each em-dash (3 UTF-8 bytes `E2 80 94`) decoded
as 3 Windows-1252 characters, which broke at various structural tokens.
Adding the BOM made the script parse cleanly on both runtimes. The
symptom looks like a syntax error but is actually an encoding error;
grepping for "Unexpected token" won't find the fix.

**Companions:** powershell.md → "Prefer .NET Framework 4.x-compatible APIs for cross-runtime PowerShell scripts"

*Source: phase01:13*

---

### Prefer .NET Framework 4.x-compatible APIs for cross-runtime PowerShell scripts
<!-- tags: powershell, dotnet-version, framework-vs-core, ps51 -->

**When:** Writing a PowerShell script that must run on both Windows
PowerShell 5.1 (inbox, .NET Framework 4.x) AND PowerShell 7+ (.NET 5+).
Common for public tooling, IT admin scripts, any `#Requires -Version 5.1`
target.

**Not when:** The script is explicitly `#Requires -Version 7.0` or
higher — then .NET Core / .NET 5+ APIs are fair game.

**Rule:** Check API availability on .NET Framework 4.x before using
any `[System.*]` static in a cross-runtime script. A type or static
that exists in .NET Core / 5+ / 8 may not exist in .NET Framework 4.x.
The script will parse fine (types are resolved at runtime, not parse
time) but will throw at the use site with a confusing "property cannot
be found" error.

Common traps:
- `[System.Text.Encoding]::Latin1` — .NET Core/5+ only. Use
  `[System.Text.Encoding]::GetEncoding(28591)` (ISO-8859-1) for PS 5.1.
- `[System.Text.Encoding]::UTF8NoBOM` — likewise .NET Core/5+. Use
  `[System.Text.UTF8Encoding]::new($false)` explicitly.
- `[System.Array]::Empty[T]()` — supported on both, but syntax differs.
- `System.Text.Json` namespace — .NET Core/5+ only. Fall back to
  `ConvertTo-Json` / `ConvertFrom-Json` cmdlets for portability.
- `.NET 5+` ranges / indices (`[0..^1]`) work in PS language syntax
  but the underlying `System.Index` / `System.Range` types are .NET
  Core/5+ only — so mixing into direct .NET API calls fails on PS 5.1.

**Verification technique:** test on `powershell.exe` (inbox PS 5.1),
not just `pwsh.exe` (PS 7+). Both are typically available on modern
Windows — invoke explicitly by binary name.

```powershell
# Compatibility testing pattern — run BOTH in CI or local verification:
powershell.exe  -NoProfile -File .\script.ps1 -FilePath .\fixture.docx   # PS 5.1
pwsh.exe        -NoProfile -File .\script.ps1 -FilePath .\fixture.docx   # PS 7+
```

**Why:** `Invoke-OfficeDocAnalysis.ps1` used
`[System.IO.File]::ReadAllText($path, [System.Text.Encoding]::Latin1)`
for a Latin-1 byte-preserving string projection of CFBF binary content.
Worked on PS 7.6 (.NET 8) but threw "`The property 'Latin1' cannot be
found on this object`" at the use site on PS 5.1 (.NET Framework 4.x).
Static was added in .NET Core 5.0; .NET Framework 4.8 predates it.
Fix: `[System.Text.Encoding]::GetEncoding(28591)` (code page for
ISO-8859-1 which is the canonical name for Latin-1) works on both
runtimes and produces identical byte-to-char mapping.

**Companions:** powershell.md → "Save .ps1 files with a UTF-8 BOM if they contain any non-ASCII characters"

*Source: phase01:13*
