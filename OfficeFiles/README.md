# Invoke-OfficeDocAnalysis.ps1

Static, read-only forensic analysis of Microsoft Office documents for
EDR false-positive triage. Detects macros, embedded objects, template
injection, Equation Editor exploits, XLM macros, and encrypted packages
— without ever modifying the source file.

**Version:** 2.1.0
**Author:** Ghost-Glitch04
**License:** (TBD — will be set at public-release time)

---

## What it does

You get an alert from SentinelOne (or any EDR) on an Office document.
Before you escalate or quarantine a potentially business-critical file,
you want a second opinion from a tool whose detection logic you can
read. This script is that tool.

It copies the flagged file to `$env:TEMP`, classifies it by magic
bytes (not by extension — attackers rename files), extracts or parses
its structure depending on the format, runs a suite of static checks,
and returns a verdict: **CLEAN**, **SUSPICIOUS**, or **MALICIOUS**.
The original file is never modified; this is verified via SHA-256
round-trip and emitted to the log on every run.

### Supported formats (detected by magic bytes, not extension)

| Format | Magic | Covers | Analysis path |
|---|---|---|---|
| **OOXML** | `50-4B-03-04` | `.docx`, `.xlsx`, `.pptx`, `.docm`, `.xlsm`, `.pptm`, `.dotm`, etc. | ZIP extraction + XML / `.rels` scan |
| **CFBF**  | `D0-CF-11-E0` | `.doc`, `.xls`, `.ppt`, `.msi`, password-protected OOXML | Raw-byte stream-name & keyword scan |
| **RTF**   | `7B-5C-72-74-66-31` (`{\rtf1`) | `.rtf`, `.doc`-renamed-RTF spoof | `\objdata` hex decode + OLE marker scan |

### What it detects

- **VBA macros** (vbaProject.bin, UTF-16LE `VBA` stream, AutoOpen / Document_Open triggers)
- **ActiveX controls** (activeX*.bin)
- **Template injection** (`attachedTemplate` with `TargetMode="External"` in settings.xml.rels)
- **External relationships** (OLE/remote targets in `.rels`)
- **DDE** (Dynamic Data Exchange references — classic macro-less payload vector)
- **Equation Editor** (CVE-2017-11882 / CVE-2018-0802 class)
- **Embedded executables** (MZ header inside decoded RTF `\objdata`)
- **XLM / Excel 4.0 macros** (Auto_Open, Macro1, veryHidden indicators)
- **Encrypted packages** (EncryptedPackage / EncryptionInfo stream names — flags silent-CLEAN false negatives)
- **Suspicious keyword LOLBin list** (PowerShell, mshta, regsvr32, certutil, bitsadmin, CreateObject, Shell.Application, etc.)
- **External URLs** — full URL is captured and included in finding Detail. Known-benign XML namespace URIs (schemas.microsoft.com, openxmlformats.org, w3.org, etc.) report as INFO; all other URLs report as SUSPICIOUS with the URL itself visible, so the analyst doesn't need a separate extraction step.
- **Extension spoofing** (magic bytes don't match declared extension)

### What it does NOT do

This is a **triage** tool, not a complete analysis platform. On escalation:
- **VBA decompilation / deobfuscation** → use `olevba` from oletools
- **RTF OLE object extraction** → use `rtfobj` from oletools
- **XLM macro decoding** → use `XLMMacroDeobfuscator`
- **Sandbox / dynamic analysis** → use FLARE VM or a proper sandbox
- **PE analysis** of embedded executables → PE-bear, CFF Explorer, IDA

---

## Prerequisites

- **Windows** (tested on Windows 10/11, 10.0.26100)
- **PowerShell 5.1 or later** (inbox `powershell.exe` works; `pwsh.exe` 7+ also works and is faster)
- **No admin required** — script runs as the invoking user, reads only
- **No network access required** — purely static, offline analysis

### Runtime performance note

A 5MB CFBF MSI scans in ~1 second on pwsh 7 and ~9 seconds on Windows
PowerShell 5.1 — the .NET Framework 4.x `[Array]::IndexOf` backing the
byte-pattern scan is materially slower than .NET 8's. If you're running
routinely on PS 5.1 and latency is a concern, install PowerShell 7+ from
the Microsoft Store or [microsoft.com/powershell](https://github.com/PowerShell/PowerShell/releases).

---

## First-time setup

### 1. Download the script

Clone the repo or download `Invoke-OfficeDocAnalysis.ps1` directly.

### 2. Unblock the file (Windows MOTW)

Files downloaded from the internet carry a "Mark of the Web" attribute
that blocks execution. Strip it:

```powershell
Unblock-File -LiteralPath .\Invoke-OfficeDocAnalysis.ps1
```

### 3. Verify script integrity

The published SHA-256 for **v2.1.0** is:

```
B9316CFC078AD3286FF2C847115857E61BFD2676FD27C57F9CCFEEA8BDC70C53
```

Verify locally:

```powershell
Get-FileHash -LiteralPath .\Invoke-OfficeDocAnalysis.ps1 -Algorithm SHA256
```

If the hash doesn't match, the file was modified in transit — re-download.

### 3a. Sanity-check the file parses before running (60 seconds)

v2.0.1 is **ASCII-only source** + UTF-8 BOM. The script is designed to
parse cleanly on both Windows PowerShell 5.1 and PowerShell 7+
regardless of whether a copy operation preserved or stripped the BOM.
Still, it's worth confirming with a parse check before feeding the
script a real case file:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile('.\Invoke-OfficeDocAnalysis.ps1', [ref]$null, [ref]$errors) | Out-Null
if ($errors) {
    Write-Host "PARSE FAIL - do not run this copy. Re-fetch from the repo." -ForegroundColor Red
    $errors | Select-Object -First 3 | ForEach-Object {
        Write-Host "  Line $($_.Extent.StartLineNumber): $($_.Message)"
    }
} else {
    Write-Host "PARSE OK - safe to run" -ForegroundColor Green
}
```

Parse errors on this script mean one of three things:
- The file was corrupted in transit (re-fetch from repo)
- A text editor re-encoded it from UTF-8 to something else (re-fetch)
- Someone edited the file and introduced a syntax error (check git log)

**Prior to v2.0.1**, parse errors on PowerShell 5.1 were a real ongoing
hazard because the script contained 60 non-ASCII characters (em-dashes
and one right-arrow). Any copy operation that stripped the UTF-8 BOM
caused PS 5.1 to mis-decode those characters as Windows-1252, corrupting
the token stream. v2.0.1 eliminates the source of that hazard by
restricting the script to strict ASCII content.

### 4. Set execution policy (session-scoped)

Unsigned scripts won't run under the default `RemoteSigned` policy. Use
the session-scoped bypass (no system-wide change):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

Or invoke directly with `-ExecutionPolicy Bypass`:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx"
```

### 5. EDR considerations

> **Note — SentinelOne / EDR allowlist:** The script contains literal
> LOLBin keywords in `$Script:SuspiciousKeywords` (mshta, regsvr32,
> certutil, bitsadmin, CreateObject, Shell.Application, etc.) because
> those are its **detection patterns** — not runtime targets. Your EDR
> may string-scan the script on disk and flag it. Before deploying to
> analyst workstations:
>
> - Submit the script's SHA-256 (above) to your EDR console for allowlist
> - Document the allowlist ticket / ID alongside this README
> - If allowlist is denied, discuss with the author before deploying
>
> This section will be updated with specific allowlist instructions once
> the first deployment target is known.

---

## Basic usage

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx"
```

That's it. Default behavior:
- Copies source to `$env:TEMP\OfficeAnalysis_<guid>\`
- Runs all four phases (Preflight → Extraction → Analysis → Report)
- Prints colored console report
- Writes JSON findings + log to `$env:TEMP\OfficeAnalysis-Reports\`
- Cleans up the temp workspace
- Returns exit 0 on success; prints VERDICT before exit

---

## Parameter reference

| Parameter | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `-FilePath` | string | **yes** | — | Full path to the Office document to analyze |
| `-OutputDir` | string | no | `$env:TEMP\OfficeAnalysis-Reports` | Where log + JSON get written |
| `-StopAfterPhase` | enum | no | `None` | Stop cleanly after: `Preflight` / `Extraction` / `Analysis` / `Report` |
| `-OutputFormat` | enum | no | `Both` | Output channels: `Console` / `Json` / `Both` |
| `-KeepTempOnAlert` | switch | no | off | When verdict is MALICIOUS, preserve temp workspace for escalation |
| `-DryRun` | switch | no | off | Run all phases but skip JSON write (log still written) |
| `-DebugMode` | switch | no | off | Promote DEBUG log entries to console; preserve workspace on script failure |

---

## Command recipes — by feature

### Default — full analysis, console + JSON

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx"
```

Console report plus JSON file in `$env:TEMP\OfficeAnalysis-Reports\`.
Workspace cleaned up at the end.

### JSON only — for automation / SOC ticketing pipelines

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -OutputFormat Json
```

Suppresses the colored console report. Log file still written (it's the
operational record). Use this when wrapping the script from another tool
that will parse the findings JSON.

### Console only — for quick interactive triage

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -OutputFormat Console
```

No JSON file on disk. Fastest for one-off "is this actually bad?" checks
when you don't need persistent findings.

### Custom output directory

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -OutputDir "D:\IR-cases\case-2026-04-24"
```

Useful when building a case folder — keeps the log and findings JSON
next to your other case artifacts rather than in `$env:TEMP`.

### Preserve workspace on a MALICIOUS verdict (for escalation)

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -KeepTempOnAlert
```

If verdict is `MALICIOUS`, the temp workspace (including extracted
`vbaProject.bin`, XML tree, etc.) is preserved and its path is logged
prominently. Hand the workspace path off to `olevba` / `rtfobj`. If
verdict is CLEAN or SUSPICIOUS, workspace is cleaned up as usual.

### Stop at a specific phase — mid-run inspection

```powershell
# Stop after Preflight to inspect hashes + format detection only
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -StopAfterPhase Preflight

# Stop after Extraction to manually inspect the temp workspace before analysis runs
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -StopAfterPhase Extraction

# Stop after Analysis to review findings before Report phase writes JSON
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -StopAfterPhase Analysis
```

A phase-gate stop always exits 0 (it's not a failure). Use this when
developing custom analysis on top of the script, or when you want to
poke around the extracted OOXML tree manually.

### Dry run — all analysis, no JSON written

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -DryRun
```

Runs Preflight, Extraction, Analysis, Report — but skips the JSON findings
file write. Console report still prints; log file still written. Useful
for verifying the script behaves correctly on a new file type without
accumulating report files.

### Debug mode — verbose console output

```powershell
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" -DebugMode
```

Promotes DEBUG-level log entries to console (which otherwise go to file
only). Also preserves the temp workspace if the script fails unexpectedly.
Use this when troubleshooting unexpected behavior.

### Combined — escalation-ready case folder

```powershell
.\Invoke-OfficeDocAnalysis.ps1 `
    -FilePath     "C:\Cases\INC-2026-042\suspect.docm" `
    -OutputDir    "C:\Cases\INC-2026-042\triage-output" `
    -OutputFormat Both `
    -KeepTempOnAlert `
    -DebugMode
```

Full analysis, outputs in the case folder, workspace preserved on
MALICIOUS verdict, verbose console. The typical invocation for a real
incident.

---

## Output routing — where everything goes

### What gets written (and where)

| Output | Path | Enabled by | Purpose |
|---|---|---|---|
| **Log file** | `<OutputDir>\Invoke-OfficeDocAnalysis-<timestamp>.log` | always | Operational record, chronological log of every unit, findings, verdict, immutability assertion |
| **JSON findings** | `<OutputDir>\Invoke-OfficeDocAnalysis-<timestamp>.findings.json` | `-OutputFormat Json`/`Both` (default), NOT on `-DryRun` | Machine-readable report for SOC tooling |
| **Console report** | stdout (colored) | `-OutputFormat Console`/`Both` (default) | Human-readable summary for interactive triage |
| **Temp workspace** | `$env:TEMP\OfficeAnalysis_<guid>\` | always during analysis | Verified source copy + extracted content (OOXML tree, raw bytes). Cleaned up at end unless `-KeepTempOnAlert`+MALICIOUS or `-DebugMode`+failure |

### Reading the JSON findings in PowerShell

```powershell
$report = Get-Content "$env:TEMP\OfficeAnalysis-Reports\Invoke-OfficeDocAnalysis-20260424-144036.findings.json" -Raw | ConvertFrom-Json

$report.verdict                    # CLEAN / SUSPICIOUS / MALICIOUS
$report.counts.alert               # number of ALERT findings
$report.findings                   # array of findings
$report.findings | Where-Object { $_.Severity -eq 'ALERT' }   # just the ALERT-level ones
$report.source.hashes.sha256       # SHA-256 of the analyzed source
$report.format.detected            # OOXML / CFBF / RTF
$report.escalation_recommended     # bool — whether to escalate to oletools etc.
```

### Redirecting console output to a file

The console report writes via `Write-Host` which PowerShell captures
differently than stdout. Use PowerShell's redirection operators:

```powershell
# Capture both console and error streams to a file
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" *> console-capture.txt

# Capture just the host (console) stream (PS 7+)
.\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx" 6> console-capture.txt

# Most reliable — use the log file (always written, contains everything):
Get-Content "$env:TEMP\OfficeAnalysis-Reports\*.log" | Select-Object -Last 50
```

For automation, prefer parsing the JSON report over scraping console output.

### Piping verdict to another tool

```powershell
# Run analysis, parse JSON, act on verdict
.\Invoke-OfficeDocAnalysis.ps1 -FilePath $file -OutputFormat Json | Out-Null
$latestReport = Get-ChildItem "$env:TEMP\OfficeAnalysis-Reports\*.findings.json" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$report = Get-Content $latestReport.FullName -Raw | ConvertFrom-Json

switch ($report.verdict) {
    'MALICIOUS'  { Send-PagerAlert -Details $report.findings }
    'SUSPICIOUS' { Add-TicketComment -Number $incId -Body ($report | ConvertTo-Json -Depth 6) }
    'CLEAN'      { Write-Host "No action required for $file" -ForegroundColor Green }
}
```

### Greppable log-file fields

Every log line follows `[YYYY-MM-DD HH:MM:SS] [LEVEL] PREFIX: message`.
Useful greps:

```powershell
# Find the verdict
Select-String -Path "$env:TEMP\OfficeAnalysis-Reports\*.log" -Pattern 'VERDICT:'

# All ALERT findings across all runs
Select-String -Path "$env:TEMP\OfficeAnalysis-Reports\*.log" -Pattern '\[ALERT\]'

# Verify immutability for a specific run
Select-String -Path "$logpath" -Pattern 'Source file immutability confirmed'

# Every UNIT_FAILED / VERIFY_FAILED across all runs
Select-String -Path "$env:TEMP\OfficeAnalysis-Reports\*.log" -Pattern 'UNIT_FAILED|VERIFY_FAILED|SCRIPT_FAILED'
```

---

## Verdict interpretation

| Verdict | Meaning | Recommended action |
|---|---|---|
| **CLEAN** | Zero ALERT-level findings, zero SUSPICIOUS findings | Overrule the EDR alert; document the decision with the log + JSON. Re-flag only if new IOCs emerge. |
| **SUSPICIOUS** | At least one SUSPICIOUS finding, zero ALERT | Read the findings. Common SUSPICIOUS causes: external URLs in relationships, macro-enabled content type with benign body, legitimate embedded objects, encrypted package. Most CFBF / MSI files land here due to expected LOLBin strings in installers. Use judgment; escalate if context warrants. |
| **MALICIOUS** | At least one ALERT-level finding | **Treat the EDR alert as confirmed.** Do NOT open the file. Preserve workspace with `-KeepTempOnAlert`; escalate per IR playbook; hand the workspace to olevba/rtfobj for decode. |

### Finding categories

| Category | Severity | What it means |
|---|---|---|
| `Macro` | ALERT | VBA project binary present |
| `ActiveX` | ALERT | ActiveX control binary present |
| `AutoExec` | ALERT | VBA auto-execution trigger (AutoOpen, Document_Open etc.) found |
| `ExternalRelationship` | ALERT | Relationship with `TargetMode="External"` — remote resource reference |
| `DDE` | ALERT | Dynamic Data Exchange reference — macro-less payload vector |
| `EquationEditor` | ALERT | CVE-2017-11882 / CVE-2018-0802 exposure |
| `EmbeddedExecutable` | ALERT | PE file (MZ header) embedded, or suspicious extension in OOXML tree |
| `TemplateInjection` | ALERT | `attachedTemplate` with remote URL — phishing pattern |
| `OLEStream` | ALERT/INFO | CFBF stream markers (VBA ALERT; WordDocument/Workbook INFO) |
| `RTFObject` | ALERT/SUSPICIOUS | `\object*` control words in RTF; `\objupdate` is ALERT |
| `EncryptedPackage` | SUSPICIOUS | Password-protected content — body cannot be scanned; escalate with password |
| `SuspiciousKeyword` | SUSPICIOUS | LOLBin / VBA keyword literal in file content |
| `ExternalUrl` | SUSPICIOUS | URL scheme in value attribute or binary content |
| `EmbeddedObject` | SUSPICIOUS | OLE / embedding reference in XML |
| `MacroEnabledContentType` | SUSPICIOUS | Content type declares macro-enabled document |
| `XLMMacro` | SUSPICIOUS | XLM / Excel 4.0 macro indicator (Auto_Open, Macro1, veryHidden) |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — either full analysis completed, or `-StopAfterPhase` gate stopped cleanly |
| `10` | Input file not found, unreadable, or zero bytes |
| `11` | Unrecognized or unsupported file format (magic bytes don't match OOXML/CFBF/RTF) |
| `20` | Unit / processing failure (read error, parse error, etc.) |
| `30` | External dependency missing (reserved) |
| `40` | Output verification failed (copy hash mismatch, empty extraction, JSON write failure) |
| `50` | Retry exhausted — transient failure (e.g., file locked) did not resolve across 3 attempts |
| `99` | Unexpected / unhandled error, OR source mutation detected (immutability contract violated) |

An exit code of 0 does NOT mean the file is clean — it means the analysis
completed. Read the verdict to interpret.

---

## Sample JSON output

```json
{
  "schema_version": "1.0",
  "script": { "name": "Invoke-OfficeDocAnalysis", "version": "2.0.0" },
  "analyzed_at": "2026-04-24T20:40:36.1023847Z",
  "source": {
    "path": "C:\\Cases\\suspect.docx",
    "size": 17488,
    "last_write_utc": "2026-04-21T21:26:28.7737481Z",
    "hashes": {
      "sha256": "150E06DE74B1286617CF2F73BD5CE2EF87A87D7816F52BE3BC532BA357842382",
      "sha1":   "456FB0FBF302C7BC9D830FB879459AECBC2A0FC0",
      "md5":    "EE22C7525BFB02E1CF457F3CA2C07243"
    }
  },
  "format": {
    "detected":          "OOXML",
    "magic_bytes":       "50-4B-03-04",
    "extension":         ".docx",
    "extension_matches": true,
    "ooxml_subtype":     "word",
    "ooxml_macro_enabled": false
  },
  "workspace": "C:\\Users\\analyst\\AppData\\Local\\Temp\\OfficeAnalysis_<guid>",
  "verdict": "CLEAN",
  "counts": { "alert": 0, "suspicious": 0, "info": 0 },
  "findings": [],
  "escalation_recommended": false,
  "escalation_reason": "",
  "record_failures": 0
}
```

---

## Immutability guarantee — the safety contract

**The script never modifies the source file.** This is verified mechanically:

1. SHA-256 of the source is captured at Preflight start
2. Source is copied to `$env:TEMP` — every downstream read operates on the copy
3. At script end (AND at every `-StopAfterPhase` gate stop), the source is
   re-hashed and compared against the Preflight hash
4. On match: log emits `VERIFY_OK: Source file immutability confirmed — SHA-256 unchanged from script start to end (<hash>)`
5. On mismatch: FATAL `SOURCE_MUTATED` + exit 99

### Verify the contract from any run's log

```powershell
# Find the most recent run's log
$log = Get-ChildItem "$env:TEMP\OfficeAnalysis-Reports\*.log" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1

# Look for the immutability confirmation
Select-String -Path $log.FullName -Pattern 'Source file immutability confirmed'
```

If that line is missing from the log, something aborted before the
assertion ran. Do not trust the verdict.

### Independent verification

Compute the source hash yourself before and after:

```powershell
$file = "C:\Cases\suspect.docx"
$before = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
.\Invoke-OfficeDocAnalysis.ps1 -FilePath $file
$after = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
$before -eq $after   # must be True — if False, file a bug report immediately
```

---

## Escalation paths

When the verdict is MALICIOUS (or SUSPICIOUS with concerning findings),
this script hands off to purpose-built decoders:

| Tool | For | Install |
|---|---|---|
| [`olevba`](https://github.com/decalage2/oletools) | VBA decompilation + deobfuscation (CFBF macros, OOXML macroEnabled) | `pip install oletools` |
| [`rtfobj`](https://github.com/decalage2/oletools) | Full OLE extraction from RTF `\objdata` | (part of oletools) |
| [`msoffcrypto-tool`](https://github.com/nolze/msoffcrypto-tool) | Decrypt password-protected Office files | `pip install msoffcrypto-tool` |
| [`XLMMacroDeobfuscator`](https://github.com/DissectMalware/XLMMacroDeobfuscator) | XLM / Excel 4.0 macro decoding | `pip install XLMMacroDeobfuscator` |

When running with `-KeepTempOnAlert`, the preserved workspace path is in
the log — feed it directly to these tools rather than re-copying the
source.

```powershell
# After a MALICIOUS verdict with -KeepTempOnAlert:
# 1. Find the workspace path from the log
Select-String -Path $logPath -Pattern 'Workspace PRESERVED' | Select-Object -ExpandProperty Line

# 2. Extract the vbaProject.bin (OOXML case) and run olevba
olevba "$workspacePath\extracted\word\vbaProject.bin"

# 3. Or for CFBF, run olevba on the source directly
olevba "C:\Cases\suspect.doc"
```

---

## Troubleshooting

### "cannot be loaded because running scripts is disabled"

Execution policy is blocking the script. Either:

```powershell
# Session-scoped (recommended, no system change)
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-OfficeDocAnalysis.ps1 -FilePath ...

# Or for the current session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

### Script flagged or quarantined by EDR

See "EDR considerations" above. The keyword list looks like malware
because it's detecting malware — submit the SHA-256 for allowlist.

### "RETRY_WAIT: Copy-Source to workspace | Attempt 1 failed"

Source file is locked by another process (usually Word or Excel has it
open). Script will retry 3 times with exponential backoff (2s → 4s).
Close the application holding the file and it will succeed on the next
attempt. If retries are exhausted, exit code 50.

### Unexpected verdict — SUSPICIOUS on a file you're sure is benign

Read the findings. Common causes:
- Standard MSI installers contain literal `Shell`, `Decode`, `http://`
  in the UI strings (SUSPICIOUS but not ALERT — typical false positive pattern)
- Macro-enabled templates have macroEnabled content type + VBA binary
  even when macros do nothing hostile
- Legitimate business docs may embed OLE objects (charts, embedded Excel)

If your benign corpus consistently triggers the same SUSPICIOUS pattern,
open an issue with the finding category and a sample — the keyword / OLE
stream list is tunable.

### Script runs but no log/JSON appears

Check `-OutputDir` — the default is `$env:TEMP\OfficeAnalysis-Reports`.
On some locked-down systems `$env:TEMP` may redirect to an unusual path.

```powershell
# Check where logs actually went
[System.IO.Path]::GetTempPath()
Get-ChildItem "$([System.IO.Path]::GetTempPath())OfficeAnalysis-Reports" -ErrorAction SilentlyContinue
```

### Source hash changed between runs but file wasn't modified

AV scanners can update metadata (access time, LastWriteTime) without
changing bytes. The script treats LastWriteTime drift as WARN (not
FATAL) and SHA-256 mismatch as FATAL. A FATAL `SOURCE_MUTATED` message
means the file bytes actually changed — investigate the invoking
process and any concurrent file access.

---

## See also

- Development notes (session-resumption anchor for future contributors):
  [`Invoke-OfficeDocAnalysis.notes.md`](Invoke-OfficeDocAnalysis.notes.md)
- Test fixtures (synthetic samples for verification):
  [`tests/fixtures/`](tests/fixtures/)
- Project-wide security standards:
  [`../SECURITY_AUDIT.md`](../SECURITY_AUDIT.md)
- Institutional knowledge base for this script:
  [`../lessons_learned/phase01_office_doc_v2_rewrite.md`](../lessons_learned/phase01_office_doc_v2_rewrite.md)
