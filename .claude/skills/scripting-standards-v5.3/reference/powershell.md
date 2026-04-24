# PowerShell Scripting Patterns

Reference for Ghost's scripting standards applied to PowerShell.
Load this file when writing or debugging any PowerShell script.

---

## Script Header Template

```powershell
<#
.SYNOPSIS
    Brief one-line description of what this script does.

.DESCRIPTION
    Full description. What problem does it solve? Who runs it? When?

.PARAMETER InputPath
    Description of parameter.

.EXAMPLE
    .\ScriptName.ps1 -InputPath "C:\data\input.csv"

.NOTES
    Author  : Ghost
    Created : 2026-04-11
    Version : 1.0.0
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputPath,

    [string]$LogPath = ".\logs\script-$(Get-Date -Format 'yyyyMMdd-HHmmss').log",

    [ValidateSet("Preflight","Collection","Processing","Output","Verification","None")]
    [string]$StopAfterPhase = "None",

    [switch]$DryRun,

    [switch]$DebugMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
```

---

## Error Code Reference Block

Place this near the top of every script, after params:

```powershell
# ============================================================
# ERROR CODE REFERENCE
# 0  = Success
# 10 = Input file not found
# 11 = Input file unreadable / malformed
# 20 = Unit / processing failure (see log for which one)
# 30 = External service / Entra connection failed or unverified
# 40 = Output verification failed (file missing, empty, or malformed)
# 50 = Retry exhausted — transient failure did not resolve
# 99 = Unexpected / unhandled error
# ============================================================
```

---

## Write-Log Helper

This must be defined before any code that calls it — including Initialization and Phase helpers.

```powershell
#region ============================================================
# HELPER: Write-Log
# Purpose : Write timestamped, leveled log entries to console and file.
#           DEBUG entries always write to file; suppressed from console
#           unless $DebugMode is set.
# Inputs  : -Message (string, mandatory), -Level (DEBUG|INFO|WARN|ERROR|FATAL, default INFO)
# Outputs : None (side effect: writes to $script:LogFile)
# Depends : $script:LogFile, $DebugMode
#endregion ==========================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,
        [Parameter(Position = 1)]
        [ValidateSet("DEBUG","INFO","WARN","ERROR","FATAL")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    # Always write to file
    Add-Content -Path $script:LogFile -Value $entry

    # Suppress DEBUG from console unless DebugMode is active
    if ($Level -eq "DEBUG" -and -not $DebugMode) { return }

    $color = switch ($Level) {
        "DEBUG" { "Gray" }
        "INFO"  { "White" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "FATAL" { "DarkRed" }
    }
    Write-Host $entry -ForegroundColor $color
}
```

---

## Invoke-WithRetry Helper

```powershell
#region ============================================================
# HELPER: Invoke-WithRetry
# Purpose : Execute a script block with exponential backoff retry.
#           Distinguishes transient failures (retry) from fatal ones (stop).
# Inputs  : -ScriptBlock, -OperationName, -MaxAttempts, -DelaySeconds
# Outputs : Return value of ScriptBlock on success; throws on exhaustion
# Depends : Write-Log
#
# IDEMPOTENCY: only use this helper for operations safe to retry —
# reads, stable-ID updates, deletes, or operations with an idempotency
# key. A bare POST /charges, POST /send-email, or POST /webhook is NOT
# safe to retry blindly; a retry that doubles payments or sends duplicate
# emails is worse than no retry at all. See SKILL.md "Idempotency Rule".
#endregion ==========================================================

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$OperationName,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 5
    )
    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            Write-Log -Level DEBUG -Message "RETRY: $OperationName | Attempt $attempt of $MaxAttempts"
            return & $ScriptBlock
        } catch {
            if ($attempt -eq $MaxAttempts) {
                Write-Log -Level ERROR -Message "RETRY_EXHAUSTED: $OperationName | All $MaxAttempts attempts failed | Last error: $($_.Exception.Message)"
                exit 50
            }
            $wait = $DelaySeconds * [Math]::Pow(2, $attempt - 1)
            Write-Log -Level WARN -Message "RETRY_WAIT: $OperationName | Attempt $attempt failed | Waiting ${wait}s | Error: $($_.Exception.Message)"
            Start-Sleep -Seconds $wait
        }
    }
}

# Usage:
# $user = Invoke-WithRetry -OperationName "Get-MgUser" -ScriptBlock { Get-MgUser -UserId $UserId }
```

---

## Invoke-PhaseStart / Invoke-PhaseGate Helpers

```powershell
#region ============================================================
# HELPER: Invoke-PhaseStart
# Purpose : Record phase start time and log phase entry
# Inputs  : -PhaseName (string)
# Outputs : Sets $script:PhaseTimer; logs PHASE_START
# Depends : Write-Log
#endregion ==========================================================

function Invoke-PhaseStart {
    param([Parameter(Mandatory)][string]$PhaseName)
    $script:PhaseTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level INFO -Message "PHASE_START: $PhaseName"
}

#region ============================================================
# HELPER: Invoke-PhaseGate
# Purpose : Log phase duration and stop cleanly if gate matches.
#           Always logs PHASE_END regardless of gate trigger.
#           Exit 0 — a gate stop is not a failure.
# Inputs  : -PhaseName (string), -Summary (string, optional)
# Depends : $StopAfterPhase param, $script:PhaseTimer, $script:ScriptTimer, Write-Log
#endregion ==========================================================

function Invoke-PhaseGate {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [string]$Summary = ""
    )

    $script:PhaseTimer.Stop()
    $phaseDuration = $script:PhaseTimer.Elapsed.TotalSeconds

    if ($Summary) {
        Write-Log -Level INFO -Message "PHASE_SUMMARY: $PhaseName | $Summary"
    }
    Write-Log -Level INFO -Message ("PHASE_END: $PhaseName | Phase Duration: {0:N3}s" -f $phaseDuration)

    if ($StopAfterPhase -eq $PhaseName) {
        $script:ScriptTimer.Stop()
        Write-Log -Level INFO -Message ("PHASE_GATE: Stopping cleanly after phase '$PhaseName' | Total Duration: {0:N3}s" -f $script:ScriptTimer.Elapsed.TotalSeconds)
        exit 0
    }
}
```

---

## Initialization Unit

Log infrastructure bootstrap (creating the log directory and setting `$script:LogFile`) must happen in the Main Block before Phase 1 starts, because `Invoke-PhaseStart` calls `Write-Log`. The `Initialize-Script` function handles everything else: environment snapshot, parameter logging, and mode announcements.

```powershell
#region ============================================================
# UNIT: Initialize-Script
# Purpose : Log environment snapshot, parameter values, and active modes.
#           Log directory creation and $script:LogFile assignment happen
#           in the Main Block bootstrap before Phase 1.
# Inputs  : $InputPath, $StopAfterPhase, $DryRun, $DebugMode (script params)
# Outputs : SCRIPT_START, ENV_SNAPSHOT, PARAMS logged
# Depends : Write-Log, $script:LogFile (set by Main Block bootstrap)
#endregion ==========================================================

function Initialize-Script {
    # Cross-platform user/host: $env:USERNAME and $env:COMPUTERNAME are Windows-only.
    # On Linux/macOS pwsh they're unset, producing empty User/Host fields in logs.
    # Fall back to $env:USER and [System.Net.Dns]::GetHostName() so SCRIPT_START is
    # always populated regardless of where the script runs.
    $userName = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

    Write-Log -Level INFO -Message "SCRIPT_START: $(Split-Path $PSCommandPath -Leaf) | User: $userName | Host: $hostName"
    Write-Log -Level INFO -Message "ENV_SNAPSHOT: ps_version=$($PSVersionTable.PSVersion) | os=$($PSVersionTable.OS) | working_dir=$(Get-Location) | script_path=$PSCommandPath"
    Write-Log -Level INFO -Message "PARAMS: input_path='$InputPath' | stop_after_phase='$StopAfterPhase' | dry_run=$DryRun | debug_mode=$DebugMode"

    if ($DryRun)    { Write-Log -Level WARN -Message "DRY-RUN MODE ACTIVE — no writes, API mutations, or system changes will occur" }
    if ($DebugMode) { Write-Log -Level INFO -Message "DEBUG MODE ACTIVE — DEBUG entries will appear on console" }
}
```

---

## Verify-EntraConnection Unit

```powershell
#region ============================================================
# UNIT: Verify-EntraConnection
# Purpose : Confirm active, correctly-scoped Entra/Graph session
# Inputs  : None (reads current session context)
# Outputs : Logs verified identity; exits 30 on failure
# Depends : Connect-MgGraph must be called before this unit
#endregion ==========================================================

function Verify-EntraConnection {
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level INFO -Message "UNIT_START: Verify-EntraConnection"

    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Log -Level FATAL -Message "VERIFY_FAILED: No active Graph context. Run Connect-MgGraph first."
            exit 30
        }
        Write-Log -Level INFO -Message "VERIFY_OK: Entra | Account: $($context.Account) | Tenant: $($context.TenantId) | Scopes: $($context.Scopes -join ', ')"
    } catch {
        Write-Log -Level FATAL -Message "VERIFY_FAILED: Entra connection check error | $_"
        exit 30
    } finally {
        $unitTimer.Stop()
        Write-Log -Level INFO -Message ("UNIT_END: Verify-EntraConnection | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
}
```

---

## Output Verification Helpers

```powershell
#region ============================================================
# HELPER: Verify-CsvOutput
# Purpose : Confirm a CSV file exists, is non-empty, and has expected rows
# Inputs  : -Path (string), -ExpectedRows (int, optional)
# Outputs : Logs VERIFY_OK or exits 40
# Depends : Write-Log
#endregion ==========================================================

function Verify-CsvOutput {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$ExpectedRows = -1
    )

    if (-not (Test-Path $Path)) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: CSV not found | Path: '$Path'"
        exit 40
    }

    $rows = Import-Csv $Path
    if ($rows.Count -eq 0) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: CSV is empty | Path: '$Path'"
        exit 40
    }

    if ($ExpectedRows -ge 0 -and $rows.Count -ne $ExpectedRows) {
        Write-Log -Level WARN -Message "VERIFY_WARN: Row count mismatch | Expected: $ExpectedRows | Actual: $($rows.Count) | Path: '$Path'"
    } else {
        Write-Log -Level INFO -Message "VERIFY_OK: CSV output | Path: '$Path' | Rows: $($rows.Count)"
    }
}

#region ============================================================
# HELPER: Verify-TextOutput
# Purpose : Confirm a text/log file exists and is non-empty
# Inputs  : -Path (string), -MinSizeBytes (int, optional)
# Outputs : Logs VERIFY_OK or exits 40
# Depends : Write-Log
#endregion ==========================================================

function Verify-TextOutput {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MinSizeBytes = 1
    )

    if (-not (Test-Path $Path)) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: File not found | Path: '$Path'"
        exit 40
    }

    $size = (Get-Item $Path).Length
    if ($size -lt $MinSizeBytes) {
        Write-Log -Level ERROR -Message "VERIFY_FAILED: File too small | Path: '$Path' | Size: ${size}B | Minimum: ${MinSizeBytes}B"
        exit 40
    }

    Write-Log -Level INFO -Message "VERIFY_OK: File output | Path: '$Path' | Size: ${size}B"
}
```

---

## Unit Timer / Exception Capture Pattern

Every catch block must record the error message, the unit name, the input values in scope, the line reference, and the exit code. Stack traces go at DEBUG level — always in the file, console-visible only in debug mode.

```powershell
$unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
Write-Log -Level INFO -Message "UNIT_START: UnitName | Input: $InputValue"

try {
    # ... unit logic ...
} catch {
    Write-Log -Level ERROR -Message "UNIT_FAILED: UnitName | Error: $($_.Exception.Message) | Input: $InputValue | Line: $($_.InvocationInfo.ScriptLineNumber) | ExitCode: 20"
    Write-Log -Level DEBUG -Message "STACK_TRACE: $($_.ScriptStackTrace)"
    exit 20
} finally {
    $unitTimer.Stop()
    Write-Log -Level INFO -Message ("UNIT_END: UnitName | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
}
```

---

## Record-Level Error Logging Pattern

Log the specific record identity at the point of failure. For fault-tolerant units that should process all records and report at the end:

```powershell
# Stop-on-first-failure:
foreach ($record in $records) {
    try {
        Process-SingleRecord -Record $record
    } catch {
        Write-Log -Level ERROR -Message "RECORD_FAILED: Process-Records | RecordId=$($record.Id) | RecordName='$($record.DisplayName)' | Error: $($_.Exception.Message)"
        Write-Log -Level DEBUG -Message "STACK_TRACE: $($_.ScriptStackTrace)"
        exit 20
    }
}

# Fault-tolerant — collect all failures, report at end:
$failures = @()
foreach ($record in $records) {
    try { Process-SingleRecord -Record $record }
    catch { $failures += "RecordId=$($record.Id) | Error: $($_.Exception.Message)" }
}
if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Log -Level ERROR -Message "RECORD_FAILED: $_" }
    Write-Log -Level ERROR -Message "UNIT_FAILED: Process-Records | $($failures.Count) of $($records.Count) records failed"
    exit 20
}
```

---

## Partial Success Evaluation Pattern

Use at the end of any fault-tolerant processing unit to classify the outcome explicitly. The failure threshold is defined in the script's configuration block.

```powershell
# Configuration block:
[int]$FailureThresholdPct = 10   # >10% failures = treat as full failure

# At the end of the processing unit:
$failPct = [math]::Round(($failures.Count / $records.Count) * 100, 1)

if ($failures.Count -eq 0) {
    Write-Log -Level INFO -Message "FULL_SUCCESS: Process-Records | $($records.Count) of $($records.Count) records processed"
} elseif ($failPct -le $FailureThresholdPct) {
    Write-Log -Level WARN -Message "PARTIAL_SUCCESS: Process-Records | $($records.Count - $failures.Count) of $($records.Count) succeeded | $($failures.Count) failed ($failPct%) | Threshold: $FailureThresholdPct%"
} else {
    Write-Log -Level ERROR -Message "FAILURE: Process-Records | $($failures.Count) of $($records.Count) failed ($failPct%) | Threshold exceeded: $FailureThresholdPct%"
    exit 20
}
```

---

## Dry-Run Pattern

```powershell
# In any unit with side effects:
if ($DryRun) {
    Write-Log -Level INFO -Message "[DRY-RUN] Would export $($records.Count) records to '$OutputPath'"
} else {
    $records | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Log -Level INFO -Message "Exported $($records.Count) records to '$OutputPath'"
}
```

---

## Dependency Documentation Pattern

When Unit B depends on Unit A completing successfully:

```powershell
#region ============================================================
# UNIT: Process-Records
# Purpose : Transform validated records into output format
# Inputs  : $ValidatedRecords (array) — produced by Validate-InputFiles
# Outputs : $ProcessedRecords (array)
# Depends : Validate-InputFiles (MUST run first; will exit 20 if missing)
#endregion ==========================================================

if (-not $ValidatedRecords) {
    Write-Log -Level FATAL -Message "DEPENDENCY_MISSING: Process-Records requires ValidatedRecords. Was Validate-InputFiles skipped?"
    exit 20
}
```

---

## CONTRACT Block for Cross-File Units

When a unit is called from another file — not just a local helper — wrap its unit header with a `<CONTRACT>` block. The block declares the formal integration contract in a grep-stable form so consumers can be enumerated mechanically. See `reference/integration-tracking.md` for the full Format Contract and Change Impact Protocol.

Field keys use **PascalCase** in PowerShell CONTRACT blocks, matching PowerShell's native parameter naming convention. This deviates from the log format contract's `lowercase_snake_case` rule — contracts are read by humans writing PowerShell, and matching the language's convention wins over cross-language uniformity for this specific case.

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

Consumers that read specific fields off the return value add a `<USES>` marker immediately above the call site:

```powershell
# <USES contract="Get-UserToken" version="1" fields="Token,ExpiresAt">
$auth = Get-UserToken -UserId $u -Scope @('read')
if ((Get-Date) -lt $auth.ExpiresAt) {
    $headers['Authorization'] = "Bearer $($auth.Token)"
}
```

The `<USES>` marker is mandatory for consumers of `public` contracts that read specific fields; optional but recommended elsewhere. Return-shape changes to `public` contracts are traced through these markers, not by grepping for property-access patterns.

---

## Main Block Pattern

The Main Block brings everything together. Log infrastructure bootstrap (creating the log directory and setting `$script:LogFile`) runs first — before Phase 1 — because `Invoke-PhaseStart` needs `Write-Log` to work. Everything after that follows the phased deployment model.

```powershell
#region ============================================================
# MAIN
# Purpose : Bootstrap log infrastructure, then orchestrate all phases
#endregion ==========================================================

# --- Log infrastructure bootstrap ---
# Must happen before any log call. Script-level announcements
# (SCRIPT_START, ENV_SNAPSHOT, PARAMS) must also happen before
# Phase 1 — the log's first line should identify the script, not
# a phase. Call Initialize-Script BEFORE Invoke-PhaseStart, so that
# cross-language triage tools (which grep for SCRIPT_START as the
# top-of-log marker) see the expected ordering: SCRIPT_START first,
# PHASE_START second. Invoke-PhaseStart called before Initialize-Script
# inverts this and breaks the convention every other language follows.
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}
$script:LogFile = $LogPath
$script:ScriptTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Script-level announcements BEFORE any phase starts.
Initialize-Script

try {
    # ================================================================
    # PHASE 1: PREFLIGHT
    # ================================================================
    Invoke-PhaseStart -PhaseName "Preflight"
    Verify-EntraConnection
    Validate-InputFiles -Path $InputPath
    Invoke-PhaseGate -PhaseName "Preflight" -Summary "Connection: verified | Input: $InputPath"

    # ================================================================
    # PHASE 2: COLLECTION
    # ================================================================
    Invoke-PhaseStart -PhaseName "Collection"
    $records = Get-InputRecords -Path $InputPath
    Invoke-PhaseGate -PhaseName "Collection" -Summary "Records retrieved: $($records.Count)"

    # ================================================================
    # PHASE 3: PROCESSING
    # ================================================================
    Invoke-PhaseStart -PhaseName "Processing"
    $processed = Process-Records -Records $records
    Invoke-PhaseGate -PhaseName "Processing" -Summary "Records processed: $($processed.Count)"

    # ================================================================
    # PHASE 4: OUTPUT
    # ================================================================
    Invoke-PhaseStart -PhaseName "Output"
    Export-Results -Data $processed
    Verify-CsvOutput -Path $OutputPath -ExpectedRows $processed.Count
    Invoke-PhaseGate -PhaseName "Output" -Summary "Output: $OutputPath"

    $script:ScriptTimer.Stop()
    Write-Log -Level INFO -Message ("SCRIPT_COMPLETE: Success | Total Duration: {0:N3}s" -f $script:ScriptTimer.Elapsed.TotalSeconds)
    exit 0

} catch {
    $script:ScriptTimer.Stop()
    Write-Log -Level FATAL -Message ("SCRIPT_FAILED: Unhandled error | {0} | Total Duration: {1:N3}s" -f $_.Exception.Message, $script:ScriptTimer.Elapsed.TotalSeconds)
    Write-Log -Level DEBUG -Message "STACK_TRACE: $($_.ScriptStackTrace)"
    exit 99
}
```

---

## Verification History

Bugs caught by running the patterns in this file end-to-end under `pwsh` on Linux, not just reviewing them.

### Minimal scaffold — Windows-only environment variables

**Caught when:** the minimal scaffold was executed under `pwsh` on Kali Linux.

**The bug:** `$env:USERNAME` and `$env:COMPUTERNAME` are Windows-specific. On Linux and macOS `pwsh`, both variables are unset. The scaffold's `SCRIPT_START` line rendered as `User:  | Host: ` with empty fields — no error, no warning, just silently wrong log output.

**The fix:** Fallback to POSIX-standard alternatives at the top of the main block:

```powershell
$UserName = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
$HostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
```

`$env:USER` is set on POSIX platforms; `[System.Net.Dns]::GetHostName()` works across all .NET platforms. The `if ... else` cascade uses the Windows variable when present and falls back only when unset.

**Lesson encoded in the file:** Both the minimal scaffold in `minimal_scripts.md` and the full template in this file use the fallback pattern. A future edit that assumes Windows is a single-platform trap.

**Generalizable rule:** When writing PowerShell that targets any environment other than a Windows workstation, assume any `$env:*` variable starting with uppercase may be Windows-only and verify with a cross-platform fallback.

### Full phased template — `Initialize-Script` called after `Invoke-PhaseStart`

**Caught when:** reading the resulting log file from a full-template run.

**The bug:** The Main Block originally called `Invoke-PhaseStart -PhaseName "Preflight"` as the first operation, then called `Initialize-Script` inside Phase 1. This meant the log file started with:

```
[INFO] PHASE_START: Preflight
[INFO] SCRIPT_START: script.ps1 | User: ... | Host: ...
[INFO] ENV_SNAPSHOT: ...
[INFO] PARAMS: ...
```

Cross-language triage tools that grep for `SCRIPT_START` as the first line of a log file expected it at log-start, not three lines in. Python and Bash templates both place the `SCRIPT_START` / env snapshot before any `PHASE_START`; PowerShell inverted the convention.

**The fix:** Run log infrastructure bootstrap and `Initialize-Script` **before** Phase 1 starts. The Main Block now bootstraps the log file, timer, and script-level announcements (SCRIPT_START, ENV_SNAPSHOT, PARAMS) first, then enters Phase 1 with `Invoke-PhaseStart`.

**Lesson encoded in the file:** The Main Block in this file carries an inline comment at the bootstrap site explaining the required ordering and why it is non-optional. The comment prevents a future editor from "simplifying" the bootstrap into the first phase.

**Generalizable rule:** Script-level announcements (SCRIPT_START, ENV_SNAPSHOT, PARAMS) always appear at log-top, before any PHASE_START. Cross-language triage assumes this ordering; breaking it silently breaks the tooling.

### Full phased template — `$_` in the SCRIPT_FAILED catch

**Caught when:** format-contract audit comparing unit-level `UNIT_FAILED` output to script-level `SCRIPT_FAILED` output.

**The bug:** The script-level catch logged `$_` directly, which stringifies to the full `ErrorRecord` — verbose position/pipeline ceremony that made `SCRIPT_FAILED` lines noisy. The unit-level catch correctly used `$_.Exception.Message`. Two patterns for the same concept, with the script-level one producing uglier output.

**The fix:** Change the `SCRIPT_FAILED` log to `$($_.Exception.Message)`, matching the unit-level pattern.

**Lesson encoded in the file:** Both unit-level and script-level catches in this file now use `$_.Exception.Message` for the user-visible error text. `$_.ScriptStackTrace` is still used separately in the DEBUG-level `STACK_TRACE` line where the full record is appropriate.
