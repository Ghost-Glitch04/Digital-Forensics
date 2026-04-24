#Requires -Version 5.1
<#
.SYNOPSIS
    Office Document Forensic Analysis - Static, Read-Only Multi-Format Inspector

.DESCRIPTION
    Performs static (non-executing) forensic analysis of Microsoft Office
    documents and adjacent formats to help triage EDR false positives.

    Supported formats (routed by magic bytes, not extension):
      * OOXML  - .docx, .xlsx, .pptx, .xml and macro-enabled variants
      * CFBF   - legacy binary .doc, .xls, .ppt (incl. XLM/Excel 4.0 macros)
      * RTF    - .rtf and renamed .doc covers; detects Equation Editor and
                 embedded executables in \objdata blobs

    Safety contract (invariant):
      The script NEVER writes to, locks, or mutates the source file. The
      source is copied once to $env:TEMP\OfficeAnalysis_<guid>\ under
      SHA-256 re-verification; every downstream read operates on the copy.
      At script end, the source is re-hashed and compared against the
      hash captured at the start - a mismatch is FATAL and indicates the
      script's contract was violated (external interference).

    Outputs:
      * Timestamped log file (always)
      * Structured JSON findings report (default; toggle with -OutputFormat)
      * Colored console report (default; toggle with -OutputFormat)

.PARAMETER FilePath
    Full path to the Office document to analyze. The file is NEVER modified.

.PARAMETER OutputDir
    Directory for the log file and findings JSON.
    Default: $env:TEMP\OfficeAnalysis-Reports

.PARAMETER StopAfterPhase
    Stop cleanly at the end of a named phase (exit 0) for inspection:
    Preflight | Extraction | Analysis | Report

.PARAMETER OutputFormat
    Which outputs to produce: Console | Json | Both (default: Both)

.PARAMETER KeepTempOnAlert
    When verdict = MALICIOUS, preserve the temp workspace for analyst
    follow-up (e.g. running olevba against the extracted vbaProject.bin).
    Path is logged prominently.

.PARAMETER DryRun
    Run preflight, extraction, and analysis, but skip writing the JSON
    findings file. Log file is still written (it is the operational record).

.PARAMETER DebugMode
    Promote DEBUG entries to console output. Log file always receives DEBUG.

.EXAMPLE
    .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.doc"

    Run a full analysis with default output (console + JSON in $env:TEMP).

.EXAMPLE
    .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docm" -KeepTempOnAlert

    Full analysis; if the verdict is MALICIOUS, the temp workspace
    containing extracted vbaProject.bin etc. is preserved for escalation.

.EXAMPLE
    .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\file.xlsx" -StopAfterPhase Extraction -DebugMode

    Stop after extraction for manual inspection of the temp workspace.

.NOTES
    Author  : Ghost-Glitch04
    Version : 2.0.1
    Date    : 2026-04-24

    Changelog:
      2.0.1 - ASCII-hardened source (removed all non-ASCII characters
              from comments and log strings). Script is now parse-safe
              on PowerShell 5.1 even when copies lose the UTF-8 BOM.
              Previously, 50+ em-dashes required BOM preservation
              through every copy operation; a single BOM-stripping
              editor or tool broke PS 5.1 parsing.
      2.0.0 - Full rewrite from v1 to scripting-standards-v5.3 template.
              Added RTF format path, template-injection detection, XLM
              macros, encrypted-package detection, retry wrapper on
              source reads, source-immutability SHA-256 round-trip
              assertion in log.

    Exit codes:
        0  = Success / clean phase-gate stop
        10 = Input file not found, unreadable, or zero bytes
        11 = Unrecognized or unsupported file format (magic bytes)
        20 = Unit / processing failure
        30 = External dependency missing (reserved)
        40 = Output verification failed (copy hash mismatch, empty extraction,
             missing JSON report, source mutation detected)
        50 = Retry exhausted
        99 = Unexpected / unhandled error (incl. source-mutation-during-run)

    Companion file: Invoke-OfficeDocAnalysis.notes.md holds the Development
    Notes block (session-resumption anchor per scripting-standards-v5.3).

    Standards compliance: scripting-standards-v5.3 (PowerShell phased template).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$FilePath,

    [string]$OutputDir = (Join-Path $env:TEMP 'OfficeAnalysis-Reports'),

    [ValidateSet('Preflight','Extraction','Analysis','Report','None')]
    [string]$StopAfterPhase = 'None',

    [ValidateSet('Console','Json','Both')]
    [string]$OutputFormat = 'Both',

    [switch]$KeepTempOnAlert,
    [switch]$DryRun,
    [switch]$DebugMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# ERROR CODE REFERENCE
#   0  = Success / clean gate stop
#   10 = Input file not found / unreadable / zero bytes
#   11 = Unrecognized or unsupported file format (magic bytes)
#   20 = Unit / processing failure
#   30 = External dependency missing
#   40 = Output verification failed (includes copy hash mismatch and
#        source-mutation-detected)
#   50 = Retry exhausted
#   99 = Unexpected / unhandled error
# ============================================================

# ============================================================
# CONFIGURATION
# ============================================================
$Script:Version       = '2.0.1'
$Script:ScriptName    = 'Invoke-OfficeDocAnalysis'
$Script:LogFile       = $null   # set in Main bootstrap
$Script:WorkingDir    = $null   # set by New-Workspace unit
$Script:WorkingPath   = $null   # path to the copy; all analysis reads this
$Script:ScriptTimer   = $null
$Script:PhaseTimer    = $null
$Script:Findings      = $null   # List[hashtable], initialized in Analysis
$Script:SourceHashSha256Start = $null   # captured in Preflight, re-checked at script end
$Script:SourceLastWriteStart  = $null

# Suspicious keyword list - VBA patterns, LOLBins, encoding APIs.
# Kept conservative: each entry is a legitimate red flag in an Office doc.
#
# URL schemes (http://, https://, ftp://) are NOT in this list. Every clean
# OOXML file contains xmlns="http://schemas.openxmlformats.org/..." in its
# namespace declarations, which would produce a SUSPICIOUS hit in every
# XML part of every benign document. URLs are handled separately by the
# OOXML path via Target=/src= attribute matching inside .rels files only.
$Script:SuspiciousKeywords = @(
    'AutoOpen','AutoExec','AutoClose','Document_Open','Workbook_Open','Auto_Open','Auto_Close','DocumentOpen',
    'Shell','WScript','CreateObject','GetObject',
    'PowerShell','cmd.exe','mshta','wscript','cscript','regsvr32',
    'certutil','bitsadmin','rundll32','msiexec',
    'Chr(','Asc(','Environ(','Execute(','Eval(',
    'Base64','FromBase64','Decode',
    'ADODB.Stream','Scripting.FileSystemObject','Shell.Application',
    'WScript.Shell','InternetExplorer.Application'
)

# URL scheme patterns - scanned with attribute context for OOXML (Target=,
# src=) and plainly for CFBF/RTF (where structural context is absent).
$Script:UrlSchemes = @('http://','https://','ftp://','file://')

$Script:SuspiciousExtensions = @('.exe','.dll','.ps1','.bat','.cmd','.scr','.vbs','.js','.hta','.msi')

# Magic byte signatures -> format name. 4-byte sigs for OOXML/CFBF; RTF needs 5.
$Script:MagicBytes = @{
    '50-4B-03-04'          = 'OOXML'   # ZIP-based
    'D0-CF-11-E0'          = 'CFBF'    # Compound Binary
    '7B-5C-72-74-66-31'    = 'RTF'     # {\rtf1  (6-byte check for specificity)
}

# Auto-execution trigger names - CFBF path. Scanned as UTF-16LE AND ASCII
# bytes because VBA module names are stored UTF-16LE in CFBF streams, but
# XLM 4.0 macro names and some legacy embeds use ANSI/ASCII.
$Script:AutoExecTriggers = @(
    'AutoOpen','AutoExec','AutoClose','Document_Open',
    'Workbook_Open','Auto_Open','Auto_Close','DocumentOpen'
)

# Encrypted-package stream names - password-protected OOXML is wrapped in a
# CFBF container with an EncryptedPackage stream; legacy CFBF (.doc/.xls)
# password protection uses the same or similar stream names. Presence means
# content analysis is not possible without the password - verdict floor is
# SUSPICIOUS and scan short-circuits with an escalation note.
$Script:EncryptedStreamNames = @('EncryptedPackage','EncryptionInfo','DataSpaces')

# ============================================================
# HELPERS
# ============================================================

#region ============================================================
# HELPER: Write-Log
# Purpose : Timestamped, leveled log entries to file (always) and console
#           (DEBUG gated on -DebugMode). Format matches scripting-standards.
# Inputs  : -Message (mandatory), -Level (default INFO)
# Outputs : None (writes to $Script:LogFile)
# Depends : $Script:LogFile, $DebugMode
#endregion ==========================================================
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,
        [Parameter(Position = 1)]
        [ValidateSet('DEBUG','INFO','WARN','ERROR','FATAL')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"

    if ($Script:LogFile) {
        Add-Content -Path $Script:LogFile -Value $entry -Encoding UTF8
    }

    if ($Level -eq 'DEBUG' -and -not $DebugMode) { return }

    $color = switch ($Level) {
        'DEBUG' { 'DarkGray' }
        'INFO'  { 'Cyan' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'FATAL' { 'Magenta' }
    }
    Write-Host $entry -ForegroundColor $color
}

#region ============================================================
# HELPER: Invoke-WithRetry
# Purpose : Execute a script block with exponential backoff retry.
#           Distinguishes transient failures (retry) from fatal ones (stop).
# Inputs  : -ScriptBlock, -OperationName, -MaxAttempts, -DelaySeconds
# Outputs : Return value of ScriptBlock on success; exits 50 on exhaustion.
# Depends : Write-Log
#
# IDEMPOTENCY: only safe for operations that produce identical outcomes
# on retry - reads, stable-path file copies, deletes, operations with
# idempotency keys. DO NOT wrap POST-style side-effecting calls.
# Source: scripting-standards-v5.3 reference/powershell.md "Invoke-WithRetry".
#endregion ==========================================================
function Invoke-WithRetry {
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory)][string]$OperationName,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2
    )
    $attempt = 0
    while ($attempt -lt $MaxAttempts) {
        $attempt++
        try {
            Write-Log "RETRY: $OperationName | Attempt $attempt of $MaxAttempts" 'DEBUG'
            return & $ScriptBlock
        } catch {
            if ($attempt -eq $MaxAttempts) {
                Write-Log "RETRY_EXHAUSTED: $OperationName | All $MaxAttempts attempts failed | Last error: $($_.Exception.Message) | ExitCode=50" 'ERROR'
                Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
                exit 50
            }
            $wait = $DelaySeconds * [Math]::Pow(2, $attempt - 1)
            Write-Log "RETRY_WAIT: $OperationName | Attempt $attempt failed | Waiting ${wait}s | Error: $($_.Exception.Message)" 'WARN'
            Start-Sleep -Seconds $wait
        }
    }
}

#region ============================================================
# HELPER: Invoke-PhaseStart / Invoke-PhaseGate
# Purpose : Phase lifecycle with duration logging. Gate stops cleanly
#           (exit 0) when $StopAfterPhase matches.
# Depends : Write-Log, $Script:PhaseTimer, $Script:ScriptTimer, $StopAfterPhase
#endregion ==========================================================
function Invoke-PhaseStart {
    param([Parameter(Mandatory)][string]$PhaseName)
    $Script:PhaseTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "PHASE_START: $PhaseName"
}

function Invoke-PhaseGate {
    param(
        [Parameter(Mandatory)][string]$PhaseName,
        [string]$Summary = ''
    )
    $Script:PhaseTimer.Stop()
    $phaseSec = $Script:PhaseTimer.Elapsed.TotalSeconds

    if ($Summary) { Write-Log "PHASE_SUMMARY: $PhaseName | $Summary" }
    Write-Log ("PHASE_END: $PhaseName | Phase Duration: {0:N3}s" -f $phaseSec)

    if ($StopAfterPhase -eq $PhaseName) {
        $Script:ScriptTimer.Stop()
        Write-Log ("PHASE_GATE: Stopping cleanly after phase '$PhaseName' | Total Duration: {0:N3}s" -f $Script:ScriptTimer.Elapsed.TotalSeconds)
        # Final safety check even on gate stop - the immutability contract applies
        Assert-SourceUnchanged
        exit 0
    }
}

#region ============================================================
# HELPER: Initialize-Script
# Purpose : Emit SCRIPT_START, ENV_SNAPSHOT, PARAMS. Must run AFTER log
#           file is set but BEFORE Phase 1. Order is load-bearing.
#endregion ==========================================================
function Initialize-Script {
    $userName = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
    $hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

    Write-Log "SCRIPT_START: $Script:ScriptName v$Script:Version | User: $userName | Host: $hostName"
    Write-Log "ENV_SNAPSHOT: ps_version=$($PSVersionTable.PSVersion) | os=$([System.Environment]::OSVersion.VersionString) | working_dir=$(Get-Location) | script_path=$PSCommandPath"
    Write-Log "PARAMS: file_path='$FilePath' | output_dir='$OutputDir' | stop_after_phase='$StopAfterPhase' | output_format='$OutputFormat' | keep_temp_on_alert=$KeepTempOnAlert | dry_run=$DryRun | debug_mode=$DebugMode"

    if ($DryRun)    { Write-Log 'DRY-RUN MODE ACTIVE - findings JSON will not be written' 'WARN' }
    if ($DebugMode) { Write-Log 'DEBUG MODE ACTIVE - DEBUG entries appear on console' }
}

#region ============================================================
# HELPER: Add-Finding
# Purpose : Record a forensic finding. Called from any analysis unit.
# Inputs  : -Severity (ALERT|SUSPICIOUS|INFO), -Category, -Detail, -Location
# Outputs : Appends to $Script:Findings, emits log entry at matched level
# Depends : $Script:Findings (initialized at Analysis phase start), Write-Log
#endregion ==========================================================
function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('ALERT','SUSPICIOUS','INFO')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Location = ''
    )
    $Script:Findings.Add([ordered]@{
        Severity = $Severity
        Category = $Category
        Detail   = $Detail
        Location = $Location
    }) | Out-Null

    $logLevel = switch ($Severity) {
        'ALERT'      { 'ERROR' }
        'SUSPICIOUS' { 'WARN' }
        default      { 'INFO' }
    }
    $locSuffix = if ($Location) { " | Location: $Location" } else { '' }
    Write-Log "[$Severity] [$Category] $Detail$locSuffix" $logLevel
}

#region ============================================================
# HELPER: New-TempWorkspace
# Purpose : Create a unique per-run working directory in $env:TEMP.
#           GUID-based name avoids Get-Random collision risk.
# Outputs : Returns path to created directory
#endregion ==========================================================
function New-TempWorkspace {
    $path = Join-Path $env:TEMP ("OfficeAnalysis_{0}" -f ([guid]::NewGuid()))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

#region ============================================================
# HELPER: Copy-SourceSafely
# Purpose : Copy source file to workspace and verify SHA-256 integrity.
#           The copy is what every downstream unit reads. If the hash
#           mismatches, the copy failed silently - exit 40 rather than
#           proceed on a potentially-mangled sample.
# Inputs  : -Source (string path), -Workspace (directory), -SourceHash (SHA-256)
# Outputs : Returns full path to the copy
#endregion ==========================================================
function Copy-SourceSafely {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Workspace,
        [Parameter(Mandatory)][string]$SourceHash
    )
    $sourceItem = Get-Item -LiteralPath $Source
    $destPath = Join-Path $Workspace ("source{0}" -f $sourceItem.Extension)

    # Wrap copy in retry - transient lock from Word/Excel still open on the
    # flagged file is the common case. Safe to retry: copy produces byte-
    # identical output at $destPath on every successful attempt; partial
    # state from an interrupted attempt is overwritten by the next (-Force).
    # Hash verification below catches any mid-retry corruption.
    Invoke-WithRetry -OperationName "Copy-Source to workspace" -MaxAttempts 3 -DelaySeconds 2 -ScriptBlock {
        Copy-Item -LiteralPath $Source -Destination $destPath -Force -ErrorAction Stop
    } | Out-Null
    $copyHash = (Get-FileHash -LiteralPath $destPath -Algorithm SHA256).Hash

    if ($copyHash -ne $SourceHash) {
        Write-Log "VERIFY_FAILED: Copy hash mismatch | source=$SourceHash | copy=$copyHash | ExitCode=40" 'ERROR'
        exit 40
    }
    Write-Log "VERIFY_OK: Source copied to workspace | SHA-256 preserved ($SourceHash)"
    return $destPath
}

#region ============================================================
# HELPER: Find-BytePattern
# Purpose : Locate the first occurrence of a byte-sequence needle inside
#           a byte-array haystack. Uses [Array]::IndexOf to jump to
#           candidate first-byte positions, then verifies remaining bytes
#           in a tight PS loop. ~68x faster than a pure-PS scan on 5MB
#           buffers - proven on 2026-04-24 during rewrite verification.
#
#           Sufficient for files into the hundreds of MB. CFBF Office
#           files are typically under 10MB; MSIs sometimes exceed 100MB.
#
# Inputs  : -Haystack ([byte[]]), -Needle ([byte[]])
# Outputs : Integer offset of first match, or -1 if not found
#endregion ==========================================================
function Find-BytePattern {
    param(
        [Parameter(Mandatory)][byte[]]$Haystack,
        [Parameter(Mandatory)][byte[]]$Needle
    )
    if ($Needle.Length -eq 0) { return -1 }
    if ($Haystack.Length -lt $Needle.Length) { return -1 }

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

#region ============================================================
# HELPER: Assert-SourceUnchanged
# Purpose : Re-hash the ORIGINAL source file and compare against the
#           hash captured at script start. This proves the immutability
#           contract from the log. Called at script end AND at gate stops.
# Exits   : 99 on mismatch (FATAL - script's contract has been violated).
#           LastWriteTime drift alone is WARN, not FATAL (AV scans etc.
#           may touch the timestamp without altering bytes).
#endregion ==========================================================
function Assert-SourceUnchanged {
    if (-not $Script:SourceHashSha256Start) { return }   # too early to check
    try {
        $hashNow = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash
        if ($hashNow -ne $Script:SourceHashSha256Start) {
            Write-Log "SOURCE_MUTATED: SHA-256 mismatch | start=$Script:SourceHashSha256Start | end=$hashNow | ExitCode=99" 'FATAL'
            exit 99
        }
        Write-Log "VERIFY_OK: Source file immutability confirmed - SHA-256 unchanged from script start to end ($hashNow)"

        $writeNow = (Get-Item -LiteralPath $FilePath).LastWriteTimeUtc
        if ($writeNow -ne $Script:SourceLastWriteStart) {
            Write-Log "VERIFY_WARN: Source LastWriteTime changed (bytes unchanged). Start=$($Script:SourceLastWriteStart.ToString('o')) | End=$($writeNow.ToString('o')). AV metadata touch is typical." 'WARN'
        }
    }
    catch {
        Write-Log "VERIFY_WARN: Could not re-hash source for immutability check: $($_.Exception.Message)" 'WARN'
    }
}

# ============================================================
# PHASE 1: PREFLIGHT
# ============================================================
function Invoke-Preflight {

    #region UNIT: Validate-InputFile --------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "UNIT_START: Validate-InputFile | Path='$FilePath'"
    try {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            Write-Log "UNIT_FAILED: Validate-InputFile | File not found: '$FilePath' | ExitCode=10" 'FATAL'
            exit 10
        }
        $Script:SourceFileItem = Get-Item -LiteralPath $FilePath
        if ($Script:SourceFileItem.Length -eq 0) {
            Write-Log "UNIT_FAILED: Validate-InputFile | File is zero bytes | ExitCode=10" 'FATAL'
            exit 10
        }
        $Script:SourceLastWriteStart = $Script:SourceFileItem.LastWriteTimeUtc
        Write-Log "VERIFY_OK: File exists | Size=$($Script:SourceFileItem.Length)B | LastWriteUtc=$($Script:SourceLastWriteStart.ToString('o')) | Created=$($Script:SourceFileItem.CreationTimeUtc.ToString('o'))"
        Write-Log ("UNIT_END: Validate-InputFile | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Validate-InputFile | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=10" 'FATAL'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 10
    }

    #region UNIT: Compute-SourceHashes ------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Compute-SourceHashes'
    try {
        # Wrap in retry: source file may be transiently locked (open in Word
        # etc.). Hashing is pure-read and idempotent - safe to retry.
        $Script:Hashes = Invoke-WithRetry -OperationName "Compute source hashes" -MaxAttempts 3 -DelaySeconds 2 -ScriptBlock {
            @{
                SHA256 = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
                SHA1   = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA1   -ErrorAction Stop).Hash
                MD5    = (Get-FileHash -LiteralPath $FilePath -Algorithm MD5    -ErrorAction Stop).Hash
            }
        }
        $Script:SourceHashSha256Start = $Script:Hashes.SHA256
        Write-Log "SHA256: $($Script:Hashes.SHA256)"
        Write-Log "SHA1  : $($Script:Hashes.SHA1)"
        Write-Log "MD5   : $($Script:Hashes.MD5)"
        Write-Log 'VERIFY_OK: All three hashes computed against source'
        Write-Log ("UNIT_END: Compute-SourceHashes | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Compute-SourceHashes | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: New-Workspace -------------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: New-Workspace'
    try {
        $Script:WorkingDir = New-TempWorkspace
        Write-Log "VERIFY_OK: Workspace created | Path='$Script:WorkingDir'"
        Write-Log ("UNIT_END: New-Workspace | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: New-Workspace | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Copy-SourceSafely (via helper) --------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Copy-SourceSafely'
    try {
        $Script:WorkingPath = Copy-SourceSafely -Source $FilePath -Workspace $Script:WorkingDir -SourceHash $Script:Hashes.SHA256
        Write-Log "Working copy: '$Script:WorkingPath'"
        Write-Log ("UNIT_END: Copy-SourceSafely | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Copy-SourceSafely | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Detect-FileFormat ---------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Detect-FileFormat'
    try {
        $firstBytes = [System.IO.File]::ReadAllBytes($Script:WorkingPath) | Select-Object -First 8
        $sig4 = [System.BitConverter]::ToString($firstBytes[0..3])
        $sig6 = [System.BitConverter]::ToString($firstBytes[0..5])
        $Script:FileExtension = $Script:SourceFileItem.Extension.ToLower()

        Write-Log "Magic bytes (first 4): $sig4 | (first 6): $sig6 | Extension: $Script:FileExtension"

        $Script:FileFormat = $null
        if ($Script:MagicBytes.ContainsKey($sig6))      { $Script:FileFormat = $Script:MagicBytes[$sig6]; $Script:HexSignature = $sig6 }
        elseif ($Script:MagicBytes.ContainsKey($sig4))  { $Script:FileFormat = $Script:MagicBytes[$sig4]; $Script:HexSignature = $sig4 }

        if (-not $Script:FileFormat) {
            Write-Log "UNIT_FAILED: Detect-FileFormat | Unrecognized magic bytes: '$sig4' / '$sig6' - not a supported Office format | ExitCode=11" 'FATAL'
            exit 11
        }
        Write-Log "VERIFY_OK: Format detected as '$Script:FileFormat' | Signature='$Script:HexSignature'"

        $expectedExtensions = @{
            OOXML = @('.docx','.xlsx','.pptx','.xml','.xlsm','.docm','.pptm','.dotx','.dotm','.xltx','.xltm','.potx','.potm','.zip')
            CFBF  = @('.doc','.xls','.ppt','.dot','.xlt','.pot','.msi','.msg')
            RTF   = @('.rtf','.doc')   # .doc RTF covers are a classic spoof - analyst should be alerted elsewhere
        }
        if ($Script:FileExtension -notin $expectedExtensions[$Script:FileFormat]) {
            Write-Log "VERIFY_WARN: Extension '$Script:FileExtension' does not match detected format '$Script:FileFormat' - possible extension spoofing" 'WARN'
        }
        Write-Log ("UNIT_END: Detect-FileFormat | Format='$Script:FileFormat' | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Detect-FileFormat | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Classify-OOXMLSubtype (OOXML only) ----------------
    if ($Script:FileFormat -eq 'OOXML') {
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Classify-OOXMLSubtype'
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            $Script:OOXMLSubtype = 'unknown'
            $Script:OOXMLMacroEnabled = $false
            $zip = [System.IO.Compression.ZipFile]::OpenRead($Script:WorkingPath)
            try {
                $ctEntry = $zip.Entries | Where-Object { $_.FullName -eq '[Content_Types].xml' } | Select-Object -First 1
                if ($ctEntry) {
                    $stream = $ctEntry.Open()
                    try {
                        $reader = New-Object System.IO.StreamReader($stream)
                        try { $ct = $reader.ReadToEnd() } finally { $reader.Dispose() }
                    } finally { $stream.Dispose() }

                    if     ($ct -match 'wordprocessingml')   { $Script:OOXMLSubtype = 'word' }
                    elseif ($ct -match 'spreadsheetml')      { $Script:OOXMLSubtype = 'excel' }
                    elseif ($ct -match 'presentationml')     { $Script:OOXMLSubtype = 'powerpoint' }

                    if ($ct -match 'macroEnabled') {
                        $Script:OOXMLMacroEnabled = $true
                        Write-Log "VERIFY_WARN: Macro-enabled content type declared in [Content_Types].xml - VBA expected in this file" 'WARN'
                    }
                }
            } finally { $zip.Dispose() }
            Write-Log "VERIFY_OK: OOXML subtype='$Script:OOXMLSubtype' | macroEnabled=$Script:OOXMLMacroEnabled"
            Write-Log ("UNIT_END: Classify-OOXMLSubtype | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
        }
        catch {
            Write-Log "UNIT_FAILED: Classify-OOXMLSubtype | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
            Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
            exit 20
        }
    }
}

# ============================================================
# PHASE 2: EXTRACTION
# ============================================================
function Invoke-Extraction {

    if ($Script:FileFormat -eq 'OOXML') {
        #region UNIT: Extract-OOXMLStructure ------------------------
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Extract-OOXMLStructure'
        try {
            $destZip = Join-Path $Script:WorkingDir 'document.zip'
            # Copy the copy to a .zip-named twin so Expand-Archive accepts it.
            # Source untouched; we're only operating under $Script:WorkingDir.
            Copy-Item -LiteralPath $Script:WorkingPath -Destination $destZip -Force
            $extractPath = Join-Path $Script:WorkingDir 'extracted'
            Expand-Archive -Path $destZip -DestinationPath $extractPath -Force

            $fileCount = (Get-ChildItem -Path $extractPath -Recurse -File).Count
            if ($fileCount -eq 0) {
                Write-Log "VERIFY_FAILED: Extract-OOXMLStructure | Archive expanded but contains no files | ExitCode=40" 'ERROR'
                exit 40
            }
            $Script:ExtractPath = $extractPath
            Write-Log "VERIFY_OK: Extracted $fileCount files to '$extractPath'"
            Write-Log ("UNIT_END: Extract-OOXMLStructure | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
        }
        catch {
            Write-Log "UNIT_FAILED: Extract-OOXMLStructure | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
            Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
            exit 20
        }
    }
    elseif ($Script:FileFormat -eq 'CFBF') {
        #region UNIT: Extract-CFBFBinary ----------------------------
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Extract-CFBFBinary'
        try {
            $Script:RawBytes = [System.IO.File]::ReadAllBytes($Script:WorkingPath)
            # Latin-1 projection preserves all byte values 1:1 as chars - safe
            # for regex scans that don't span UTF-16 null-byte boundaries.
            # [Encoding]::Latin1 static is .NET Core / 5+ only; use code page 28591
            # (ISO-8859-1) for cross-runtime compatibility with PowerShell 5.1 /
            # .NET Framework 4.x. Byte-for-character mapping is identical.
            $Script:RawContent = [System.IO.File]::ReadAllText($Script:WorkingPath, [System.Text.Encoding]::GetEncoding(28591))
            if ($Script:RawBytes.Length -eq 0) {
                Write-Log "VERIFY_FAILED: Extract-CFBFBinary | Zero bytes read | ExitCode=40" 'ERROR'
                exit 40
            }
            Write-Log "VERIFY_OK: CFBF raw loaded | bytes=$($Script:RawBytes.Length) | chars=$($Script:RawContent.Length)"
            Write-Log ("UNIT_END: Extract-CFBFBinary | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
        }
        catch {
            Write-Log "UNIT_FAILED: Extract-CFBFBinary | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
            Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
            exit 20
        }
    }
    elseif ($Script:FileFormat -eq 'RTF') {
        #region UNIT: Extract-RTFContent ----------------------------
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Extract-RTFContent'
        try {
            $Script:RtfContent = [System.IO.File]::ReadAllText($Script:WorkingPath, [System.Text.Encoding]::UTF8)
            if ([string]::IsNullOrEmpty($Script:RtfContent)) {
                Write-Log "VERIFY_FAILED: Extract-RTFContent | Empty content | ExitCode=40" 'ERROR'
                exit 40
            }
            # Pre-decode \objdata hex blobs for downstream binary-header scans.
            # RTF \objdata sections are long runs of ASCII hex pairs. Convert
            # the first ~64KB of hex content to bytes for MZ/Equation scans;
            # full-file conversion is unnecessary for static triage.
            $Script:RtfDecodedBytes = $null
            $objMatches = [regex]::Matches($Script:RtfContent, '\\objdata\s+([0-9a-fA-F\s]+)')
            if ($objMatches.Count -gt 0) {
                $hex = ($objMatches | ForEach-Object { $_.Groups[1].Value }) -join ''
                $hex = ($hex -replace '\s','')
                if ($hex.Length -ge 2) {
                    $cap = [Math]::Min($hex.Length, 131072)  # up to 64KB decoded
                    if ($cap % 2 -ne 0) { $cap-- }
                    $byteCount = $cap / 2
                    $bytes = New-Object byte[] $byteCount
                    for ($i = 0; $i -lt $byteCount; $i++) {
                        $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16)
                    }
                    $Script:RtfDecodedBytes = $bytes
                    Write-Log "RTF \objdata decoded: $byteCount bytes (from $($objMatches.Count) block(s))"
                }
            }
            Write-Log "VERIFY_OK: RTF content loaded | chars=$($Script:RtfContent.Length) | objdata_blocks=$($objMatches.Count)"
            Write-Log ("UNIT_END: Extract-RTFContent | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
        }
        catch {
            Write-Log "UNIT_FAILED: Extract-RTFContent | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
            Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
            exit 20
        }
    }
}

# ============================================================
# PHASE 3: ANALYSIS
# ============================================================
function Invoke-Analysis {
    $Script:Findings = [System.Collections.Generic.List[object]]::new()
    $Script:RecordFailures = 0   # per-unit recoverable failures (PARTIAL_SUCCESS tracking)

    # Load early-warning signal from Preflight into findings if set.
    if ($Script:FileFormat -eq 'OOXML' -and $Script:OOXMLMacroEnabled) {
        Add-Finding 'SUSPICIOUS' 'MacroEnabledContentType' "Content type declares macro-enabled document - VBA expected" '[Content_Types].xml'
    }

    switch ($Script:FileFormat) {
        'OOXML' { Invoke-OOXMLAnalysis }
        'CFBF'  { Invoke-CFBFAnalysis }
        'RTF'   { Invoke-RTFAnalysis }
    }

    # PARTIAL_SUCCESS classification - analysis units that encountered
    # per-file read failures but continued.
    if ($Script:RecordFailures -gt 0) {
        Write-Log "PARTIAL_SUCCESS: Analysis completed with $Script:RecordFailures per-file read failure(s) - see RECORD_FAILED entries" 'WARN'
    } else {
        Write-Log 'FULL_SUCCESS: Analysis completed with no per-file read failures'
    }
}

function Invoke-OOXMLAnalysis {

    #region UNIT: Analyze-OOXMLFileTree -----------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-OOXMLFileTree'
    try {
        $allFiles = Get-ChildItem -Path $Script:ExtractPath -Recurse -File
        Write-Log "Total files in archive: $($allFiles.Count)"
        foreach ($f in $allFiles) {
            Write-Log "Extracted file: $($f.FullName) [$($f.Length) bytes]" 'DEBUG'
            if ($f.Extension -in $Script:SuspiciousExtensions) {
                $rel = $f.FullName.Substring($Script:ExtractPath.Length).TrimStart('\','/')
                Add-Finding 'ALERT' 'EmbeddedExecutable' "Suspicious embedded file: '$($f.Name)'" $rel
            }
        }
        Write-Log ("UNIT_END: Analyze-OOXMLFileTree | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-OOXMLFileTree | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-VBAPresence -------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-VBAPresence'
    try {
        $vbaBin = @(Get-ChildItem -Path $Script:ExtractPath -Recurse -Filter 'vbaProject.bin' -ErrorAction SilentlyContinue)
        foreach ($v in $vbaBin) {
            $rel = $v.FullName.Substring($Script:ExtractPath.Length).TrimStart('\','/')
            Add-Finding 'ALERT' 'Macro' "VBA project binary present [$($v.Length) bytes]" $rel
        }
        $activeX = @(Get-ChildItem -Path $Script:ExtractPath -Recurse -Filter 'activeX*.bin' -ErrorAction SilentlyContinue)
        foreach ($ax in $activeX) {
            $rel = $ax.FullName.Substring($Script:ExtractPath.Length).TrimStart('\','/')
            Add-Finding 'ALERT' 'ActiveX' "ActiveX binary: '$($ax.Name)' [$($ax.Length) bytes]" $rel
        }
        Write-Log ("UNIT_END: Analyze-VBAPresence | vba={0} | activeX={1} | Duration: {2:N3}s" -f $vbaBin.Count, $activeX.Count, $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-VBAPresence | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-OOXMLContent ------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-OOXMLContent'
    try {
        $xmlFiles = Get-ChildItem -Path $Script:ExtractPath -Recurse -Include '*.xml','*.rels' -File
        Write-Log "XML/rels files to scan: $($xmlFiles.Count)"

        foreach ($xmlFile in $xmlFiles) {
            $relPath = $xmlFile.FullName.Substring($Script:ExtractPath.Length).TrimStart('\','/')
            try {
                $content = Get-Content -LiteralPath $xmlFile.FullName -Raw -Encoding UTF8

                # External relationships (attribute order-independent regex - v1 bug fix)
                $extMatches = [regex]::Matches($content,
                    '(?:TargetMode="External"[^>]*Target="([^"]+)")|(?:Target="([^"]+)"[^>]*TargetMode="External")')
                foreach ($m in $extMatches) {
                    $target = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
                    Add-Finding 'ALERT' 'ExternalRelationship' "External target: $target" $relPath
                }

                # Embedded object / OLE references
                if ($content -match '(oleObject|embeddings|externalLink)') {
                    Add-Finding 'SUSPICIOUS' 'EmbeddedObject' 'OLE/embedded reference present' $relPath
                }

                # Keyword scan - remove v1's `break` so multiple keywords are recorded.
                foreach ($kw in $Script:SuspiciousKeywords) {
                    if ($content -match [regex]::Escape($kw)) {
                        Add-Finding 'SUSPICIOUS' 'SuspiciousKeyword' "Keyword '$kw' found" $relPath
                    }
                }

                # URL schemes - only inside value attributes of .rels files
                # (Target=, src=, Source=) or inside document.xml content nodes.
                # xmlns= namespace declarations and schema URIs are excluded.
                if ($relPath -like '*.rels' -or $relPath -like '*word*\document.xml' -or $relPath -like '*xl*\sharedStrings.xml') {
                    foreach ($scheme in $Script:UrlSchemes) {
                        $urlPattern = '(?:Target|src|Source)\s*=\s*"([^"]*' + [regex]::Escape($scheme) + '[^"]*)"'
                        $urlMatches = [regex]::Matches($content, $urlPattern)
                        foreach ($m in $urlMatches) {
                            Add-Finding 'SUSPICIOUS' 'ExternalUrl' "URL in attribute: $($m.Groups[1].Value)" $relPath
                        }
                    }
                }

                # DDE
                if ($content -match 'ddeService|DDE\s') {
                    Add-Finding 'ALERT' 'DDE' 'DDE reference present' $relPath
                }
            }
            catch {
                $Script:RecordFailures++
                Write-Log "RECORD_FAILED: Could not read '$relPath' | Error='$($_.Exception.Message)'" 'ERROR'
            }
        }
        Write-Log ("UNIT_END: Analyze-OOXMLContent | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-OOXMLContent | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-TemplateInjection -------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-TemplateInjection'
    try {
        # settings.xml.rels is where Word/Excel/PowerPoint store attachedTemplate.
        # Pattern holds across {word,xl,ppt}/_rels/settings.xml.rels.
        $relsFiles = Get-ChildItem -Path $Script:ExtractPath -Recurse -Filter 'settings.xml.rels' -ErrorAction SilentlyContinue
        $hit = $false
        foreach ($rf in $relsFiles) {
            $rel = $rf.FullName.Substring($Script:ExtractPath.Length).TrimStart('\','/')
            try {
                $content = Get-Content -LiteralPath $rf.FullName -Raw -Encoding UTF8
                $tm = [regex]::Matches($content,
                    '(?:Type="[^"]*attachedTemplate[^"]*"[^>]*Target="([^"]+)"[^>]*TargetMode="External")|(?:Target="([^"]+)"[^>]*Type="[^"]*attachedTemplate[^"]*"[^>]*TargetMode="External")')
                foreach ($m in $tm) {
                    $target = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
                    Add-Finding 'ALERT' 'TemplateInjection' "Remote attachedTemplate URL: $target (template-injection phishing pattern)" $rel
                    $hit = $true
                }
            }
            catch {
                $Script:RecordFailures++
                Write-Log "RECORD_FAILED: Could not read '$rel' | Error='$($_.Exception.Message)'" 'ERROR'
            }
        }
        if (-not $hit) { Write-Log 'VERIFY_OK: No remote attachedTemplate references detected' }
        Write-Log ("UNIT_END: Analyze-TemplateInjection | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-TemplateInjection | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }
}

function Invoke-CFBFAnalysis {

    #region UNIT: Detect-EncryptedPackage --------------------------
    # Runs FIRST in CFBF analysis. Password-protected OOXML is wrapped in
    # a CFBF outer container with an 'EncryptedPackage' stream - so when
    # the user points this script at a password-protected .docx, magic
    # bytes route it here (D0-CF-11-E0), not to the OOXML path. Legacy
    # CFBF (.doc/.xls) password protection uses the same stream name.
    #
    # If detected, we emit a SUSPICIOUS finding with an escalation note.
    # Downstream keyword/OLE-stream scans still run - they won't fire
    # meaningful findings on encrypted ciphertext, but their zero-result
    # output is itself diagnostic (confirms the encryption hypothesis).
    #endregion
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Detect-EncryptedPackage'
    try {
        $encHits = @()
        foreach ($name in $Script:EncryptedStreamNames) {
            $utf16Needle = [System.Text.Encoding]::Unicode.GetBytes($name)
            $offset = Find-BytePattern -Haystack $Script:RawBytes -Needle $utf16Needle
            if ($offset -ge 0) {
                $encHits += [pscustomobject]@{ Name = $name; Offset = $offset }
            }
        }
        if ($encHits.Count -gt 0) {
            $detail = "Password-protected or encrypted document - static content analysis of body is not possible without the password. Detected streams: " + (($encHits | ForEach-Object { $_.Name }) -join ', ')
            $firstOffset = "offset=0x{0:X}" -f $encHits[0].Offset
            Add-Finding 'SUSPICIOUS' 'EncryptedPackage' $detail $firstOffset
            Write-Log 'VERIFY_WARN: Encrypted package detected - body cannot be scanned statically; escalate with password to olevba/MSOFFCRYPTO-tool' 'WARN'
        } else {
            Write-Log 'VERIFY_OK: No encrypted-package indicators detected'
        }
        Write-Log ("UNIT_END: Detect-EncryptedPackage | hits={0} | Duration: {1:N3}s" -f $encHits.Count, $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Detect-EncryptedPackage | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-CFBFKeywords ------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-CFBFKeywords'
    try {
        $hits = 0
        foreach ($kw in $Script:SuspiciousKeywords) {
            if ($Script:RawContent -match [regex]::Escape($kw)) {
                Add-Finding 'SUSPICIOUS' 'SuspiciousKeyword' "Keyword '$kw' found in binary content"
                $hits++
            }
        }
        # URL schemes inside CFBF binary content - VBA source strings often
        # contain these. CFBF lacks the xmlns namespace noise problem that
        # OOXML has, so direct substring match is reliable here.
        foreach ($scheme in $Script:UrlSchemes) {
            if ($Script:RawContent -match [regex]::Escape($scheme)) {
                Add-Finding 'SUSPICIOUS' 'ExternalUrl' "URL scheme '$scheme' in binary content"
                $hits++
            }
        }
        if ($hits -gt 0) {
            Write-Log "VERIFY_WARN: $hits suspicious keyword(s) matched - run olevba for full macro decode if verdict is not CLEAN" 'WARN'
        } else {
            Write-Log 'VERIFY_OK: No plaintext suspicious keywords detected'
        }
        Write-Log ("UNIT_END: Analyze-CFBFKeywords | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-CFBFKeywords | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-CFBFAutoExec ------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-CFBFAutoExec'
    try {
        foreach ($trigger in $Script:AutoExecTriggers) {
            # ASCII check (plaintext occurrences)
            if ($Script:RawContent -match [regex]::Escape($trigger)) {
                Add-Finding 'ALERT' 'AutoExec' "Auto-execution trigger '$trigger' (ASCII) - macro likely fires on document open"
            }
            # UTF-16LE check - VBA module/procedure names in CFBF streams
            $needle = [System.Text.Encoding]::Unicode.GetBytes($trigger)
            $offset = Find-BytePattern -Haystack $Script:RawBytes -Needle $needle
            if ($offset -ge 0) {
                Add-Finding 'ALERT' 'AutoExec' "Auto-execution trigger '$trigger' (UTF-16LE) - VBA module auto-exec procedure" ("offset=0x{0:X}" -f $offset)
            }
        }
        Write-Log ("UNIT_END: Analyze-CFBFAutoExec | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-CFBFAutoExec | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-CFBFOLEStreams (CENTERPIECE CORRECTNESS FIX)
    # v1 used literal "\x00" in a PowerShell double-quoted string - those are
    # five-character strings, not null bytes. This unit replaces that regex
    # with proper UTF-16LE byte-array searches via Find-BytePattern.
    #endregion
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-CFBFOLEStreams'
    try {
        $olePatterns = [ordered]@{
            'Macros (VBA)'        = @{ Needle = [System.Text.Encoding]::Unicode.GetBytes('VBA');           Severity = 'ALERT' }
            'WordDocument stream' = @{ Needle = [System.Text.Encoding]::Unicode.GetBytes('WordDocument');  Severity = 'INFO'  }
            'Workbook stream'     = @{ Needle = [System.Text.Encoding]::Unicode.GetBytes('Workbook');      Severity = 'INFO'  }
            'PowerPoint stream'   = @{ Needle = [System.Text.Encoding]::Unicode.GetBytes('PowerPoint Document'); Severity = 'INFO' }
            'OLE Package stream'  = @{ Needle = ([byte[]]@(0x01) + [System.Text.Encoding]::ASCII.GetBytes('Ole10Native')); Severity = 'ALERT' }
            'Equation Native'     = @{ Needle = [System.Text.Encoding]::ASCII.GetBytes('Equation Native'); Severity = 'ALERT' }
        }
        foreach ($name in $olePatterns.Keys) {
            $entry = $olePatterns[$name]
            $offset = Find-BytePattern -Haystack $Script:RawBytes -Needle $entry.Needle
            if ($offset -ge 0) {
                Add-Finding $entry.Severity 'OLEStream' "CFBF stream detected: '$name'" ("offset=0x{0:X}" -f $offset)
            }
        }

        # CVE-2017-11882 / CVE-2018-0802 callout - any Equation Editor embed
        # in a modern document is high-risk regardless of content.
        $eqOffset = Find-BytePattern -Haystack $Script:RawBytes -Needle ([System.Text.Encoding]::ASCII.GetBytes('Equation Native'))
        if ($eqOffset -ge 0) {
            Add-Finding 'ALERT' 'EquationEditor' 'Equation Editor object present - high risk for CVE-2017-11882 / CVE-2018-0802' ("offset=0x{0:X}" -f $eqOffset)
        }

        Write-Log ("UNIT_END: Analyze-CFBFOLEStreams | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-CFBFOLEStreams | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-XLMMacros --------------------------------
    # XLM / Excel 4.0 macros are best-effort detection in static analysis.
    # They don't live in vbaProject.bin - they're hidden in worksheet
    # cells or a defined name like 'Auto_Open' pointing at a 'Macro1' sheet.
    # Hits here are SUSPICIOUS (not ALERT) plus an escalation note.
    #endregion
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-XLMMacros'
    try {
        $xlmIndicators = @(
            @{ Label = 'Auto_Open (XLM defined name)'; AsciiNeedle = 'Auto_Open' },
            @{ Label = 'Auto_Close (XLM defined name)'; AsciiNeedle = 'Auto_Close' },
            @{ Label = 'Macro sheet reference'; AsciiNeedle = 'Macro1' },
            @{ Label = 'veryHidden sheet marker'; AsciiNeedle = 'veryHidden' }
        )
        $xlmFound = $false
        foreach ($ind in $xlmIndicators) {
            $asciiNeedle = [System.Text.Encoding]::ASCII.GetBytes($ind.AsciiNeedle)
            $utf16Needle = [System.Text.Encoding]::Unicode.GetBytes($ind.AsciiNeedle)

            $aOff = Find-BytePattern -Haystack $Script:RawBytes -Needle $asciiNeedle
            $uOff = Find-BytePattern -Haystack $Script:RawBytes -Needle $utf16Needle
            if ($aOff -ge 0) {
                Add-Finding 'SUSPICIOUS' 'XLMMacro' "XLM indicator (ASCII): $($ind.Label)" ("offset=0x{0:X}" -f $aOff)
                $xlmFound = $true
            }
            if ($uOff -ge 0) {
                Add-Finding 'SUSPICIOUS' 'XLMMacro' "XLM indicator (UTF-16LE): $($ind.Label)" ("offset=0x{0:X}" -f $uOff)
                $xlmFound = $true
            }
        }
        if ($xlmFound) {
            Write-Log 'VERIFY_WARN: XLM/Excel 4.0 macro indicators present - escalate with XLMMacroDeobfuscator for full decode' 'WARN'
        } else {
            Write-Log 'VERIFY_OK: No XLM macro indicators detected'
        }
        Write-Log ("UNIT_END: Analyze-XLMMacros | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-XLMMacros | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }
}

function Invoke-RTFAnalysis {

    #region UNIT: Analyze-RTFObjects --------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-RTFObjects'
    try {
        $objCount       = ([regex]::Matches($Script:RtfContent, '\\object\b')).Count
        $objDataCount   = ([regex]::Matches($Script:RtfContent, '\\objdata\b')).Count
        $objUpdateCount = ([regex]::Matches($Script:RtfContent, '\\objupdate\b')).Count
        $objClassCount  = ([regex]::Matches($Script:RtfContent, '\\objclass\b')).Count

        if ($objCount -gt 0)       { Add-Finding 'SUSPICIOUS' 'RTFObject' "$objCount \object control word(s)" }
        if ($objDataCount -gt 0)   { Add-Finding 'SUSPICIOUS' 'RTFObject' "$objDataCount \objdata block(s) present" }
        if ($objUpdateCount -gt 0) { Add-Finding 'ALERT' 'RTFObject' "$objUpdateCount \objupdate control word(s) - forces OLE refresh on open" }
        if ($objClassCount -gt 0)  { Add-Finding 'SUSPICIOUS' 'RTFObject' "$objClassCount \objclass block(s) - examine target CLSID" }

        Write-Log ("UNIT_END: Analyze-RTFObjects | object={0} objdata={1} objupdate={2} objclass={3} | Duration: {4:N3}s" -f $objCount, $objDataCount, $objUpdateCount, $objClassCount, $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-RTFObjects | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-RTFEquationEditor -------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-RTFEquationEditor'
    try {
        # Equation.3 / Equation.2 ProgIDs appear as text inside \objclass and
        # (hex-decoded) inside \objdata. Check both surfaces.
        $eqRe = 'Equation\.[23]'
        if ($Script:RtfContent -match $eqRe) {
            Add-Finding 'ALERT' 'EquationEditor' 'Equation Editor ProgID in RTF text - high risk for CVE-2017-11882 / CVE-2018-0802'
        }
        if ($Script:RtfDecodedBytes) {
            $asciiView = [System.Text.Encoding]::ASCII.GetString($Script:RtfDecodedBytes)
            if ($asciiView -match $eqRe -or $asciiView -match 'Equation Native') {
                Add-Finding 'ALERT' 'EquationEditor' 'Equation Editor marker in decoded \objdata - high risk for CVE-2017-11882 / CVE-2018-0802'
            }
        }
        Write-Log ("UNIT_END: Analyze-RTFEquationEditor | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-RTFEquationEditor | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }

    #region UNIT: Analyze-RTFEmbeddedExe ----------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Analyze-RTFEmbeddedExe'
    try {
        if ($Script:RtfDecodedBytes) {
            $mzOffset = Find-BytePattern -Haystack $Script:RtfDecodedBytes -Needle ([byte[]]@(0x4D, 0x5A))
            if ($mzOffset -ge 0) {
                Add-Finding 'ALERT' 'EmbeddedExecutable' 'MZ header (PE file) in decoded \objdata - embedded executable payload' ("objdata_offset=0x{0:X}" -f $mzOffset)
            }
        }
        Write-Log ("UNIT_END: Analyze-RTFEmbeddedExe | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        Write-Log "UNIT_FAILED: Analyze-RTFEmbeddedExe | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20" 'ERROR'
        Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
        exit 20
    }
}

# ============================================================
# PHASE 4: REPORT
# ============================================================
function Invoke-Report {

    #region UNIT: Build-FindingsSummary -----------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log 'UNIT_START: Build-FindingsSummary'

    $alerts     = @($Script:Findings | Where-Object { $_.Severity -eq 'ALERT' })
    $suspicious = @($Script:Findings | Where-Object { $_.Severity -eq 'SUSPICIOUS' })
    $infoItems  = @($Script:Findings | Where-Object { $_.Severity -eq 'INFO' })

    $Script:Verdict = if     ($alerts.Count -gt 0)     { 'MALICIOUS' }
                      elseif ($suspicious.Count -gt 0) { 'SUSPICIOUS' }
                      else                              { 'CLEAN' }

    Write-Log "VERDICT: $Script:Verdict | Alerts=$($alerts.Count) | Suspicious=$($suspicious.Count) | Info=$($infoItems.Count)"
    Write-Log ("UNIT_END: Build-FindingsSummary | Verdict=$Script:Verdict | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)

    #region UNIT: Write-ConsoleReport -------------------------------
    if ($OutputFormat -eq 'Console' -or $OutputFormat -eq 'Both') {
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Write-ConsoleReport'

        $separator = '=' * 72
        $header = @"

$separator
  OFFICE DOCUMENT FORENSIC ANALYSIS - FINDINGS REPORT
$separator
  File    : $($Script:SourceFileItem.FullName)
  Size    : $($Script:SourceFileItem.Length) bytes
  Format  : $Script:FileFormat ($Script:HexSignature)
  Ext     : $Script:FileExtension

  SHA256  : $($Script:Hashes.SHA256)
  SHA1    : $($Script:Hashes.SHA1)
  MD5     : $($Script:Hashes.MD5)
$separator
  VERDICT : $Script:Verdict
  Alerts     : $($alerts.Count)
  Suspicious : $($suspicious.Count)
  Info       : $($infoItems.Count)
$separator
"@
        Write-Host $header

        if ($alerts.Count -gt 0) {
            Write-Host "`n  [ALERT] FINDINGS:" -ForegroundColor Red
            foreach ($f in $alerts) {
                $loc = if ($f.Location) { " @ $($f.Location)" } else { '' }
                Write-Host "    [$($f.Category)] $($f.Detail)$loc" -ForegroundColor Red
            }
        }
        if ($suspicious.Count -gt 0) {
            Write-Host "`n  [SUSPICIOUS] FINDINGS:" -ForegroundColor Yellow
            foreach ($f in $suspicious) {
                $loc = if ($f.Location) { " @ $($f.Location)" } else { '' }
                Write-Host "    [$($f.Category)] $($f.Detail)$loc" -ForegroundColor Yellow
            }
        }
        if ($infoItems.Count -gt 0) {
            Write-Host "`n  [INFO] FINDINGS:" -ForegroundColor Cyan
            foreach ($f in $infoItems) {
                $loc = if ($f.Location) { " @ $($f.Location)" } else { '' }
                Write-Host "    [$($f.Category)] $($f.Detail)$loc" -ForegroundColor Cyan
            }
        }
        Write-Host "`n$separator`n"

        if ($Script:FileFormat -eq 'CFBF' -and ($alerts.Count -gt 0 -or $suspicious.Count -gt 0)) {
            Write-Host '  ESCALATION NOTE: CFBF findings present.' -ForegroundColor Magenta
            Write-Host '  Static scanning cannot decode obfuscated / compressed VBA.' -ForegroundColor Magenta
            Write-Host "  Recommended: run 'olevba' (oletools) on source for full macro extraction." -ForegroundColor Magenta
            Write-Log 'ESCALATION: CFBF findings present - olevba recommended for full decode' 'WARN'
        }
        if ($Script:FileFormat -eq 'RTF' -and $alerts.Count -gt 0) {
            Write-Host '  ESCALATION NOTE: RTF with ALERT-level findings.' -ForegroundColor Magenta
            Write-Host "  Recommended: run 'rtfobj' (oletools) on source for full OLE-object extraction." -ForegroundColor Magenta
            Write-Log 'ESCALATION: RTF alerts present - rtfobj recommended for full OLE extraction' 'WARN'
        }

        Write-Log ("UNIT_END: Write-ConsoleReport | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }

    #region UNIT: Write-JsonReport ----------------------------------
    if (($OutputFormat -eq 'Json' -or $OutputFormat -eq 'Both') -and -not $DryRun) {
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log 'UNIT_START: Write-JsonReport'
        try {
            $jsonPath = Join-Path $OutputDir ("{0}-{1}.findings.json" -f $Script:ScriptName, (Get-Date -Format 'yyyyMMdd-HHmmss'))

            $escalation = ''
            if ($Script:FileFormat -eq 'CFBF' -and ($alerts.Count -gt 0 -or $suspicious.Count -gt 0)) {
                $escalation = 'CFBF findings present - run olevba (oletools) on source for full macro decode'
            } elseif ($Script:FileFormat -eq 'RTF' -and $alerts.Count -gt 0) {
                $escalation = 'RTF ALERT-level findings - run rtfobj (oletools) on source for full OLE extraction'
            }

            $subtype = if ($Script:FileFormat -eq 'OOXML') { $Script:OOXMLSubtype } else { $null }
            $macroEnabled = if ($Script:FileFormat -eq 'OOXML') { [bool]$Script:OOXMLMacroEnabled } else { $false }
            $extMatches = $true
            $expectedExtensions = @{
                OOXML = @('.docx','.xlsx','.pptx','.xml','.xlsm','.docm','.pptm','.dotx','.dotm','.xltx','.xltm','.potx','.potm','.zip')
                CFBF  = @('.doc','.xls','.ppt','.dot','.xlt','.pot','.msi','.msg')
                RTF   = @('.rtf','.doc')
            }
            if ($Script:FileExtension -notin $expectedExtensions[$Script:FileFormat]) { $extMatches = $false }

            $report = [ordered]@{
                schema_version = '1.0'
                script         = [ordered]@{ name = $Script:ScriptName; version = $Script:Version }
                analyzed_at    = (Get-Date).ToUniversalTime().ToString('o')
                source         = [ordered]@{
                    path       = $Script:SourceFileItem.FullName
                    size       = $Script:SourceFileItem.Length
                    last_write_utc = $Script:SourceLastWriteStart.ToString('o')
                    hashes     = [ordered]@{
                        sha256 = $Script:Hashes.SHA256
                        sha1   = $Script:Hashes.SHA1
                        md5    = $Script:Hashes.MD5
                    }
                }
                format         = [ordered]@{
                    detected          = $Script:FileFormat
                    magic_bytes       = $Script:HexSignature
                    extension         = $Script:FileExtension
                    extension_matches = $extMatches
                    ooxml_subtype     = $subtype
                    ooxml_macro_enabled = $macroEnabled
                }
                workspace      = $Script:WorkingDir
                verdict        = $Script:Verdict
                counts         = [ordered]@{
                    alert      = $alerts.Count
                    suspicious = $suspicious.Count
                    info       = $infoItems.Count
                }
                findings       = @($Script:Findings)
                escalation_recommended = [bool]$escalation
                escalation_reason      = $escalation
                record_failures = $Script:RecordFailures
            }

            $json = $report | ConvertTo-Json -Depth 6
            Set-Content -LiteralPath $jsonPath -Value $json -Encoding UTF8

            # Verification: file exists, non-empty, round-trips as JSON
            $jsonItem = Get-Item -LiteralPath $jsonPath
            if ($jsonItem.Length -eq 0) {
                Write-Log "VERIFY_FAILED: JSON report is zero bytes | Path='$jsonPath' | ExitCode=40" 'ERROR'
                exit 40
            }
            $null = Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            Write-Log "VERIFY_OK: JSON report written and round-trips | Path='$jsonPath' | Size=$($jsonItem.Length)B"
            Write-Log ("UNIT_END: Write-JsonReport | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
        }
        catch {
            Write-Log "UNIT_FAILED: Write-JsonReport | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=40" 'ERROR'
            Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'
            exit 40
        }
    }
    elseif ($DryRun) {
        Write-Log '[DRY-RUN] Would write JSON findings report to $OutputDir - skipped'
    }

    #region UNIT: Cleanup-Workspace ---------------------------------
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "UNIT_START: Cleanup-Workspace | Path='$Script:WorkingDir'"
    try {
        $preserve = ($KeepTempOnAlert -and $Script:Verdict -eq 'MALICIOUS')
        if ($preserve) {
            Write-Log "Workspace PRESERVED for analyst review (-KeepTempOnAlert + MALICIOUS): '$Script:WorkingDir'" 'WARN'
        }
        elseif ($Script:WorkingDir -and (Test-Path -LiteralPath $Script:WorkingDir)) {
            Remove-Item -LiteralPath $Script:WorkingDir -Recurse -Force
            Write-Log 'VERIFY_OK: Workspace removed'
        }
        Write-Log ("UNIT_END: Cleanup-Workspace | Duration: {0:N3}s" -f $unitTimer.Elapsed.TotalSeconds)
    }
    catch {
        # Cleanup failures are WARN not FATAL - analyst can remove manually.
        Write-Log "Cleanup-Workspace | Could not remove workspace - manual cleanup needed: '$Script:WorkingDir' | Error='$($_.Exception.Message)'" 'WARN'
    }
}

# ============================================================
# MAIN
# IDEMPOTENT: This script is read-only against the source file.
# Re-running on the same file is always safe and produces identical
# findings (modulo timestamp-based output filenames).
# ============================================================
try {
    if (-not (Test-Path -LiteralPath $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $Script:LogFile = Join-Path $OutputDir ("{0}-{1}.log" -f $Script:ScriptName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    '' | Out-File -LiteralPath $Script:LogFile -Encoding UTF8

    $Script:ScriptTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Initialize-Script

    Invoke-PhaseStart -PhaseName 'Preflight'
    Invoke-Preflight
    Invoke-PhaseGate  -PhaseName 'Preflight' -Summary "File='$($Script:SourceFileItem.Name)' | Format='$Script:FileFormat' | Size=$($Script:SourceFileItem.Length)B"

    Invoke-PhaseStart -PhaseName 'Extraction'
    Invoke-Extraction
    Invoke-PhaseGate  -PhaseName 'Extraction' -Summary "Format='$Script:FileFormat' | Workspace='$Script:WorkingDir'"

    Invoke-PhaseStart -PhaseName 'Analysis'
    Invoke-Analysis
    Invoke-PhaseGate  -PhaseName 'Analysis' -Summary "Findings=$(($Script:Findings).Count) | RecordFailures=$Script:RecordFailures"

    Invoke-PhaseStart -PhaseName 'Report'
    Invoke-Report
    Invoke-PhaseGate  -PhaseName 'Report' -Summary "Verdict=$Script:Verdict | LogFile='$Script:LogFile'"

    # Final immutability assertion - the contract the whole rewrite exists to prove.
    Assert-SourceUnchanged

    $Script:ScriptTimer.Stop()
    $totalSec = $Script:ScriptTimer.Elapsed.TotalSeconds
    Write-Log ("SCRIPT_COMPLETE: {0} | Verdict={1} | TotalDuration={2:N3}s | Log='{3}'" -f $Script:ScriptName, $Script:Verdict, $totalSec, $Script:LogFile)
    exit 0
}
catch {
    Write-Log "SCRIPT_FAILED: Unhandled error | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=99" 'FATAL'
    Write-Log "STACK_TRACE: $($_.ScriptStackTrace)" 'DEBUG'

    # Best-effort cleanup unless DebugMode preserves workspace for post-mortem.
    if ($Script:WorkingDir -and (Test-Path -LiteralPath $Script:WorkingDir) -and -not $DebugMode) {
        Remove-Item -LiteralPath $Script:WorkingDir -Recurse -Force -ErrorAction SilentlyContinue
    } elseif ($DebugMode -and $Script:WorkingDir) {
        Write-Log "Workspace preserved for post-mortem (DebugMode): '$Script:WorkingDir'" 'WARN'
    }
    exit 99
}
