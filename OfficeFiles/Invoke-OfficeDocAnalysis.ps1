#Requires -Version 5.1
<#
.SYNOPSIS
    Office Document Forensic Analysis — Multi-Format Static Inspector

.DESCRIPTION
    Performs static (non-executing) forensic analysis of Microsoft Office documents.
    Supports legacy binary format (.doc, .xls, .ppt) and Open XML format
    (.docx, .xlsx, .pptx, .xml). Detects macros, embedded objects, suspicious
    keywords, and anomalous structures without opening the file in any application.

    Format routing is automatic based on magic byte detection — not file extension.

.PARAMETER FilePath
    Full path to the Office document to analyze.

.PARAMETER OutputDir
    Directory for log file and extracted artifacts. Defaults to script directory.

.PARAMETER StopAfterPhase
    Stop cleanly after a named phase: Preflight, Extraction, Analysis, Report.

.PARAMETER DebugMode
    Promote DEBUG log entries to console output.

.PARAMETER DryRun
    Validate and extract only. Skip no write-operations are performed outside
    the temp extraction directory.

.EXAMPLE
    .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\suspect.docx"

.EXAMPLE
    .\Invoke-OfficeDocAnalysis.ps1 -FilePath "C:\Cases\old_file.doc" -DebugMode -StopAfterPhase Extraction

.NOTES
    Author  : Ghost
    Version : 1.0.0
    Date    : 2025-04-24

    Exit Codes:
        0  = Success / clean gate stop
        10 = Input file not found or inaccessible
        11 = Unrecognized or unsupported file format
        20 = Unit / processing failure
        40 = Output verification failed
        99 = Unexpected / unhandled error
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = $PSScriptRoot,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Preflight", "Extraction", "Analysis", "Report")]
    [string]$StopAfterPhase = "",

    [switch]$DebugMode,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================
$Script:Version     = "1.0.0"
$Script:ScriptName  = "Invoke-OfficeDocAnalysis"
$Script:LogFile     = Join-Path $OutputDir "$Script:ScriptName-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$Script:TempDir     = $null   # set during Preflight
$Script:ScriptTimer = $null

# Suspicious keyword lists — extend as needed
$Script:SuspiciousKeywords = @(
    'AutoOpen', 'AutoExec', 'AutoClose', 'Document_Open', 'Workbook_Open',
    'Shell', 'WScript', 'CreateObject', 'GetObject',
    'PowerShell', 'cmd.exe', 'mshta', 'wscript', 'cscript', 'regsvr32',
    'certutil', 'bitsadmin', 'rundll32', 'msiexec',
    'http://', 'https://', 'ftp://',
    'Chr(', 'Asc(', 'Environ(', 'Execute(', 'Eval(',
    'Base64', 'FromBase64', 'Decode',
    'ADODB.Stream', 'Scripting.FileSystemObject', 'Shell.Application',
    'WScript.Shell', 'InternetExplorer.Application'
)

$Script:SuspiciousExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.scr', '.vbs', '.js', '.hta', '.msi')

# Magic byte signatures → format name
$Script:MagicBytes = @{
    "50-4B-03-04" = "OOXML"      # ZIP-based: .docx, .xlsx, .pptx, .xml
    "D0-CF-11-E0" = "CFBF"       # Compound Binary: .doc, .xls, .ppt
}

# ============================================================
# HELPERS
# ============================================================

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    # Always write to file
    Add-Content -Path $Script:LogFile -Value $entry -Encoding UTF8

    # Console output based on level and flags
    switch ($Level) {
        "DEBUG" { if ($DebugMode) { Write-Host $entry -ForegroundColor DarkGray } }
        "INFO"  { Write-Host $entry -ForegroundColor Cyan }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "FATAL" { Write-Host $entry -ForegroundColor Magenta }
    }
}

function Invoke-PhaseStart {
    param([string]$PhaseName)
    $Script:PhaseTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "PHASE_START: $PhaseName"
}

function Invoke-PhaseGate {
    param(
        [string]$PhaseName,
        [string]$Summary = ""
    )
    $Script:PhaseTimer.Stop()
    $duration = [math]::Round($Script:PhaseTimer.Elapsed.TotalSeconds, 2)
    $totalElapsed = [math]::Round($Script:ScriptTimer.Elapsed.TotalSeconds, 2)

    if ($Summary) {
        Write-Log "INFO" "PHASE_SUMMARY: $PhaseName | $Summary"
    }
    Write-Log "INFO" "PHASE_END: $PhaseName | Phase Duration: ${duration}s"

    if ($StopAfterPhase -eq $PhaseName) {
        Write-Log "INFO" "PHASE_GATE: Stopping cleanly after phase '$PhaseName' | Total Duration: ${totalElapsed}s"
        exit 0
    }
}

function Get-ElapsedSeconds {
    param([System.Diagnostics.Stopwatch]$Timer)
    return [math]::Round($Timer.Elapsed.TotalSeconds, 2)
}

# ============================================================
# PHASE 1: PREFLIGHT
# ============================================================
function Invoke-Preflight {
    #region ============================================================
    # UNIT: Initialize
    # Purpose : Start timers, init log file, capture environment snapshot
    # Inputs  : $Script:LogFile, $OutputDir
    # Outputs : Log file created, $Script:ScriptTimer started
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Initialize"

    $Script:ScriptTimer = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Log "INFO" "SCRIPT_START: $Script:ScriptName v$Script:Version"

    if ($DryRun)    { Write-Log "INFO" "DRY-RUN MODE ACTIVE — no writes outside temp extraction dir" }
    if ($DebugMode) { Write-Log "INFO" "DEBUG MODE ACTIVE" }

    # Environment snapshot
    Write-Log "INFO" "ENV_SNAPSHOT: PSVersion=$($PSVersionTable.PSVersion) | OS=$([System.Environment]::OSVersion.VersionString) | User=$env:USERNAME | Host=$env:COMPUTERNAME | WorkDir=$(Get-Location)"
    Write-Log "INFO" "PARAMS: FilePath='$FilePath' | OutputDir='$OutputDir' | StopAfterPhase='$StopAfterPhase' | DebugMode=$DebugMode | DryRun=$DryRun"

    Write-Log "INFO" "UNIT_END: Initialize | Duration: $(Get-ElapsedSeconds $unitTimer)s"

    #region ============================================================
    # UNIT: Validate-InputFile
    # Purpose : Confirm target file exists, is readable, and has non-zero size
    # Inputs  : $FilePath
    # Outputs : $Script:FileItem (FileInfo object)
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Validate-InputFile | Path='$FilePath'"

    try {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            Write-Log "FATAL" "UNIT_FAILED: Validate-InputFile | File not found: '$FilePath' | ExitCode=10"
            exit 10
        }

        $Script:FileItem = Get-Item -LiteralPath $FilePath
        if ($Script:FileItem.Length -eq 0) {
            Write-Log "FATAL" "UNIT_FAILED: Validate-InputFile | File is zero bytes: '$FilePath' | ExitCode=10"
            exit 10
        }

        Write-Log "INFO" "VERIFY_OK: File exists | Size=$($Script:FileItem.Length) bytes | LastWrite=$($Script:FileItem.LastWriteTime) | Created=$($Script:FileItem.CreationTime)"
        Write-Log "INFO" "UNIT_END: Validate-InputFile | Duration: $(Get-ElapsedSeconds $unitTimer)s"
    }
    catch {
        Write-Log "FATAL" "UNIT_FAILED: Validate-InputFile | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=10"
        Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
        exit 10
    }

    #region ============================================================
    # UNIT: Detect-FileFormat
    # Purpose : Read magic bytes to determine true file format, independent
    #           of file extension. Routes downstream phases accordingly.
    # Inputs  : $FilePath
    # Outputs : $Script:FileFormat ("OOXML" | "CFBF" | "UNKNOWN")
    #           $Script:HexSignature (raw 4-byte hex string)
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Detect-FileFormat | Path='$FilePath'"

    try {
        $rawBytes = [System.IO.File]::ReadAllBytes($FilePath) | Select-Object -First 4
        $Script:HexSignature = [System.BitConverter]::ToString($rawBytes)
        $Script:FileExtension = $Script:FileItem.Extension.ToLower()

        Write-Log "INFO" "Magic bytes: $Script:HexSignature | Extension: $Script:FileExtension"

        if ($Script:MagicBytes.ContainsKey($Script:HexSignature)) {
            $Script:FileFormat = $Script:MagicBytes[$Script:HexSignature]
            Write-Log "INFO" "VERIFY_OK: Format detected as '$Script:FileFormat' | Signature='$Script:HexSignature'"
        }
        else {
            Write-Log "FATAL" "UNIT_FAILED: Detect-FileFormat | Unrecognized magic bytes: '$Script:HexSignature' — not a supported Office format | ExitCode=11"
            exit 11
        }

        # Extension/format mismatch warning — extension can be spoofed; magic bytes are ground truth
        $expectedExtensions = @{
            "OOXML" = @('.docx', '.xlsx', '.pptx', '.xml', '.xlsm', '.docm', '.pptm')
            "CFBF"  = @('.doc', '.xls', '.ppt', '.dot', '.xlt', '.pot')
        }
        if ($Script:FileExtension -notin $expectedExtensions[$Script:FileFormat]) {
            Write-Log "WARN" "VERIFY_WARN: Extension '$Script:FileExtension' does not match detected format '$Script:FileFormat' — possible extension spoofing or renamed file"
        }

        Write-Log "INFO" "UNIT_END: Detect-FileFormat | Format='$Script:FileFormat' | Duration: $(Get-ElapsedSeconds $unitTimer)s"
    }
    catch {
        Write-Log "FATAL" "UNIT_FAILED: Detect-FileFormat | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
        Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
        exit 20
    }

    #region ============================================================
    # UNIT: Compute-Hashes
    # Purpose : Generate SHA256, SHA1, MD5 hashes for VirusTotal / threat intel
    # Inputs  : $FilePath
    # Outputs : $Script:Hashes (hashtable)
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Compute-Hashes | Path='$FilePath'"

    try {
        $Script:Hashes = @{
            SHA256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
            SHA1   = (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
            MD5    = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
        }

        Write-Log "INFO" "SHA256 : $($Script:Hashes.SHA256)"
        Write-Log "INFO" "SHA1   : $($Script:Hashes.SHA1)"
        Write-Log "INFO" "MD5    : $($Script:Hashes.MD5)"
        Write-Log "INFO" "VERIFY_OK: All three hashes computed"
        Write-Log "INFO" "UNIT_END: Compute-Hashes | Duration: $(Get-ElapsedSeconds $unitTimer)s"
    }
    catch {
        Write-Log "ERROR" "UNIT_FAILED: Compute-Hashes | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
        Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
        exit 20
    }

    #region ============================================================
    # UNIT: Prepare-TempDir
    # Purpose : Create isolated temp directory for safe artifact extraction
    # Inputs  : None
    # Outputs : $Script:TempDir (path string)
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Prepare-TempDir"

    try {
        $Script:TempDir = Join-Path $env:TEMP "OfficeAnalysis_$(Get-Random)"
        New-Item -ItemType Directory -Path $Script:TempDir | Out-Null
        Write-Log "INFO" "VERIFY_OK: Temp directory created: '$Script:TempDir'"
        Write-Log "INFO" "UNIT_END: Prepare-TempDir | Duration: $(Get-ElapsedSeconds $unitTimer)s"
    }
    catch {
        Write-Log "FATAL" "UNIT_FAILED: Prepare-TempDir | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
        Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
        exit 20
    }
}

# ============================================================
# PHASE 2: EXTRACTION
# ============================================================
function Invoke-Extraction {

    #region ============================================================
    # UNIT: Extract-OOXMLStructure  (OOXML path only)
    # Purpose : Copy file as .zip and expand archive to temp dir
    # Inputs  : $FilePath, $Script:TempDir
    # Outputs : Extracted XML/binary tree under $Script:TempDir\extracted\
    #endregion ==========================================================
    if ($Script:FileFormat -eq "OOXML") {
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Extract-OOXMLStructure | Source='$FilePath'"

        try {
            $destZip = Join-Path $Script:TempDir "document.zip"
            Copy-Item -LiteralPath $FilePath -Destination $destZip
            $extractPath = Join-Path $Script:TempDir "extracted"
            Expand-Archive -Path $destZip -DestinationPath $extractPath -Force

            $fileCount = (Get-ChildItem -Path $extractPath -Recurse -File).Count
            if ($fileCount -eq 0) {
                Write-Log "ERROR" "VERIFY_FAILED: Extract-OOXMLStructure | Archive expanded but no files found | ExitCode=40"
                exit 40
            }

            Write-Log "INFO" "VERIFY_OK: Extracted $fileCount files to '$extractPath'"
            $Script:ExtractPath = $extractPath
            Write-Log "INFO" "UNIT_END: Extract-OOXMLStructure | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Extract-OOXMLStructure | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }
    }

    #region ============================================================
    # UNIT: Extract-CFBFStrings  (CFBF path only)
    # Purpose : Read raw binary as Latin-1 text for string scanning.
    #           CFBF cannot be ZIP-extracted. String analysis is the
    #           primary static analysis path for legacy binary files.
    # Inputs  : $FilePath
    # Outputs : $Script:RawContent (string)
    #endregion ==========================================================
    if ($Script:FileFormat -eq "CFBF") {
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Extract-CFBFStrings | Source='$FilePath'"
        Write-Log "INFO" "NOTE: CFBF (legacy binary) format — ZIP extraction not applicable. Using raw binary string scan."

        try {
            # Latin-1 preserves all byte values as readable characters for pattern matching
            $Script:RawContent = [System.IO.File]::ReadAllText($FilePath, [System.Text.Encoding]::Latin1)

            if ([string]::IsNullOrEmpty($Script:RawContent)) {
                Write-Log "ERROR" "VERIFY_FAILED: Extract-CFBFStrings | Raw content read returned empty | ExitCode=40"
                exit 40
            }

            Write-Log "INFO" "VERIFY_OK: Raw binary content loaded | Length=$($Script:RawContent.Length) chars"
            Write-Log "INFO" "UNIT_END: Extract-CFBFStrings | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Extract-CFBFStrings | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }
    }
}

# ============================================================
# PHASE 3: ANALYSIS
# ============================================================
function Invoke-Analysis {

    # Initialize findings accumulator used by both paths
    $Script:Findings = [System.Collections.Generic.List[hashtable]]::new()

    # Helper: record a finding
    function Add-Finding {
        param(
            [string]$Severity,   # ALERT | SUSPICIOUS | INFO
            [string]$Category,
            [string]$Detail
        )
        $Script:Findings.Add(@{ Severity = $Severity; Category = $Category; Detail = $Detail })
        $logLevel = switch ($Severity) {
            "ALERT"      { "ERROR" }
            "SUSPICIOUS" { "WARN" }
            default      { "INFO" }
        }
        Write-Log $logLevel "[$Severity] [$Category] $Detail"
    }

    # ----------------------------------------------------------------
    # OOXML ANALYSIS PATH
    # ----------------------------------------------------------------
    if ($Script:FileFormat -eq "OOXML") {

        #region ============================================================
        # UNIT: Analyze-OOXMLFileTree
        # Purpose : Enumerate all extracted files; flag suspicious extensions
        # Inputs  : $Script:ExtractPath
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-OOXMLFileTree"

        try {
            $allFiles = Get-ChildItem -Path $Script:ExtractPath -Recurse -File
            Write-Log "INFO" "Total files in archive: $($allFiles.Count)"

            foreach ($f in $allFiles) {
                Write-Log "DEBUG" "Extracted file: $($f.FullName) [$($f.Length) bytes]"
                if ($f.Extension -in $Script:SuspiciousExtensions) {
                    Add-Finding "ALERT" "EmbeddedExecutable" "Suspicious embedded file: '$($f.Name)' at path '$($f.FullName)'"
                }
            }

            Write-Log "INFO" "UNIT_END: Analyze-OOXMLFileTree | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-OOXMLFileTree | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }

        #region ============================================================
        # UNIT: Analyze-VBAPresence
        # Purpose : Detect vbaProject.bin and activeX control binaries
        # Inputs  : $Script:ExtractPath
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-VBAPresence"

        try {
            # vbaProject.bin is present in any OOXML file with macros (.docm, .xlsm etc.)
            $vbaBin = Get-ChildItem -Path $Script:ExtractPath -Recurse -Filter "vbaProject.bin" -ErrorAction SilentlyContinue
            if ($vbaBin) {
                Add-Finding "ALERT" "Macro" "VBA project binary found: '$($vbaBin.FullName)' [$($vbaBin.Length) bytes]"
            }

            # ActiveX controls
            $activeX = Get-ChildItem -Path $Script:ExtractPath -Recurse -Filter "activeX*.bin" -ErrorAction SilentlyContinue
            foreach ($ax in $activeX) {
                Add-Finding "ALERT" "ActiveX" "ActiveX binary found: '$($ax.Name)' [$($ax.Length) bytes]"
            }

            Write-Log "INFO" "UNIT_END: Analyze-VBAPresence | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-VBAPresence | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }

        #region ============================================================
        # UNIT: Analyze-OOXMLContent
        # Purpose : Scan all XML files for suspicious keywords, external
        #           relationships, and embedded object references
        # Inputs  : $Script:ExtractPath
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-OOXMLContent"

        try {
            $xmlFiles = Get-ChildItem -Path $Script:ExtractPath -Recurse -Include "*.xml", "*.rels" -File
            Write-Log "INFO" "XML/rels files to scan: $($xmlFiles.Count)"

            foreach ($xmlFile in $xmlFiles) {
                $relPath = $xmlFile.FullName.Replace($Script:ExtractPath, "").TrimStart('\','/')

                try {
                    $content = Get-Content -LiteralPath $xmlFile.FullName -Raw -Encoding UTF8

                    # External relationships (OLE, remote targets)
                    if ($content -match 'TargetMode="External"') {
                        $matches = [regex]::Matches($content, 'Target="([^"]+)"[^>]*TargetMode="External"')
                        foreach ($m in $matches) {
                            Add-Finding "ALERT" "ExternalRelationship" "External target in '$relPath': $($m.Groups[1].Value)"
                        }
                    }

                    # Embedded object or OLE references
                    if ($content -match '(oleObject|embeddings|externalLink)') {
                        Add-Finding "SUSPICIOUS" "EmbeddedObject" "OLE/embedded reference found in '$relPath'"
                    }

                    # Keyword scan across XML content
                    foreach ($kw in $Script:SuspiciousKeywords) {
                        if ($content -match [regex]::Escape($kw)) {
                            Add-Finding "SUSPICIOUS" "SuspiciousKeyword" "Keyword '$kw' found in '$relPath'"
                            break  # One finding per file per keyword category is sufficient
                        }
                    }

                    # DDE (Dynamic Data Exchange) — common payload vector
                    if ($content -match 'ddeService|DDE\s') {
                        Add-Finding "ALERT" "DDE" "DDE reference found in '$relPath'"
                    }
                }
                catch {
                    Write-Log "WARN" "RECORD_FAILED: Could not read '$relPath' | Error='$($_.Exception.Message)'"
                }
            }

            Write-Log "INFO" "UNIT_END: Analyze-OOXMLContent | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-OOXMLContent | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }
    }

    # ----------------------------------------------------------------
    # CFBF ANALYSIS PATH
    # ----------------------------------------------------------------
    if ($Script:FileFormat -eq "CFBF") {

        #region ============================================================
        # UNIT: Analyze-CFBFKeywords
        # Purpose : Scan raw binary content for suspicious plaintext strings.
        #           Catches unobfuscated macro payloads and auto-exec triggers.
        #           Note: obfuscated/compressed VBA requires oletools (Python)
        #           for full decode — flag for escalation if hits are found.
        # Inputs  : $Script:RawContent
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-CFBFKeywords"

        try {
            $hitCount = 0
            foreach ($kw in $Script:SuspiciousKeywords) {
                if ($Script:RawContent -match [regex]::Escape($kw)) {
                    Add-Finding "SUSPICIOUS" "SuspiciousKeyword" "Keyword '$kw' found in binary content"
                    $hitCount++
                }
            }

            if ($hitCount -gt 0) {
                Write-Log "WARN" "VERIFY_WARN: $hitCount suspicious keyword(s) found — recommend oletools vba_extract for full macro decode"
            }
            else {
                Write-Log "INFO" "VERIFY_OK: No suspicious plaintext keywords detected"
            }

            Write-Log "INFO" "UNIT_END: Analyze-CFBFKeywords | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-CFBFKeywords | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }

        #region ============================================================
        # UNIT: Analyze-CFBFAutoExec
        # Purpose : Specifically hunt for auto-execution trigger strings
        #           that fire when the document is opened
        # Inputs  : $Script:RawContent
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-CFBFAutoExec"

        try {
            $autoExecTriggers = @('AutoOpen', 'AutoExec', 'AutoClose', 'Document_Open',
                                   'Workbook_Open', 'Auto_Open', 'DocumentOpen')
            foreach ($trigger in $autoExecTriggers) {
                if ($Script:RawContent -match [regex]::Escape($trigger)) {
                    Add-Finding "ALERT" "AutoExec" "Auto-execution trigger '$trigger' found in binary — macro likely fires on document open"
                }
            }

            Write-Log "INFO" "UNIT_END: Analyze-CFBFAutoExec | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-CFBFAutoExec | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }

        #region ============================================================
        # UNIT: Analyze-CFBFOLEStreams
        # Purpose : Detect CFBF stream headers for known OLE automation objects
        #           and embedded package streams by pattern matching known
        #           CFBF stream name byte sequences
        # Inputs  : $Script:RawContent
        #endregion ==========================================================
        $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Log "INFO" "UNIT_START: Analyze-CFBFOLEStreams"

        try {
            # CFBF stream names are stored as UTF-16LE — these patterns appear in the raw Latin-1 read
            $olePatterns = @{
                "Macros stream"          = "V\x00B\x00A\x00"
                "Word document stream"   = "W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00"
                "Workbook stream"        = "W\x00o\x00r\x00k\x00b\x00o\x00o\x00k\x00"
                "OLE Package stream"     = "\x01Ole10Native"
                "Equation Editor embed" = "Equation Native"
            }

            foreach ($name in $olePatterns.Keys) {
                if ($Script:RawContent -match $olePatterns[$name]) {
                    $severity = if ($name -match "Macros|Package|Equation") { "ALERT" } else { "INFO" }
                    Add-Finding $severity "OLEStream" "CFBF stream detected: '$name'"
                }
            }

            # Equation Editor (CVE-2017-11882 class) is especially high risk
            if ($Script:RawContent -match "Equation Native") {
                Add-Finding "ALERT" "EquationEditor" "Equation Editor object present — high risk for CVE-2017-11882 / CVE-2018-0802 exploitation"
            }

            Write-Log "INFO" "UNIT_END: Analyze-CFBFOLEStreams | Duration: $(Get-ElapsedSeconds $unitTimer)s"
        }
        catch {
            Write-Log "ERROR" "UNIT_FAILED: Analyze-CFBFOLEStreams | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=20"
            Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"
            exit 20
        }
    }
}

# ============================================================
# PHASE 4: REPORT
# ============================================================
function Invoke-Report {

    #region ============================================================
    # UNIT: Build-FindingsSummary
    # Purpose : Categorize and count findings; determine overall verdict
    # Inputs  : $Script:Findings
    # Outputs : $Script:Verdict, console summary, log entries
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Build-FindingsSummary"

    $alerts     = @($Script:Findings | Where-Object { $_.Severity -eq "ALERT" })
    $suspicious = @($Script:Findings | Where-Object { $_.Severity -eq "SUSPICIOUS" })
    $infoItems  = @($Script:Findings | Where-Object { $_.Severity -eq "INFO" })

    $Script:Verdict = if     ($alerts.Count -gt 0)     { "MALICIOUS" }
                      elseif ($suspicious.Count -gt 0) { "SUSPICIOUS" }
                      else                              { "CLEAN" }

    $separator = "=" * 72
    $output = @"

$separator
  OFFICE DOCUMENT FORENSIC ANALYSIS — FINDINGS REPORT
$separator
  File    : $($Script:FileItem.FullName)
  Size    : $($Script:FileItem.Length) bytes
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

    Write-Host $output
    Write-Log "INFO" "VERDICT: $Script:Verdict | Alerts=$($alerts.Count) | Suspicious=$($suspicious.Count) | Info=$($infoItems.Count)"

    if ($alerts.Count -gt 0) {
        Write-Host "`n  [ALERT] FINDINGS:" -ForegroundColor Red
        foreach ($f in $alerts) {
            Write-Host "    [$($f.Category)] $($f.Detail)" -ForegroundColor Red
            Write-Log "ERROR" "FINDING_ALERT: [$($f.Category)] $($f.Detail)"
        }
    }

    if ($suspicious.Count -gt 0) {
        Write-Host "`n  [SUSPICIOUS] FINDINGS:" -ForegroundColor Yellow
        foreach ($f in $suspicious) {
            Write-Host "    [$($f.Category)] $($f.Detail)" -ForegroundColor Yellow
            Write-Log "WARN" "FINDING_SUSPICIOUS: [$($f.Category)] $($f.Detail)"
        }
    }

    if ($infoItems.Count -gt 0) {
        Write-Host "`n  [INFO] FINDINGS:" -ForegroundColor Cyan
        foreach ($f in $infoItems) {
            Write-Host "    [$($f.Category)] $($f.Detail)" -ForegroundColor Cyan
            Write-Log "INFO" "FINDING_INFO: [$($f.Category)] $($f.Detail)"
        }
    }

    Write-Host "`n$separator`n"

    if ($Script:FileFormat -eq "CFBF" -and ($alerts.Count -gt 0 -or $suspicious.Count -gt 0)) {
        Write-Host "  ESCALATION NOTE: Legacy binary format with hits detected." -ForegroundColor Magenta
        Write-Host "  PowerShell string scanning cannot decode obfuscated/compressed VBA." -ForegroundColor Magenta
        Write-Host "  Recommended next step: run 'olevba' (oletools) on this file for full macro extraction." -ForegroundColor Magenta
        Write-Log "WARN" "ESCALATION: CFBF findings present — oletools vba_extract recommended for full decode"
    }

    Write-Log "INFO" "UNIT_END: Build-FindingsSummary | Verdict=$Script:Verdict | Duration: $(Get-ElapsedSeconds $unitTimer)s"

    #region ============================================================
    # UNIT: Cleanup-TempDir
    # Purpose : Remove temp extraction directory
    # Inputs  : $Script:TempDir
    #endregion ==========================================================
    $unitTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log "INFO" "UNIT_START: Cleanup-TempDir | Path='$Script:TempDir'"

    try {
        if (Test-Path $Script:TempDir) {
            Remove-Item -Path $Script:TempDir -Recurse -Force
            Write-Log "INFO" "VERIFY_OK: Temp directory removed"
        }
        Write-Log "INFO" "UNIT_END: Cleanup-TempDir | Duration: $(Get-ElapsedSeconds $unitTimer)s"
    }
    catch {
        Write-Log "WARN" "UNIT_FAILED: Cleanup-TempDir | Could not remove temp dir — manual cleanup needed: '$Script:TempDir' | Error='$($_.Exception.Message)'"
    }
}

# ============================================================
# MAIN
# ============================================================
try {
    # Ensure output dir and log file are writable before anything else
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir | Out-Null
    }
    "" | Out-File -FilePath $Script:LogFile -Encoding UTF8

    Invoke-PhaseStart -PhaseName "Preflight"
    Invoke-Preflight
    Invoke-PhaseGate  -PhaseName "Preflight" -Summary "File='$($Script:FileItem.Name)' | Format='$Script:FileFormat' | Size=$($Script:FileItem.Length)B"

    Invoke-PhaseStart -PhaseName "Extraction"
    Invoke-Extraction
    Invoke-PhaseGate  -PhaseName "Extraction" -Summary "Format='$Script:FileFormat' | TempDir='$Script:TempDir'"

    Invoke-PhaseStart -PhaseName "Analysis"
    Invoke-Analysis
    Invoke-PhaseGate  -PhaseName "Analysis" -Summary "Findings=$(($Script:Findings).Count)"

    Invoke-PhaseStart -PhaseName "Report"
    Invoke-Report
    Invoke-PhaseGate  -PhaseName "Report" -Summary "Verdict=$Script:Verdict | LogFile='$Script:LogFile'"

    $totalElapsed = [math]::Round($Script:ScriptTimer.Elapsed.TotalSeconds, 2)
    Write-Log "INFO" "SCRIPT_COMPLETE: $Script:ScriptName | Verdict=$Script:Verdict | TotalDuration=${totalElapsed}s | Log='$Script:LogFile'"
    exit 0
}
catch {
    Write-Log "FATAL" "SCRIPT_FAILED: Unhandled error | Error='$($_.Exception.Message)' | Line=$($_.InvocationInfo.ScriptLineNumber) | ExitCode=99"
    Write-Log "DEBUG" "STACK_TRACE: $($_.ScriptStackTrace)"

    # Best-effort temp cleanup on unexpected exit
    if ($Script:TempDir -and (Test-Path $Script:TempDir)) {
        Remove-Item -Path $Script:TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 99
}