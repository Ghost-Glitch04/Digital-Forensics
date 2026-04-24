<#
.SYNOPSIS
    Detect drift between integration-tracking markers and .integration-map.md.

.DESCRIPTION
    Scans source files for <CONTRACT> and <USES> markers, compares against
    the .integration-map.md entries, and reports drift in both directions
    per the Integration Grep Protocol Q6 queries defined in
    reference/integration-tracking.md.

    Recognizes the '# DRIFT-EXPECTED:' escape hatch comment at the top of
    the map file; when present, drift findings are downgraded from ERROR
    to WARN and the script exits 0 instead of 40.

.PARAMETER ProjectRoot
    Root directory of the project. Defaults to the current directory.

.PARAMETER MapPath
    Path to the Integration Map file. Defaults to
    $ProjectRoot/.integration-map.md.

.PARAMETER StopAfterPhase
    Stop cleanly at the end of the named phase. Useful for debugging the
    verify script itself. Valid values: Preflight, Collection, Analysis,
    Output, None.

.PARAMETER DebugMode
    Promote DEBUG log entries to the console. File logging is unaffected.

.EXAMPLE
    ./verify-integrations.ps1

.EXAMPLE
    ./verify-integrations.ps1 -ProjectRoot /path/to/project -DebugMode

.NOTES
    Author  : Ghost
    Created : 2026-04-22
    Version : 1.0.0
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Get-Location).Path,

    [string]$MapPath,

    [ValidateSet("Preflight","Collection","Analysis","Output","None")]
    [string]$StopAfterPhase = "None",

    [switch]$DebugMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# ERROR CODE REFERENCE
# 0  = Success (no drift, or drift downgraded via DRIFT-EXPECTED)
# 10 = Map file not found
# 11 = Map file unreadable
# 20 = Processing failure (malformed marker, unparseable line)
# 40 = Drift detected (code-ahead-of-map, map-ahead-of-code, or version mismatch)
# 99 = Unhandled error
# ============================================================

# ============================================================
# CONFIGURATION
# ============================================================
$script:SourceExtensions = @('*.ps1', '*.psm1', '*.sh', '*.bash', '*.py')

# Marker patterns — correspond to invariants I1, I3, I4, I5 in integration-tracking.md
$script:ContractPattern      = '<CONTRACT\s+id="([^"]+)"\s+version="(\d+)"\s+scope="([^"]+)"'
$script:UsesPattern          = '<USES\s+contract="([^"]+)"\s+version="(\d+)"(?:\s+fields="([^"]+)")?'
$script:MapContractPattern   = '^##\s+<contract:([^>]+)>'
$script:MapConsumerPattern   = '^-\s+CONSUMER:\s+([^:]+):(\d+)'
$script:DriftExpectedPattern = '^#\s+DRIFT-EXPECTED:'

if (-not $MapPath) { $MapPath = Join-Path $ProjectRoot '.integration-map.md' }

$script:LogDir     = Join-Path $ProjectRoot 'logs'
$script:Timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:LogFile    = Join-Path $script:LogDir "verify-integrations-$($script:Timestamp).log"

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}

# ============================================================
# HELPERS
# ============================================================

function Write-Log {
    param(
        [Parameter(Mandatory)][ValidateSet('DEBUG','INFO','WARN','ERROR','FATAL')][string]$Level,
        [Parameter(Mandatory)][string]$Prefix,
        [string]$Message = ""
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = if ($Message) { "[$ts] [$Level] ${Prefix}: $Message" } else { "[$ts] [$Level] ${Prefix}" }

    Add-Content -Path $script:LogFile -Value $line

    $showConsole = ($Level -ne 'DEBUG') -or $DebugMode
    if ($showConsole) {
        switch ($Level) {
            'ERROR' { Write-Host $line -ForegroundColor Red }
            'FATAL' { Write-Host $line -ForegroundColor Red }
            'WARN'  { Write-Host $line -ForegroundColor Yellow }
            default { Write-Host $line }
        }
    }
}

function Invoke-PhaseStart {
    param([string]$PhaseName)
    $script:CurrentPhase = $PhaseName
    $script:PhaseStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Log -Level INFO -Prefix PHASE_START -Message $PhaseName
}

function Invoke-PhaseEnd {
    param([string]$Summary = "")
    $duration = [math]::Round($script:PhaseStopwatch.Elapsed.TotalSeconds, 2)
    if ($Summary) {
        Write-Log -Level INFO -Prefix PHASE_SUMMARY -Message "$script:CurrentPhase | $Summary"
    }
    Write-Log -Level INFO -Prefix PHASE_END -Message "$script:CurrentPhase | Phase Duration: ${duration}s"
}

function Invoke-PhaseGate {
    param([string]$PhaseName)
    if ($StopAfterPhase -eq $PhaseName) {
        $total = [math]::Round($script:ScriptStopwatch.Elapsed.TotalSeconds, 2)
        Write-Log -Level INFO -Prefix PHASE_GATE -Message "Stopping cleanly after phase '$PhaseName' | Total Duration: ${total}s"
        exit 0
    }
}

# ============================================================
# UNITS
# ============================================================

# <CONTRACT id="Read-MapFile" version="1" scope="internal">
#   PARAMS:
#     Path  [string]  required  absolute path to .integration-map.md
#   RETURNS: [hashtable]
#     Contracts       [string[]]    contract ids from `## <contract:NAME>` headings
#     Consumers       [object[]]    parsed CONSUMER entries (Path, Line)
#     DriftExpected   [bool]        true if `# DRIFT-EXPECTED:` is present at top
#   THROWS: terminates with exit 10 (file missing) or 11 (unreadable)
# </CONTRACT>
# ============================================================
# UNIT: Read-MapFile
# Purpose : Parse the Integration Map into a structured object
# Inputs  : Path to .integration-map.md
# Outputs : Hashtable with Contracts, Consumers, DriftExpected
# Depends : None
# ============================================================
function Read-MapFile {
    param([string]$Path)

    Write-Log -Level INFO -Prefix UNIT_START -Message "Read-MapFile | path=$Path"

    if (-not (Test-Path $Path)) {
        Write-Log -Level ERROR -Prefix UNIT_FAILED -Message "Read-MapFile | path=$Path | reason=file_not_found | exit=10"
        exit 10
    }

    try {
        $lines = Get-Content -Path $Path -ErrorAction Stop
    } catch {
        Write-Log -Level ERROR -Prefix UNIT_FAILED -Message "Read-MapFile | path=$Path | reason=$($_.Exception.Message) | exit=11"
        exit 11
    }

    $contracts     = [System.Collections.Generic.List[string]]::new()
    $consumers     = [System.Collections.Generic.List[object]]::new()
    $driftExpected = $false

    foreach ($line in $lines) {
        if ($line -match $script:DriftExpectedPattern) {
            $driftExpected = $true
            Write-Log -Level DEBUG -Prefix DRIFT_EXPECTED_DETECTED -Message "line=$line"
        }
        if ($line -match $script:MapContractPattern) {
            $contracts.Add($matches[1].Trim())
        }
        if ($line -match $script:MapConsumerPattern) {
            $consumers.Add([PSCustomObject]@{
                Path = $matches[1].Trim()
                Line = [int]$matches[2]
            })
        }
    }

    Write-Log -Level INFO -Prefix UNIT_END -Message "Read-MapFile | contracts=$($contracts.Count) | consumers=$($consumers.Count) | drift_expected=$driftExpected"

    return @{
        Contracts     = $contracts
        Consumers     = $consumers
        DriftExpected = $driftExpected
    }
}

# ============================================================
# UNIT: Get-MarkersFromSource
# Purpose : Scan source files for CONTRACT and USES markers
# Inputs  : Root directory to scan
# Outputs : Hashtable with Contracts and Uses lists
# Depends : None
# ============================================================
function Get-MarkersFromSource {
    param([string]$Root)

    Write-Log -Level INFO -Prefix UNIT_START -Message "Get-MarkersFromSource | root=$Root"

    $contracts = [System.Collections.Generic.List[object]]::new()
    $uses      = [System.Collections.Generic.List[object]]::new()

    # Exclude logs/ and .git/ to match Bash helper's find filter and avoid
    # self-reference noise (the script's own log files would otherwise be
    # scanned on the next run).
    $sourceFiles = foreach ($ext in $script:SourceExtensions) {
        Get-ChildItem -Path $Root -Filter $ext -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/](logs|\.git)[\\/]' }
    }

    foreach ($file in $sourceFiles) {
        try {
            $lines = Get-Content -Path $file.FullName -ErrorAction Stop
        } catch {
            Write-Log -Level WARN -Prefix VERIFY_WARN -Message "Skipped unreadable file | path=$($file.FullName) | reason=$($_.Exception.Message)"
            continue
        }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $lineNum = $i + 1

            if ($line -match $script:ContractPattern) {
                $contracts.Add([PSCustomObject]@{
                    Id      = $matches[1]
                    Version = [int]$matches[2]
                    Scope   = $matches[3]
                    File    = $file.FullName
                    Line    = $lineNum
                })
            }
            if ($line -match $script:UsesPattern) {
                $uses.Add([PSCustomObject]@{
                    Contract = $matches[1]
                    Version  = [int]$matches[2]
                    Fields   = if ($matches.Count -gt 3 -and $matches[3]) { $matches[3] } else { $null }
                    File     = $file.FullName
                    Line     = $lineNum
                })
            }
        }
    }

    Write-Log -Level INFO -Prefix UNIT_END -Message "Get-MarkersFromSource | contracts=$($contracts.Count) | uses=$($uses.Count) | files_scanned=$($sourceFiles.Count)"

    return @{ Contracts = $contracts; Uses = $uses }
}

# ============================================================
# UNIT: Find-Drift
# Purpose : Compute drift in both directions and version mismatches
# Inputs  : MapState hashtable, MarkerState hashtable
# Outputs : Array of drift records (Direction, ContractId, Location, Detail)
# Depends : Read-MapFile, Get-MarkersFromSource
# ============================================================
function Find-Drift {
    param(
        [hashtable]$MapState,
        [hashtable]$MarkerState
    )

    Write-Log -Level INFO -Prefix UNIT_START -Message "Find-Drift"

    $drift = [System.Collections.Generic.List[object]]::new()

    # Direction 1: code-ahead-of-map — contract ids referenced in code but not in map
    $codeContractIds = @(
        $MarkerState.Contracts | ForEach-Object { $_.Id }
        $MarkerState.Uses      | ForEach-Object { $_.Contract }
    ) | Select-Object -Unique

    $mapContractSet = @{}
    foreach ($c in $MapState.Contracts) { $mapContractSet[$c] = $true }

    foreach ($id in $codeContractIds) {
        if (-not $mapContractSet.ContainsKey($id)) {
            $drift.Add([PSCustomObject]@{
                Direction  = 'code_ahead_of_map'
                ContractId = $id
                Location   = '(code referenced, map missing)'
                Detail     = 'Contract referenced in source but no `## <contract:NAME>` heading in map'
            })
        }
    }

    # Direction 2: map-ahead-of-code — CONSUMER entries pointing to non-existent files
    foreach ($consumer in $MapState.Consumers) {
        $fullPath = if ([System.IO.Path]::IsPathRooted($consumer.Path)) {
            $consumer.Path
        } else {
            Join-Path $ProjectRoot $consumer.Path
        }
        if (-not (Test-Path $fullPath)) {
            $drift.Add([PSCustomObject]@{
                Direction  = 'map_ahead_of_code'
                ContractId = '(any)'
                Location   = "$($consumer.Path):$($consumer.Line)"
                Detail     = 'CONSUMER entry points to file that does not exist'
            })
        }
    }

    # Direction 3: version mismatch — USES marker version does not match a contract's current version
    $codeContractVersions = @{}
    foreach ($c in $MarkerState.Contracts) { $codeContractVersions[$c.Id] = $c.Version }

    foreach ($u in $MarkerState.Uses) {
        if ($codeContractVersions.ContainsKey($u.Contract)) {
            $currentVersion = $codeContractVersions[$u.Contract]
            if ($u.Version -ne $currentVersion) {
                $drift.Add([PSCustomObject]@{
                    Direction  = 'version_mismatch'
                    ContractId = $u.Contract
                    Location   = "$($u.File):$($u.Line)"
                    Detail     = "USES version=$($u.Version) but contract is now version=$currentVersion"
                })
            }
        }
    }

    Write-Log -Level INFO -Prefix UNIT_END -Message "Find-Drift | drift_count=$($drift.Count)"
    return ,$drift
}

# ============================================================
# MAIN
# ============================================================

$script:ScriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

$UserName = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
$HostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

Write-Log -Level INFO -Prefix SCRIPT_START -Message "verify-integrations.ps1 | User: $UserName | Host: $HostName"
Write-Log -Level INFO -Prefix ENV_SNAPSHOT -Message "pwsh=$($PSVersionTable.PSVersion) | os=$([System.Runtime.InteropServices.RuntimeInformation]::OSDescription) | cwd=$ProjectRoot"
Write-Log -Level INFO -Prefix PARAMS -Message "ProjectRoot=$ProjectRoot | MapPath=$MapPath | StopAfterPhase=$StopAfterPhase | DebugMode=$DebugMode"

if ($DebugMode) { Write-Log -Level INFO -Prefix DEBUG_MODE_ACTIVE -Message "" }

try {
    # --- Phase 1: Preflight ---
    Invoke-PhaseStart -PhaseName "Preflight"
    if (-not (Test-Path $ProjectRoot)) {
        Write-Log -Level FATAL -Prefix SCRIPT_FAILED -Message "ProjectRoot not found | path=$ProjectRoot | exit=10"
        exit 10
    }
    Write-Log -Level INFO -Prefix VERIFY_OK -Message "ProjectRoot exists | path=$ProjectRoot"
    Invoke-PhaseEnd -Summary "ProjectRoot: verified"
    Invoke-PhaseGate -PhaseName "Preflight"

    # --- Phase 2: Collection ---
    Invoke-PhaseStart -PhaseName "Collection"
    $mapState    = Read-MapFile -Path $MapPath
    $markerState = Get-MarkersFromSource -Root $ProjectRoot
    Invoke-PhaseEnd -Summary "Map contracts: $($mapState.Contracts.Count) | Code contracts: $($markerState.Contracts.Count) | Code uses: $($markerState.Uses.Count)"
    Invoke-PhaseGate -PhaseName "Collection"

    # --- Phase 3: Analysis ---
    Invoke-PhaseStart -PhaseName "Analysis"
    $drift = Find-Drift -MapState $mapState -MarkerState $markerState
    Invoke-PhaseEnd -Summary "Drift findings: $($drift.Count) | DRIFT-EXPECTED active: $($mapState.DriftExpected)"
    Invoke-PhaseGate -PhaseName "Analysis"

    # --- Phase 4: Output ---
    Invoke-PhaseStart -PhaseName "Output"
    $driftLevel = if ($mapState.DriftExpected) { 'WARN' } else { 'ERROR' }

    foreach ($d in $drift) {
        Write-Log -Level $driftLevel -Prefix CONTRACT_DRIFT `
            -Message "direction=$($d.Direction) | contract_id=$($d.ContractId) | location=$($d.Location) | detail=$($d.Detail)"
    }

    if ($drift.Count -eq 0) {
        Write-Log -Level INFO -Prefix INTEGRATION_MAP_UPDATED -Message "No drift detected | contracts=$($mapState.Contracts.Count) | consumers=$($mapState.Consumers.Count)"
    } elseif ($mapState.DriftExpected) {
        Write-Log -Level WARN -Prefix VERIFY_WARN -Message "Drift detected but DRIFT-EXPECTED active | drift_count=$($drift.Count)"
    } else {
        Write-Log -Level ERROR -Prefix VERIFY_FAILED -Message "Drift detected | drift_count=$($drift.Count) | exit=40"
    }
    Invoke-PhaseEnd -Summary "Drift reported: $($drift.Count) at level $driftLevel"

    $totalDuration = [math]::Round($script:ScriptStopwatch.Elapsed.TotalSeconds, 2)

    if ($drift.Count -gt 0 -and -not $mapState.DriftExpected) {
        Write-Log -Level INFO -Prefix SCRIPT_COMPLETE -Message "Total Duration: ${totalDuration}s | exit=40"
        exit 40
    } else {
        Write-Log -Level INFO -Prefix SCRIPT_COMPLETE -Message "Total Duration: ${totalDuration}s | exit=0"
        exit 0
    }

} catch {
    $totalDuration = [math]::Round($script:ScriptStopwatch.Elapsed.TotalSeconds, 2)
    Write-Log -Level DEBUG -Prefix STACK_TRACE -Message $_.ScriptStackTrace
    Write-Log -Level FATAL -Prefix SCRIPT_FAILED -Message "$($_.Exception.Message) | Total Duration: ${totalDuration}s | exit=99"
    exit 99
}
