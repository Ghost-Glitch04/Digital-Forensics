<#
.SYNOPSIS
    Copies Windows Event Viewer logs for forensic analysis
.DESCRIPTION
    Compatible with SentinelOne Remote Shell (Powershell 5.1)
    Copies event log files from system location to target directory with
    comprehensive error handling, logging, and validation
.NOTES
    Author: Ghost-Glitch04
    Version: 2.0
    Date: 2026-02-13
#>

# Define Variables
$timestamp     = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$sourceDir     = "C:\Windows\System32\winevt\Logs"
$csRoot        = "$env:TEMP\chainsaw"
$targetDir     = "$csRoot\chainsaw\WEV_COPY"
$logDir        = "$csRoot\chainsaw\logs"
$summaryLog    = "$env:TEMP\evtx_copy_summary_$timestamp.txt"

# Event logs to copy (can be extended)
$logsToCopy = @(
    "Application.evtx",
    "Security.evtx",
    "Setup.evtx",
    "System.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
)

# Initialize counters
$successCount = 0
$failCount = 0
$skippedCount = 0
$totalSize = 0

# Initialize summary log
"[*] Event Log Copy Operation - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | 
    Out-File $summaryLog -Force
"[*] Host: $env:COMPUTERNAME" | Out-File $summaryLog -Append
"[*] User: $env:USERNAME" | Out-File $summaryLog -Append
"[*] Source: $sourceDir" | Out-File $summaryLog -Append
"[*] Target: $targetDir" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append

# Reusable Function: Validate Directory
function Test-DirectoryAccess {
    param([string]$Path, [string]$Description)
    
    Write-Host "[*] Validating $Description..."
    
    if (-not (Test-Path $Path)) {
        Write-Host "[!] $Description does not exist: $Path" -ForegroundColor Red
        "[!] $Description not found: $Path" | Out-File $summaryLog -Append
        return $false
    }
    
    try {
        $null = Get-ChildItem $Path -ErrorAction Stop
        Write-Host "[OK] $Description accessible"
        "[OK] $Description validated" | Out-File $summaryLog -Append
        return $true
    } catch {
        Write-Host "[!] Cannot access $Description : $($_.Exception.Message)" -ForegroundColor Red
        "[!] Access denied: $Description" | Out-File $summaryLog -Append
        return $false
    }
}

# Reusable Function: Create Directory with Validation
function New-DirectoryWithValidation {
    param([string]$Path, [string]$Description)
    
    Write-Host "[*] Checking $Description..."
    
    if (Test-Path $Path) {
        Write-Host "[OK] $Description already exists"
        "[OK] $Description found" | Out-File $summaryLog -Append
        return $true
    }
    
    try {
        New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        
        if (Test-Path $Path) {
            Write-Host "[OK] Created $Description"
            "[OK] Created $Description : $Path" | Out-File $summaryLog -Append
            return $true
        } else {
            throw "Directory creation validation failed"
        }
    } catch {
        Write-Host "[!] Failed to create $Description : $($_.Exception.Message)" -ForegroundColor Red
        "[!] Failed to create $Description" | Out-File $summaryLog -Append
        return $false
    }
}

# Reusable Function: Copy File with Retry Logic
function Copy-FileWithRetry {
    param(
        [string]$Source,
        [string]$Destination,
        [int]$MaxRetries = 3
    )
    
    $fileName = Split-Path $Source -Leaf
    $attempt = 0
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            if (-not (Test-Path $Source)) {
                Write-Host "    [SKIP] $fileName - File not found" -ForegroundColor Yellow
                return "SKIP"
            }
            
            $fileSize = [math]::Round((Get-Item $Source).Length / 1MB, 2)
            Write-Host "    [*] Copying $fileName ($fileSize MB)..." -NoNewline
            
            Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
            
            # Verify copy
            $destFile = Join-Path $Destination $fileName
            if (Test-Path $destFile) {
                Write-Host " [OK]" -ForegroundColor Green
                return @{Status="SUCCESS"; Size=$fileSize}
            } else {
                throw "File verification failed"
            }
            
        } catch {
            if ($attempt -lt $MaxRetries) {
                Write-Host " [RETRY $attempt/$MaxRetries]" -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            } else {
                Write-Host " [FAIL]" -ForegroundColor Red
                Write-Host "    [!] Error: $($_.Exception.Message)" -ForegroundColor Red
                return @{Status="FAIL"; Error=$_.Exception.Message}
            }
        }
    }
}

# Validate source directory
"" | Out-File $summaryLog -Append
if (-not (Test-DirectoryAccess -Path $sourceDir -Description "Source directory")) {
    Write-Host "[!] Cannot proceed without access to source directory" -ForegroundColor Red
    "[!] Operation aborted - Source directory inaccessible" | Out-File $summaryLog -Append
    Get-Content $summaryLog
    exit 1
}

# Create target directory
"" | Out-File $summaryLog -Append
if (-not (New-DirectoryWithValidation -Path $targetDir -Description "Target directory")) {
    Write-Host "[!] Cannot proceed without target directory" -ForegroundColor Red
    "[!] Operation aborted - Cannot create target directory" | Out-File $summaryLog -Append
    Get-Content $summaryLog
    exit 1
}

# Copy event logs
Write-Host ""
Write-Host "[*] Copying event log files..." -ForegroundColor Cyan
"" | Out-File $summaryLog -Append
"[*] Copy Operations:" | Out-File $summaryLog -Append

foreach ($logFile in $logsToCopy) {
    $sourcePath = Join-Path $sourceDir $logFile
    $result = Copy-FileWithRetry -Source $sourcePath -Destination $targetDir
    
    if ($result -is [hashtable]) {
        if ($result.Status -eq "SUCCESS") {
            $successCount++
            $totalSize += $result.Size
            "    [OK] $logFile - $($result.Size) MB" | Out-File $summaryLog -Append
        } elseif ($result.Status -eq "FAIL") {
            $failCount++
            "    [FAIL] $logFile - $($result.Error)" | Out-File $summaryLog -Append
        }
    } elseif ($result -eq "SKIP") {
        $skippedCount++
        "    [SKIP] $logFile - Not found" | Out-File $summaryLog -Append
    }
}

# Move summary log to logs directory if it exists
if (Test-Path $logDir) {
    try {
        $newSummaryPath = "$logDir\evtx_copy_summary_$timestamp.txt"
        Move-Item -Path $summaryLog -Destination $newSummaryPath -Force -ErrorAction Stop
        $summaryLog = $newSummaryPath
    } catch {
        # Keep summary in TEMP if move fails
    }
}

# Generate summary
"" | Out-File $summaryLog -Append
"[*] Operation Summary:" | Out-File $summaryLog -Append
"    - Total logs processed: $($logsToCopy.Count)" | Out-File $summaryLog -Append
"    - Successfully copied: $successCount" | Out-File $summaryLog -Append
"    - Failed: $failCount" | Out-File $summaryLog -Append
"    - Skipped (not found): $skippedCount" | Out-File $summaryLog -Append
"    - Total size copied: $totalSize MB" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] File Locations:" | Out-File $summaryLog -Append
"    - Copied logs: $targetDir" | Out-File $summaryLog -Append
"    - Summary log: $summaryLog" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append

if ($failCount -gt 0) {
    "[!] WARNING: Some files failed to copy. Review errors above." | 
        Out-File $summaryLog -Append
}

# Display summary
Write-Host ""
Write-Host "[*] Copy Operation Summary:" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Get-Content $summaryLog | Select-Object -Skip 6
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if ($failCount -eq 0 -and $successCount -gt 0) {
    Write-Host "[OK] All available event logs copied successfully!" -ForegroundColor Green
    Write-Host "[*] Location: $targetDir" -ForegroundColor Green
} elseif ($successCount -gt 0) {
    Write-Host "[!] Copy completed with some failures" -ForegroundColor Yellow
    Write-Host "[*] Location: $targetDir" -ForegroundColor Yellow
} else {
    Write-Host "[!] Copy operation failed - No files copied" -ForegroundColor Red
}