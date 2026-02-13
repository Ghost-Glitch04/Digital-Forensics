<#
.SYNOPSIS
    Downloads and installs Chainsaw for Windows Event Log forensic analysis
.DESCRIPTION
    Compatible with SentinelOne Remote Shell (Powershell 5.1)
    Downloads Chainsaw, extracts files, and performs cleanup
.NOTES
    Author: Ghost-Glitch04
    Version: 1.0
    Date: 2026-02-13
#>

# Define Variables
$url = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.13.1/chainsaw_all_platforms+rules+examples.zip"
$zip = "$env:TEMP\chainsaw.zip"
$dir = "$env:TEMP\chainsaw"
$summaryLog = "$env:TEMP\chainsaw_summary.txt"
$csVersion = "chainsaw_x86_64-pc-windows-msvc.exe"

# Initialize summary log
"[*] Chainsaw Installation - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | 
    Out-File $summaryLog -Force
"[*] Host: $env:COMPUTERNAME" | Out-File $summaryLog -Append
"[*] User: $env:USERNAME" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append

# Test URL connectivity
Write-Host "[*] Testing URL connectivity..."
try {
    $test = Invoke-WebRequest -Uri $url -Method Head `
        -UseBasicParsing -TimeoutSec 10
    if ($test.StatusCode -eq 200) {
        Write-Host "[OK] URL validated - Status: 200"
        "[OK] URL validation successful" | Out-File $summaryLog -Append
    }
} catch {
    $errorMsg = "[!] URL test failed: $($_.Exception.Message)"
    Write-Host $errorMsg
    $errorMsg | Out-File $summaryLog -Append
    Get-Content $summaryLog
    exit 1
}

# Download Chainsaw
Write-Host "[*] Downloading Chainsaw..."
try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    if (Test-Path $zip) {
        $size = [math]::Round((Get-Item $zip).Length / 1MB, 2)
        Write-Host "[OK] Download complete - $size MB"
        "[OK] Download complete - $size MB" | Out-File $summaryLog -Append
    }
} catch {
    $errorMsg = "[!] Download failed: $($_.Exception.Message)"
    Write-Host $errorMsg
    $errorMsg | Out-File $summaryLog -Append
    Get-Content $summaryLog
    exit 1
}

# Extract archive
Write-Host "[*] Extracting files..."
try {
    Expand-Archive -Path $zip -DestinationPath $dir -Force
    
    # Search for chainsaw.exe (handles nested directories)
    $chainsawExe = Get-ChildItem -Path $dir -Filter $csVersion `
        -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($chainsawExe) {
        # Update $dir to point to the actual location of chainsaw.exe
        $dir = $chainsawExe.DirectoryName
        $logsDir = "$dir\logs"
        $wevCopyDir = "$dir\WEV_COPY"
        Write-Host "[OK] Extraction complete"
        Write-Host "[*] Chainsaw found at: $dir"
        "[OK] Extraction complete" | Out-File $summaryLog -Append
        "[*] Chainsaw location: $dir" | Out-File $summaryLog -Append
    } else {
        throw "chainsaw.exe not found after extraction"
    }
} catch {
    $errorMsg = "[!] Extraction failed: $($_.Exception.Message)"
    Write-Host $errorMsg
    $errorMsg | Out-File $summaryLog -Append
    Get-Content $summaryLog
    exit 1
}    

# File Cleanup
Write-Host "[*] Cleaning up temporary files..."
try {
    if (Test-Path $zip) {
        Remove-Item $zip -Force -ErrorAction Stop
        if (-not (Test-Path $zip)) {
            Write-Host "[OK] Zip file removed"
            "[OK] Zip file removed" | Out-File $summaryLog -Append
        }
    } else {
        Write-Host "[OK] Zip file already removed"
        "[OK] Zip file already removed" | Out-File $summaryLog -Append
    }
} catch {
    $warnMsg = "[!] Warning: Could not remove zip file: $($_.Exception.Message)"
    Write-Host $warnMsg
    $warnMsg | Out-File $summaryLog -Append
}
"" | Out-File $summaryLog -Append

# Organize log files
Write-Host "[*] Organizing log files..."
try {
    # Check if logs directory exists, create if not
    if (-not (Test-Path $logsDir)) {
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Created logs directory: $logsDir"
    } else {
        Write-Host "[OK] Logs directory already exists"
    }
    
    # Move summary log to logs directory
    $newSummaryPath = "$logsDir\chainsaw_summary.txt"
    if (Test-Path $summaryLog) {
        Move-Item -Path $summaryLog -Destination $newSummaryPath -Force
        $summaryLog = $newSummaryPath
        Write-Host "[OK] Log files moved to: $logsDir"
    }
} catch {
    $warnMsg = "[!] Warning: Could not organize logs: $($_.Exception.Message)"
    Write-Host $warnMsg
}

# Create WEV_COPY directory
Write-Host "[*] Creating WEV_COPY directory..."
try {
    # Check if WEV_COPY directory exists
    if (-not (Test-Path $wevCopyDir)) {
        New-Item -Path $wevCopyDir -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Created WEV_COPY directory"
        
        # Validate directory was created
        if (Test-Path $wevCopyDir) {
            Write-Host "[OK] Validated WEV_COPY directory exists: $wevCopyDir"
            "[OK] WEV_COPY directory created and validated" | Out-File $summaryLog -Append
        } else {
            throw "WEV_COPY directory validation failed"
        }
    } else {
        Write-Host "[OK] WEV_COPY directory already exists"
        "[OK] WEV_COPY directory already exists" | Out-File $summaryLog -Append
    }
} catch {
    $warnMsg = "[!] Warning: Could not create WEV_COPY directory: $($_.Exception.Message)"
    Write-Host $warnMsg
    $warnMsg | Out-File $summaryLog -Append
}
"" | Out-File $summaryLog -Append

# Generate summary
"[*] Installation Complete" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] File Locations:" | Out-File $summaryLog -Append
"    - Chainsaw executable: $dir\$csVersion" | Out-File $summaryLog -Append
"    - Chainsaw directory: $dir" | Out-File $summaryLog -Append
"    - Logs directory: $logsDir" | Out-File $summaryLog -Append
"    - WEV_COPY directory: $wevCopyDir" | Out-File $summaryLog -Append
"    - Summary log: $summaryLog" | Out-File $summaryLog -Append
"    - Zip file: Automatically removed" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] Usage Example:" | Out-File $summaryLog -Append
"    & '$dir\$csVersion' hunt C:\Windows\System32\winevt\Logs --output results.csv" | 
    Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] Manual Cleanup:" | Out-File $summaryLog -Append
"    Remove-Item '$dir' -Recurse -Force" | 
    Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append

# Display summary
Write-Host ""
Write-Host "[*] Installation Summary:"
Get-Content $summaryLog
Write-Host ""
Write-Host "[OK] Chainsaw is ready to use at: $dir\$csVersion"