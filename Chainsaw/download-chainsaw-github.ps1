<#
.SYNOPSIS
    Downloads and runs Chainsaw for Windows Event Log forensic analysis
.DESCRIPTION
    Compatible with SentinelOne Remote Shell (Powershell 5.1)
    Downloads Chainsaw, performs hunt analysis, and outputs results
.NOTES
    Author: Ghost-Glitch04
    Version: 1.0
    Date: 2026-02-13
#>

# Define Variables
$url = "https://github.com/WithSecureLabs/chainsaw/releases/download/v2.13.1/chainsaw_x86_64-pc-windows-msvc.zip"
$zip = "$env:TEMP\chainsaw.zip"
$dir = "$env:TEMP\chainsaw"
$logFile = "$env:TEMP\chainsaw_hunt_results.csv"
$summaryLog = "$env:TEMP\chainsaw_summary.txt"

# Initialize summary log
"[*] Chainsaw Analysis - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | 
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
    $chainsawExe = Get-ChildItem -Path $dir -Filter "chainsaw.exe" `
        -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($chainsawExe) {
        # Update $dir to point to the actual location of chainsaw.exe
        $dir = $chainsawExe.DirectoryName
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

# Generate summary
"[*] File Locations:" | Out-File $summaryLog -Append
"    - Chainsaw: $dir\chainsaw.exe" | Out-File $summaryLog -Append
"    - Results: $logFile" | Out-File $summaryLog -Append
"    - Summary: $summaryLog" | Out-File $summaryLog -Append
"    - Zip file: Automatically removed" | Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] Manual Cleanup Required:" | Out-File $summaryLog -Append
"    - Chainsaw directory: Remove-Item '$dir' -Recurse -Force" | 
    Out-File $summaryLog -Append
"    - Results files: Remove-Item '$logFile','$summaryLog' -Force" | 
    Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append
"[*] Quick Actions:" | Out-File $summaryLog -Append
"    - View results: Get-Content '$logFile'" | Out-File $summaryLog -Append
"    - View summary: Get-Content '$summaryLog'" | 
    Out-File $summaryLog -Append
"" | Out-File $summaryLog -Append

# Display summary
Write-Host ""
Write-Host "[*] Analysis Summary:"
Get-Content $summaryLog

Write-Host ""
Write-Host "[*] First 20 lines of results:"
Get-Content $logFile -TotalCount 20