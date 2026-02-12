<#
.SYNOPSIS
    Recursively searches a directory for files matching a specific SHA256 hash and deletes them.

.DESCRIPTION
    Starting from the specified target directory, this script recursively computes the SHA256
    hash of each file and deletes any file whose hash matches the provided SHA256 value.

.PARAMETER TargetDirectory
    The root directory to begin searching.

.PARAMETER SHA256Hash
    The SHA256 hash to match against files.

.EXAMPLE
    .\Remove-FileByHash.ps1 -TargetDirectory "C:\Users\Public" -SHA256Hash "ABC123..."

.EXAMPLE
    .\Remove-FileByHash.ps1 -TargetDirectory "C:\Temp" -SHA256Hash "ABC123..."
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$TargetDirectory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[A-Fa-f0-9]{64}$")]
    [string]$SHA256Hash
)

Write-Host "Starting recursive hash search in: $TargetDirectory"
Write-Host "Target SHA256: $SHA256Hash"
Write-Host "---------------------------------------------"

$matchCount = 0

try {
    $files = Get-ChildItem -Path $TargetDirectory -File -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $files) {
        try {
            $fileHash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop

            if ($fileHash.Hash -ieq $SHA256Hash) {
                Write-Host "[MATCH] $($file.FullName)" -ForegroundColor Red

                if ($PSCmdlet.ShouldProcess($file.FullName, "Delete file")) {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Host "[DELETED] $($file.FullName)" -ForegroundColor Yellow
                }

                $matchCount++
            }
        }
        catch {
            Write-Warning "Could not process file: $($file.FullName)"
        }
    }

    Write-Host "---------------------------------------------"
    Write-Host "Completed. Total matches found: $matchCount"
}
catch {
    Write-Error "Failed during execution: $_"
}