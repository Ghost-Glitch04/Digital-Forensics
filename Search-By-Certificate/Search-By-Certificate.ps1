<#
.SYNOPSIS
    Searches for files that can be code-signed and optionally verifies if they're signed by a specific certificate.

.DESCRIPTION
    Efficiently searches directories for signable files using parallel processing and regex filtering.
    Can verify if files are signed by a specific certificate thumbprint.

.PARAMETER Path
    The root path to search for files. Defaults to current directory.

.PARAMETER CertificateThumbprint
    Optional. The thumbprint of the certificate to verify against. If provided, only files signed by this certificate will be returned.

.PARAMETER IncludeUnsigned
    When used with CertificateThumbprint, also returns unsigned files.

.PARAMETER ThrottleLimit
    Number of parallel threads to use. Defaults to processor count.

.EXAMPLE
    Find-SignableFiles -Path "C:\Program Files" -CertificateThumbprint "ABC123..."

.EXAMPLE
    Find-SignableFiles -Path "C:\MyApp" -IncludeUnsigned
#>

function Find-SignableFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [array]$Path = (Get-Location).Path,
        
        [Parameter(Mandatory=$false)]
        [string]$CertificateThumbprint,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeUnsigned,
        
        [Parameter(Mandatory=$false)]
        [int]$ThrottleLimit = [Environment]::ProcessorCount
    )
    
    # File extensions that support code signing
    $signableExtensions = @(
        '\.exe$', '\.dll$', '\.ocx$', '\.sys$', '\.cat$',
        '\.ps1$', '\.psm1$', '\.psd1$', '\.ps1xml$',
        '\.msi$', '\.msix$', '\.appx$', '\.cab$',
        '\.vbs$', '\.js$', '\.wsf$'
    )
    
    # Create regex pattern for efficient filtering
    $extensionPattern = "($($signableExtensions -join '|'))"
    
    Write-Host "Searching for signable files in: $Path" -ForegroundColor Cyan
    Write-Host "Using $ThrottleLimit parallel threads" -ForegroundColor Cyan
    
    # Get all files matching the pattern
    Write-Host "Scanning directory structure..." -ForegroundColor Yellow
    
    # Handle both file and directory paths
    $files = @()
    foreach ($p in $Path) {
        if (Test-Path -Path $p -PathType Leaf) {
            # It's a file, add it directly if it matches the pattern
            $fileItem = Get-Item -Path $p -ErrorAction SilentlyContinue
            if ($fileItem -and ($fileItem.Name -match $extensionPattern)) {
                $files += $fileItem
            }
        } elseif (Test-Path -Path $p -PathType Container) {
            # It's a directory, recurse through it
            $files += Get-ChildItem -Path $p -File -Recurse -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match $extensionPattern }
        } else {
            Write-Warning "Path not found or inaccessible: $p"
        }
    }
    
    $totalFiles = $files.Count
    Write-Host "Found $totalFiles potentially signable files" -ForegroundColor Green
    
    if ($totalFiles -eq 0) {
        Write-Host "No signable files found." -ForegroundColor Yellow
        return
    }
    
    # Process files in parallel
    Write-Host "Analyzing signatures..." -ForegroundColor Yellow
    
    $results = $files | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $file = $_
        $certThumbprint = $using:CertificateThumbprint
        $includeUnsigned = $using:IncludeUnsigned
        
        try {
            $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
            
            $result = [PSCustomObject]@{
                FilePath = $file.FullName
                FileName = $file.Name
                Extension = $file.Extension
                SizeKB = [math]::Round($file.Length / 1KB, 2)
                IsSigned = $signature.Status -eq 'Valid'
                SignatureStatus = $signature.Status
                SignerCertificate = $signature.SignerCertificate
                Thumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null }
                Subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
                Issuer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Issuer } else { $null }
                NotBefore = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotBefore } else { $null }
                NotAfter = if ($signature.SignerCertificate) { $signature.SignerCertificate.NotAfter } else { $null }
                MatchesCertificate = $false
            }
            
            # Check if certificate matches the specified thumbprint
            if ($certThumbprint) {
                $result.MatchesCertificate = ($result.Thumbprint -eq $certThumbprint)
                
                # Return based on criteria
                if ($result.MatchesCertificate) {
                    return $result
                } elseif ($includeUnsigned -and -not $result.IsSigned) {
                    return $result
                }
            } else {
                # No thumbprint specified, return all results
                return $result
            }
            
        } catch {
            Write-Warning "Error processing file: $($file.FullName) - $_"
        }
    }
    
    # Filter and display results
    $filteredResults = $results | Where-Object { $_ -ne $null }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "RESULTS SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total files analyzed: $totalFiles" -ForegroundColor White
    
    if ($CertificateThumbprint) {
        $matchCount = ($filteredResults | Where-Object { $_.MatchesCertificate }).Count
        $unsignedCount = ($filteredResults | Where-Object { -not $_.IsSigned }).Count
        
        Write-Host "Files signed by certificate: $matchCount" -ForegroundColor Green
        if ($IncludeUnsigned) {
            Write-Host "Unsigned files: $unsignedCount" -ForegroundColor Yellow
        }
    } else {
        $signedCount = ($filteredResults | Where-Object { $_.IsSigned }).Count
        $unsignedCount = ($filteredResults | Where-Object { -not $_.IsSigned }).Count
        
        Write-Host "Signed files: $signedCount" -ForegroundColor Green
        Write-Host "Unsigned files: $unsignedCount" -ForegroundColor Yellow
    }
    
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    return $filteredResults
}

# Example usage:
# Basic search - finds all signable files
# $results = Find-SignableFiles -Path "C:\MyApp"

# Search for files signed by specific certificate
# $results = Find-SignableFiles -Path "C:\MyApp" -CertificateThumbprint "1234567890ABCDEF1234567890ABCDEF12345678"

# Include unsigned files in results
# $results = Find-SignableFiles -Path "C:\MyApp" -CertificateThumbprint "1234..." -IncludeUnsigned

# Export results to CSV
# $results | Export-Csv -Path "signable_files_report.csv" -NoTypeInformation

# Display results in grid view
# $results | Out-GridView

# Filter results for specific certificate matches
# $results | Where-Object { $_.MatchesCertificate } | Format-Table FileName, FilePath, Subject