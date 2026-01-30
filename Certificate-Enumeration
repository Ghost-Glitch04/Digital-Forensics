<#
.SYNOPSIS
    Certificate Enumeration & Analysis - READ-ONLY Mode
.DESCRIPTION
    Analyzes Windows certificate stores to identify suspicious certificates
    that may have been installed by malware. This is a READ-ONLY script
    designed for learning and validation before running remediation.
    
    NO CERTIFICATES ARE REMOVED - This is for analysis only.
    
.NOTES
    Author: sentinelrshuser
    Repository: Ghost-Glitch04/Threat-Remediation-Scripts
    Branch: OneStart.AI
    Mode: READ-ONLY (No removal operations)
#>

#Requires -RunAsAdministrator

# ============================================================================
# CONFIGURATION
# ============================================================================

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFolder = "$env:TEMP\Certificate_Analysis"
$logFile = "$logFolder\Certificate_Analysis_${timestamp}.log"
$csvReport = "$logFolder\Certificate_Report_${timestamp}.csv"
$flaggedReport = "$logFolder\Flagged_Certificates_${timestamp}.csv"

# Create log folder
if (!(Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
}

# Certificate Analysis Configuration
$certConfig = @{
    # Keywords that trigger suspicion in Subject/Issuer fields
    SuspiciousKeywords = @(
        "OneStart",
        "OneStart.AI",
        "One Start",
        "Electron",
        "DO_NOT_TRUST",
        "Test",
        "Development",
        "Debug"
    )
    
    # Certificate stores to scan (ordered by risk level)
    Stores = @(
        @{Location = "LocalMachine"; Store = "Root"; Risk = "CRITICAL"},
        @{Location = "LocalMachine"; Store = "TrustedPublisher"; Risk = "HIGH"},
        @{Location = "LocalMachine"; Store = "CA"; Risk = "MEDIUM"},
        @{Location = "LocalMachine"; Store = "AuthRoot"; Risk = "MEDIUM"},
        @{Location = "CurrentUser"; Store = "Root"; Risk = "CRITICAL"},
        @{Location = "CurrentUser"; Store = "TrustedPublisher"; Risk = "HIGH"},
        @{Location = "CurrentUser"; Store = "CA"; Risk = "MEDIUM"}
    )
    
    # Analysis thresholds
    RecentlyInstalledDays = 90    # Flag certs installed in last 90 days
    SuspiciousValidityYears = 20  # Flag certs valid for over 20 years
}

# Results tracking
$allCertificates = @()
$flaggedCertificates = @()
$statistics = @{
    TotalStoresScanned = 0
    TotalCertificatesFound = 0
    TotalCertificatesFlagged = 0
    FlagReasons = @{}
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
}

function Get-CertificateAge {
    param([DateTime]$NotBefore)
    $age = (Get-Date) - $NotBefore
    return [Math]::Round($age.TotalDays, 0)
}

function Get-CertificateValidityPeriod {
    param(
        [DateTime]$NotBefore,
        [DateTime]$NotAfter
    )
    $validity = $NotAfter - $NotBefore
    return [Math]::Round($validity.TotalDays / 365.25, 1)
}

function Test-SuspiciousSubject {
    param(
        [string]$Subject,
        [array]$Keywords
    )
    
    foreach ($keyword in $Keywords) {
        if ($Subject -like "*$keyword*") {
            return $true
        }
    }
    return $false
}

function Get-CertificateIssuerName {
    param([string]$Issuer)
    
    # Extract CN from issuer string
    if ($Issuer -match "CN=([^,]+)") {
        return $matches[1]
    }
    return $Issuer
}

function Get-CertificateSubjectName {
    param([string]$Subject)
    
    # Extract CN from subject string
    if ($Subject -match "CN=([^,]+)") {
        return $matches[1]
    }
    return $Subject
}

# ============================================================================
# CERTIFICATE ENUMERATION
# ============================================================================

function Invoke-CertificateEnumeration {
    Write-Log "========================================" "INFO"
    Write-Log "CERTIFICATE ENUMERATION & ANALYSIS" "INFO"
    Write-Log "Mode: READ-ONLY (No certificates will be removed)" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "" "INFO"
    
    Write-Log "EDUCATION: Certificate Stores Explained" "INFO"
    Write-Log "  * Root Store = Trusted Root Certificate Authorities" "INFO"
    Write-Log "    - Most critical store for trust decisions" "INFO"
    Write-Log "    - Malware installs certs here to bypass security" "INFO"
    Write-Log "" "INFO"
    Write-Log "  * TrustedPublisher Store = Code Signing Trust" "INFO"
    Write-Log "    - Controls which publishers can install software" "INFO"
    Write-Log "    - Malware uses this to appear legitimate" "INFO"
    Write-Log "" "INFO"
    Write-Log "  * CA Store = Intermediate Certificate Authorities" "INFO"
    Write-Log "    - Less critical but can still be exploited" "INFO"
    Write-Log "" "INFO"
    Write-Log "Scanning $($certConfig.Stores.Count) certificate stores..." "INFO"
    Write-Log "" "INFO"
    
    foreach ($storeConfig in $certConfig.Stores) {
        $location = $storeConfig.Location
        $storeName = $storeConfig.Store
        $riskLevel = $storeConfig.Risk
        
        $statistics.TotalStoresScanned++
        
        Write-Log "Scanning: $location\$storeName (Risk: $riskLevel)" "INFO"
        
        try {
            # Open certificate store (read-only)
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                $storeName,
                $location
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            
            $certificates = $store.Certificates
            $storeCount = $certificates.Count
            $statistics.TotalCertificatesFound += $storeCount
            
            Write-Log "  Found $storeCount certificate(s)" "INFO"
            
            foreach ($cert in $certificates) {
                # Calculate metrics
                $certAge = Get-CertificateAge -NotBefore $cert.NotBefore
                $validityYears = Get-CertificateValidityPeriod -NotBefore $cert.NotBefore -NotAfter $cert.NotAfter
                $isRecentlyInstalled = $certAge -le $certConfig.RecentlyInstalledDays
                $hasLongValidity = $validityYears -ge $certConfig.SuspiciousValidityYears
                $hasSuspiciousSubject = Test-SuspiciousSubject -Subject $cert.Subject -Keywords $certConfig.SuspiciousKeywords
                $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                
                # Extract friendly names
                $subjectCN = Get-CertificateSubjectName -Subject $cert.Subject
                $issuerCN = Get-CertificateIssuerName -Issuer $cert.Issuer
                
                # Build certificate object
                $certObject = [PSCustomObject]@{
                    StoreLocation = $location
                    StoreName = $storeName
                    RiskLevel = $riskLevel
                    Subject = $cert.Subject
                    SubjectCN = $subjectCN
                    Issuer = $cert.Issuer
                    IssuerCN = $issuerCN
                    Thumbprint = $cert.Thumbprint
                    SerialNumber = $cert.SerialNumber
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                    AgeDays = $certAge
                    ValidityYears = $validityYears
                    IsSelfSigned = $isSelfSigned
                    HasPrivateKey = $cert.HasPrivateKey
                    SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                    FriendlyName = $cert.FriendlyName
                    # Analysis flags
                    IsRecentlyInstalled = $isRecentlyInstalled
                    HasLongValidity = $hasLongValidity
                    HasSuspiciousSubject = $hasSuspiciousSubject
                    WouldBeFlagged = $false
                    FlagReasons = ""
                }
                
                # Determine if certificate would be flagged
                $flagReasons = @()
                
                if ($hasSuspiciousSubject) {
                    $flagReasons += "Suspicious subject name"
                }
                
                if ($isRecentlyInstalled -and $isSelfSigned -and $riskLevel -eq "CRITICAL") {
                    $flagReasons += "Recently installed self-signed cert in critical store"
                }
                
                if ($hasLongValidity -and $isSelfSigned) {
                    $flagReasons += "Self-signed with unusually long validity period"
                }
                
                if ($flagReasons.Count -gt 0) {
                    $certObject.WouldBeFlagged = $true
                    $certObject.FlagReasons = $flagReasons -join "; "
                    
                    $script:flaggedCertificates += $certObject
                    $statistics.TotalCertificatesFlagged++
                    
                    # Track flag reason statistics
                    foreach ($reason in $flagReasons) {
                        if ($statistics.FlagReasons.ContainsKey($reason)) {
                            $statistics.FlagReasons[$reason]++
                        } else {
                            $statistics.FlagReasons[$reason] = 1
                        }
                    }
                    
                    Write-Log "  [FLAGGED] $subjectCN" "WARNING"
                    Write-Log "    Thumbprint: $($cert.Thumbprint)" "WARNING"
                    Write-Log "    Reasons: $($certObject.FlagReasons)" "WARNING"
                }
                
                $script:allCertificates += $certObject
            }
            
            $store.Close()
            
        } catch {
            Write-Log "  [ERROR] Failed to scan $location\$storeName - $($_.Exception.Message)" "ERROR"
        }
        
        Write-Log "" "INFO"
    }
}

# ============================================================================
# ANALYSIS REPORTING
# ============================================================================

function Show-AnalysisReport {
    Write-Log "========================================" "INFO"
    Write-Log "ANALYSIS SUMMARY" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "Stores Scanned: $($statistics.TotalStoresScanned)" "INFO"
    Write-Log "Total Certificates Found: $($statistics.TotalCertificatesFound)" "INFO"
    Write-Log "Certificates That Would Be Flagged: $($statistics.TotalCertificatesFlagged)" "WARNING"
    Write-Log "" "INFO"
    
    if ($statistics.TotalCertificatesFlagged -eq 0) {
        Write-Log "[OK] No suspicious certificates detected!" "SUCCESS"
        Write-Log "The remediation script would not flag any certificates on this system." "SUCCESS"
    } else {
        Write-Log "[WARNING] $($statistics.TotalCertificatesFlagged) certificate(s) would be targeted for removal!" "WARNING"
        Write-Log "" "INFO"
        
        Write-Log "FLAG REASONS BREAKDOWN:" "INFO"
        foreach ($reason in $statistics.FlagReasons.Keys | Sort-Object) {
            Write-Log "  * $reason : $($statistics.FlagReasons[$reason]) certificate(s)" "INFO"
        }
        Write-Log "" "INFO"
        
        Write-Log "FLAGGED CERTIFICATES (Detailed):" "WARNING"
        Write-Log "" "INFO"
        
        foreach ($cert in $flaggedCertificates) {
            Write-Log "---" "WARNING"
            Write-Log "Certificate: $($cert.SubjectCN)" "WARNING"
            Write-Log "  Store: $($cert.StoreLocation)\$($cert.StoreName)" "INFO"
            Write-Log "  Risk Level: $($cert.RiskLevel)" "WARNING"
            Write-Log "  Thumbprint: $($cert.Thumbprint)" "INFO"
            Write-Log "  Subject: $($cert.Subject)" "INFO"
            Write-Log "  Issuer: $($cert.Issuer)" "INFO"
            Write-Log "  Serial Number: $($cert.SerialNumber)" "INFO"
            Write-Log "  Valid From: $($cert.NotBefore)" "INFO"
            Write-Log "  Valid Until: $($cert.NotAfter)" "INFO"
            Write-Log "  Age: $($cert.AgeDays) days" "INFO"
            Write-Log "  Validity Period: $($cert.ValidityYears) years" "INFO"
            Write-Log "  Self-Signed: $($cert.IsSelfSigned)" "INFO"
            Write-Log "  Has Private Key: $($cert.HasPrivateKey)" "INFO"
            Write-Log "  Signature Algorithm: $($cert.SignatureAlgorithm)" "INFO"
            Write-Log "  FLAG REASONS: $($cert.FlagReasons)" "WARNING"
            Write-Log "" "INFO"
        }
    }
    
    Write-Log "========================================" "INFO"
    Write-Log "DECISION LOGIC EXPLANATION" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "A certificate is FLAGGED if it meets ANY of these criteria:" "INFO"
    Write-Log "" "INFO"
    Write-Log "1. SUSPICIOUS SUBJECT NAME" "INFO"
    Write-Log "   Keywords: $($certConfig.SuspiciousKeywords -join ', ')" "INFO"
    Write-Log "   Reason: Direct match to known malware names" "INFO"
    Write-Log "" "INFO"
    Write-Log "2. RECENTLY INSTALLED + SELF-SIGNED + CRITICAL STORE" "INFO"
    Write-Log "   Threshold: Installed within last $($certConfig.RecentlyInstalledDays) days" "INFO"
    Write-Log "   Stores: Root (LocalMachine or CurrentUser)" "INFO"
    Write-Log "   Reason: Legitimate root CAs are rarely self-signed and recently added" "INFO"
    Write-Log "" "INFO"
    Write-Log "3. SELF-SIGNED + LONG VALIDITY PERIOD" "INFO"
    Write-Log "   Threshold: Valid for $($certConfig.SuspiciousValidityYears)+ years" "INFO"
    Write-Log "   Reason: Malware creates long-validity certs to persist" "INFO"
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
}

# ============================================================================
# EXPORT REPORTS
# ============================================================================

function Export-Reports {
    Write-Log "Exporting detailed reports..." "INFO"
    
    # Export all certificates to CSV
    try {
        $allCertificates | Export-Csv -Path $csvReport -NoTypeInformation -Force
        Write-Log "[OK] Full certificate report: $csvReport" "SUCCESS"
    } catch {
        Write-Log "[ERROR] Failed to export full report: $($_.Exception.Message)" "ERROR"
    }
    
    # Export flagged certificates to separate CSV
    if ($flaggedCertificates.Count -gt 0) {
        try {
            $flaggedCertificates | Export-Csv -Path $flaggedReport -NoTypeInformation -Force
            Write-Log "[OK] Flagged certificates report: $flaggedReport" "SUCCESS"
        } catch {
            Write-Log "[ERROR] Failed to export flagged report: $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Log "" "INFO"
    Write-Log "========================================" "INFO"
    Write-Log "REPORTS GENERATED" "SUCCESS"
    Write-Log "========================================" "INFO"
    Write-Log "Log File: $logFile" "INFO"
    Write-Log "Full Report (CSV): $csvReport" "INFO"
    if ($flaggedCertificates.Count -gt 0) {
        Write-Log "Flagged Certificates (CSV): $flaggedReport" "INFO"
    }
    Write-Log "" "INFO"
    Write-Log "You can review these CSV files in Excel for detailed analysis." "INFO"
    Write-Log "========================================" "INFO"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Log "========================================" "INFO"
Write-Log "Certificate Analysis Script Started" "INFO"
Write-Log "Timestamp: $(Get-Date)" "INFO"
Write-Log "User: $env:USERNAME" "INFO"
Write-Log "Computer: $env:COMPUTERNAME" "INFO"
Write-Log "Mode: READ-ONLY (No removal operations)" "INFO"
Write-Log "========================================" "INFO"
Write-Log "" "INFO"

# Run enumeration
Invoke-CertificateEnumeration

# Show analysis
Show-AnalysisReport

# Export reports
Export-Reports

Write-Log "========================================" "INFO"
Write-Log "Analysis Complete!" "SUCCESS"
Write-Log "========================================" "INFO"

# Display results to console
Write-Output ""
Write-Output "=========================================="
Write-Output "Certificate Analysis Complete!"
Write-Output "=========================================="
Write-Output ""
Write-Output "Log File: $logFile"
Write-Output ""
Write-Output "Retrieving results..."
Write-Output ""

# Display log contents
Get-Content $logFile

Write-Output ""
Write-Output "=========================================="
Write-Output "Review the CSV reports for detailed analysis:"
Write-Output "  Full Report: $csvReport"
if ($flaggedCertificates.Count -gt 0) {
    Write-Output "  Flagged Only: $flaggedReport"
}
Write-Output "=========================================="
