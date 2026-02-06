<#
.SYNOPSIS
    Enumerates a file flagged by SentinelOne and logs all details.

.DESCRIPTION
    Gathers MD5, SHA1, SHA256 hashes, file metadata, and digital signature
    information for a specified file. All output is written to a log file.

.PARAMETER FilePath
    Full path to the file to enumerate.

.EXAMPLE
    .\File_Enumeration.ps1 -FilePath "C:\Path\To\Suspicious.exe"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Initialize log file
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "$env:TEMP\File_Enumeration_$timestamp.txt"

# Function to write to log
function Write-Log {
    param([string]$Message)
    Add-Content -Path $logFile -Value $Message
}

# Function to write section header
function Write-SectionHeader {
    param([string]$Title)
    Write-Log ""
    Write-Log ("=" * 80)
    Write-Log $Title
    Write-Log ("=" * 80)
}

# Start enumeration
Write-Log "File Enumeration Report"
Write-Log "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "Target File: $FilePath"
Write-Log ""

# Check if file exists
if (-not (Test-Path -Path $FilePath -PathType Leaf)) {
    Write-Log "ERROR: File not found at specified path."
    Get-Content $logFile
    exit 1
}

# Section 1: File Hashes
Write-SectionHeader "FILE HASHES"
try {
    Write-Log "Calculating MD5..."
    $md5 = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
    Write-Log "MD5:    $md5"
    
    Write-Log "Calculating SHA1..."
    $sha1 = (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
    Write-Log "SHA1:   $sha1"
    
    Write-Log "Calculating SHA256..."
    $sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    Write-Log "SHA256: $sha256"
} catch {
    Write-Log "ERROR calculating hashes: $($_.Exception.Message)"
}

# Section 2: File Metadata
Write-SectionHeader "FILE METADATA"
try {
    $fileInfo = Get-Item -Path $FilePath -Force
    
    Write-Log "File Name:        $($fileInfo.Name)"
    Write-Log "Full Path:        $($fileInfo.FullName)"
    Write-Log "Directory:        $($fileInfo.DirectoryName)"
    Write-Log "Extension:        $($fileInfo.Extension)"
    Write-Log "Size (Bytes):     $($fileInfo.Length)"
    Write-Log "Size (KB):        $([math]::Round($fileInfo.Length/1KB, 2))"
    Write-Log "Size (MB):        $([math]::Round($fileInfo.Length/1MB, 2))"
    Write-Log "Created:          $($fileInfo.CreationTime)"
    Write-Log "Modified:         $($fileInfo.LastWriteTime)"
    Write-Log "Accessed:         $($fileInfo.LastAccessTime)"
    Write-Log "Attributes:       $($fileInfo.Attributes)"
    Write-Log "Is ReadOnly:      $($fileInfo.IsReadOnly)"
    
    # Get file version info if available
    if ($fileInfo.VersionInfo) {
        $versionInfo = $fileInfo.VersionInfo
        Write-Log ""
        Write-Log "--- Version Information ---"
        Write-Log "Product Name:     $($versionInfo.ProductName)"
        Write-Log "Product Version:  $($versionInfo.ProductVersion)"
        Write-Log "File Version:     $($versionInfo.FileVersion)"
        Write-Log "Company Name:     $($versionInfo.CompanyName)"
        Write-Log "Description:      $($versionInfo.FileDescription)"
        Write-Log "Copyright:        $($versionInfo.LegalCopyright)"
        Write-Log "Original Name:    $($versionInfo.OriginalFilename)"
        Write-Log "Internal Name:    $($versionInfo.InternalName)"
        Write-Log "Language:         $($versionInfo.Language)"
    }
} catch {
    Write-Log "ERROR retrieving metadata: $($_.Exception.Message)"
}

# Section 3: Digital Signature and Certificate Information
Write-SectionHeader "DIGITAL SIGNATURE INFORMATION"
try {
    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    
    Write-Log "Signature Status: $($signature.Status)"
    Write-Log "Status Message:   $($signature.StatusMessage)"
    Write-Log "Is OS Binary:     $($signature.IsOSBinary)"
    Write-Log "Signature Type:   $($signature.SignatureType)"
    
    if ($signature.SignerCertificate) {
        $cert = $signature.SignerCertificate
        
        Write-Log ""
        Write-Log "--- Signer Certificate ---"
        Write-Log "Subject:          $($cert.Subject)"
        Write-Log "Issuer:           $($cert.Issuer)"
        Write-Log "Thumbprint:       $($cert.Thumbprint)"
        Write-Log "Serial Number:    $($cert.SerialNumber)"
        Write-Log "Not Before:       $($cert.NotBefore)"
        Write-Log "Not After:        $($cert.NotAfter)"
        Write-Log "Version:          $($cert.Version)"
        Write-Log "Has Private Key:  $($cert.HasPrivateKey)"
        Write-Log "Key Algorithm:    $($cert.PublicKey.Oid.FriendlyName)"
        
        # Enhanced Key Usage
        if ($cert.EnhancedKeyUsageList) {
            Write-Log ""
            Write-Log "Enhanced Key Usage:"
            foreach ($eku in $cert.EnhancedKeyUsageList) {
                Write-Log "  * $($eku.FriendlyName) ($($eku.ObjectId))"
            }
        }
    } else {
        Write-Log ""
        Write-Log "No signer certificate found (file is not signed)."
    }
    
    # Check for timestamp certificate
    if ($signature.TimeStamperCertificate) {
        $tsCert = $signature.TimeStamperCertificate
        
        Write-Log ""
        Write-Log "--- TimeStamp Certificate ---"
        Write-Log "Subject:          $($tsCert.Subject)"
        Write-Log "Issuer:           $($tsCert.Issuer)"
        Write-Log "Thumbprint:       $($tsCert.Thumbprint)"
        Write-Log "Serial Number:    $($tsCert.SerialNumber)"
        Write-Log "Not Before:       $($tsCert.NotBefore)"
        Write-Log "Not After:        $($tsCert.NotAfter)"
    }
    
} catch {
    Write-Log "ERROR retrieving signature info: $($_.Exception.Message)"
}

# Section 4: Additional File Properties
Write-SectionHeader "ADDITIONAL PROPERTIES"
try {
    $shell = New-Object -ComObject Shell.Application
    $folder = $shell.Namespace($fileInfo.DirectoryName)
    $file = $folder.ParseName($fileInfo.Name)
    
    # Get extended properties (0-300+ properties)
    for ($i = 0; $i -lt 350; $i++) {
        $propName = $folder.GetDetailsOf($null, $i)
        if ($propName) {
            $propValue = $folder.GetDetailsOf($file, $i)
            if ($propValue) {
                Write-Log "$propName : $propValue"
            }
        }
    }
} catch {
    Write-Log "ERROR retrieving extended properties: $($_.Exception.Message)"
}

# Footer
Write-Log ""
Write-Log ("=" * 80)
Write-Log "End of Report"
Write-Log "Log saved to: $logFile"
Write-Log ("=" * 80)

# Display the log file contents
Write-Host "`nEnumeration complete. Log file: $logFile`n"
Get-Content $logFile