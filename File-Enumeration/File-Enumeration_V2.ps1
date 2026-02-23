<#
.SYNOPSIS
    Enumerates a file flagged by SentinelOne and logs all details including compilation data.

.DESCRIPTION
    Gathers MD5, SHA1, SHA256 hashes, file metadata, digital signature information,
    and PE compilation details (compiler used, compilation date, linker version, etc.)
    for a specified file. All output is written to a log file.

.PARAMETER FilePath
    Full path to the file to enumerate.

.EXAMPLE
    .\File_Enumeration_Enhanced.ps1 -FilePath "C:\Path\To\Suspicious.exe"
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

# Function to convert Unix timestamp to DateTime
function Convert-UnixTimeStamp {
    param([int]$TimeStamp)
    try {
        $origin = New-Object DateTime(1970, 1, 1, 0, 0, 0, 0, [DateTimeKind]::Utc)
        return $origin.AddSeconds($TimeStamp).ToLocalTime()
    } catch {
        return "Invalid timestamp"
    }
}

# Function to parse PE compilation information
function Get-PECompilationInfo {
    param([string]$Path)
    
    $compilationInfo = @{
        IsPE = $false
        CompilationDate = $null
        LinkerVersion = $null
        CompilerInfo = @()
        DebugInfo = @()
        Subsystem = $null
        Machine = $null
        Characteristics = @()
        RichHeader = @()
        SectionHeaders = @()
    }
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        
        # Check for MZ header (DOS header)
        if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
            return $compilationInfo
        }
        
        # Get PE header offset (at offset 0x3C)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        
        # Verify PE signature
        if ($peOffset -ge $bytes.Length -or 
            $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45 -or
            $bytes[$peOffset+2] -ne 0x00 -or $bytes[$peOffset+3] -ne 0x00) {
            return $compilationInfo
        }
        
        $compilationInfo.IsPE = $true
        
        # Parse COFF Header (starts at PE offset + 4)
        $coffOffset = $peOffset + 4
        
        # Machine type (2 bytes)
        $machine = [BitConverter]::ToUInt16($bytes, $coffOffset)
        $compilationInfo.Machine = switch ($machine) {
            0x014c { "Intel 386 (x86)" }
            0x0200 { "Intel Itanium" }
            0x8664 { "x64 (AMD64/EM64T)" }
            0x01c0 { "ARM" }
            0xaa64 { "ARM64" }
            default { "Unknown (0x{0:X4})" -f $machine }
        }
        
        # Number of sections
        $numberOfSections = [BitConverter]::ToUInt16($bytes, $coffOffset + 2)
        
        # TimeDateStamp (4 bytes at offset +4 from COFF header)
        $timeStamp = [BitConverter]::ToInt32($bytes, $coffOffset + 4)
        $compilationInfo.CompilationDate = Convert-UnixTimeStamp $timeStamp
        
        # Characteristics (2 bytes at offset +18)
        $characteristics = [BitConverter]::ToUInt16($bytes, $coffOffset + 18)
        if ($characteristics -band 0x0001) { $compilationInfo.Characteristics += "Relocation info stripped" }
        if ($characteristics -band 0x0002) { $compilationInfo.Characteristics += "Executable image" }
        if ($characteristics -band 0x0004) { $compilationInfo.Characteristics += "Line numbers stripped" }
        if ($characteristics -band 0x0008) { $compilationInfo.Characteristics += "Local symbols stripped" }
        if ($characteristics -band 0x0020) { $compilationInfo.Characteristics += "Large address aware" }
        if ($characteristics -band 0x0100) { $compilationInfo.Characteristics += "32-bit machine" }
        if ($characteristics -band 0x0200) { $compilationInfo.Characteristics += "Debug info stripped" }
        if ($characteristics -band 0x1000) { $compilationInfo.Characteristics += "System file" }
        if ($characteristics -band 0x2000) { $compilationInfo.Characteristics += "DLL" }
        
        # Optional Header size
        $optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $coffOffset + 16)
        $optionalHeaderOffset = $coffOffset + 20
        
        if ($optionalHeaderSize -gt 0 -and ($optionalHeaderOffset + $optionalHeaderSize) -le $bytes.Length) {
            # Magic number (PE32 or PE32+)
            $magic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)
            $isPE32Plus = ($magic -eq 0x20B)
            
            # Linker version
            $linkerMajor = $bytes[$optionalHeaderOffset + 2]
            $linkerMinor = $bytes[$optionalHeaderOffset + 3]
            $compilationInfo.LinkerVersion = "$linkerMajor.$linkerMinor"
            
            # Subsystem (offset depends on PE32 vs PE32+)
            $subsystemOffset = if ($isPE32Plus) { $optionalHeaderOffset + 68 } else { $optionalHeaderOffset + 68 }
            if ($subsystemOffset + 2 -le $bytes.Length) {
                $subsystem = [BitConverter]::ToUInt16($bytes, $subsystemOffset)
                $compilationInfo.Subsystem = switch ($subsystem) {
                    1 { "Native" }
                    2 { "Windows GUI" }
                    3 { "Windows CUI (Console)" }
                    5 { "OS/2 CUI" }
                    7 { "POSIX CUI" }
                    9 { "Windows CE GUI" }
                    10 { "EFI Application" }
                    11 { "EFI Boot Service Driver" }
                    12 { "EFI Runtime Driver" }
                    13 { "EFI ROM" }
                    14 { "Xbox" }
                    16 { "Windows Boot Application" }
                    default { "Unknown ($subsystem)" }
                }
            }
            
            # Parse Data Directories to find Debug Directory
            $numberOfRvaAndSizes = if ($isPE32Plus) { 
                [BitConverter]::ToInt32($bytes, $optionalHeaderOffset + 108)
            } else { 
                [BitConverter]::ToInt32($bytes, $optionalHeaderOffset + 92)
            }
            
            $dataDirectoryOffset = if ($isPE32Plus) { $optionalHeaderOffset + 112 } else { $optionalHeaderOffset + 96 }
            
            # Debug Directory is the 7th entry (index 6)
            if ($numberOfRvaAndSizes -ge 7) {
                $debugDirRVA = [BitConverter]::ToInt32($bytes, $dataDirectoryOffset + (6 * 8))
                $debugDirSize = [BitConverter]::ToInt32($bytes, $dataDirectoryOffset + (6 * 8) + 4)
                
                if ($debugDirRVA -ne 0 -and $debugDirSize -ne 0) {
                    # Convert RVA to file offset using section headers
                    $sectionHeaderOffset = $optionalHeaderOffset + $optionalHeaderSize
                    $debugFileOffset = $null
                    
                    for ($i = 0; $i -lt $numberOfSections; $i++) {
                        $sectionOffset = $sectionHeaderOffset + ($i * 40)
                        if ($sectionOffset + 40 -le $bytes.Length) {
                            $virtualAddress = [BitConverter]::ToInt32($bytes, $sectionOffset + 12)
                            $sizeOfRawData = [BitConverter]::ToInt32($bytes, $sectionOffset + 16)
                            $pointerToRawData = [BitConverter]::ToInt32($bytes, $sectionOffset + 20)
                            
                            if ($debugDirRVA -ge $virtualAddress -and $debugDirRVA -lt ($virtualAddress + $sizeOfRawData)) {
                                $debugFileOffset = $pointerToRawData + ($debugDirRVA - $virtualAddress)
                                break
                            }
                        }
                    }
                    
                    # Parse debug directory entries
                    if ($debugFileOffset -and $debugFileOffset + 28 -le $bytes.Length) {
                        $debugType = [BitConverter]::ToInt32($bytes, $debugFileOffset + 12)
                        $debugDataSize = [BitConverter]::ToInt32($bytes, $debugFileOffset + 16)
                        $debugDataRVA = [BitConverter]::ToInt32($bytes, $debugFileOffset + 20)
                        $debugDataOffset = [BitConverter]::ToInt32($bytes, $debugFileOffset + 24)
                        
                        $debugTypeName = switch ($debugType) {
                            1 { "COFF" }
                            2 { "CodeView" }
                            4 { "Misc" }
                            16 { "Repro" }
                            default { "Unknown ($debugType)" }
                        }
                        
                        $compilationInfo.DebugInfo += "Type: $debugTypeName"
                        
                        # Try to extract PDB path (CodeView debug type)
                        if ($debugType -eq 2 -and $debugDataOffset -ne 0 -and 
                            $debugDataOffset + $debugDataSize -le $bytes.Length) {
                            
                            $cvSig = [BitConverter]::ToUInt32($bytes, $debugDataOffset)
                            
                            # RSDS signature (0x53445352) - PDB 7.0
                            if ($cvSig -eq 0x53445352 -and $debugDataSize -gt 24) {
                                # Skip signature (4) + GUID (16) + Age (4) = 24 bytes
                                $pdbPathStart = $debugDataOffset + 24
                                $pdbPathBytes = $bytes[$pdbPathStart..($debugDataOffset + $debugDataSize - 1)]
                                $nullIndex = [Array]::IndexOf($pdbPathBytes, [byte]0)
                                if ($nullIndex -gt 0) {
                                    $pdbPath = [System.Text.Encoding]::ASCII.GetString($pdbPathBytes[0..($nullIndex-1)])
                                    $compilationInfo.DebugInfo += "PDB Path: $pdbPath"
                                    
                                    # Extract compiler hints from PDB path
                                    if ($pdbPath -match "vc\d+") {
                                        $compilationInfo.CompilerInfo += "Likely Visual C++ (from PDB path)"
                                    }
                                }
                            }
                            # NB10 signature (older PDB format)
                            elseif ($cvSig -eq 0x3031424E -and $debugDataSize -gt 16) {
                                $pdbPathStart = $debugDataOffset + 16
                                $pdbPathBytes = $bytes[$pdbPathStart..($debugDataOffset + $debugDataSize - 1)]
                                $nullIndex = [Array]::IndexOf($pdbPathBytes, [byte]0)
                                if ($nullIndex -gt 0) {
                                    $pdbPath = [System.Text.Encoding]::ASCII.GetString($pdbPathBytes[0..($nullIndex-1)])
                                    $compilationInfo.DebugInfo += "PDB Path: $pdbPath (NB10)"
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Parse Rich Header for compiler information
        # Rich header is between DOS stub and PE header
        $richOffset = -1
        for ($i = 0x80; $i -lt $peOffset - 4; $i++) {
            if ($bytes[$i] -eq 0x52 -and $bytes[$i+1] -eq 0x69 -and 
                $bytes[$i+2] -eq 0x63 -and $bytes[$i+3] -eq 0x68) {
                $richOffset = $i
                break
            }
        }
        
        if ($richOffset -gt 0) {
            # Find DanS marker (start of Rich header, XORed)
            $xorKey = [BitConverter]::ToInt32($bytes, $richOffset + 4)
            
            for ($i = $richOffset - 4; $i -ge 0x80; $i -= 4) {
                $value = [BitConverter]::ToInt32($bytes, $i)
                $decoded = $value -bxor $xorKey
                
                if ($decoded -eq 0x536E6144) { # "DanS" reversed
                    # Parse compiler entries
                    for ($j = $i + 8; $j -lt $richOffset; $j += 8) {
                        $compId = [BitConverter]::ToInt32($bytes, $j) -bxor $xorKey
                        $count = [BitConverter]::ToInt32($bytes, $j + 4) -bxor $xorKey
                        
                        if ($compId -ne 0) {
                            $prodId = ($compId -shr 16) -band 0xFFFF
                            $buildNum = $compId -band 0xFFFF
                            
                            $toolName = switch ($prodId) {
                                0x0001 { "Imported Symbol" }
                                0x0004 { "Linker" }
                                0x0005 { "CVTOMF" }
                                0x0006 { "CVTRES" }
                                0x0007 { "UTCATLMFCLIB" }
                                0x000A { "Resource Compiler" }
                                0x000B { "MASM" }
                                0x005D { "Imported Symbol (Unknown)" }
                                0x0083 { "C/C++ Compiler (Visual Studio 6.0)" }
                                0x0093 { "C/C++ Compiler (Visual Studio .NET 2002)" }
                                0x009A { "C/C++ Compiler (Visual Studio .NET 2003)" }
                                0x009B { "MASM (Visual Studio .NET 2003)" }
                                0x00AA { "C/C++ Compiler (Visual Studio 2005)" }
                                0x00AB { "MASM (Visual Studio 2005)" }
                                0x00BA { "C/C++ Compiler (Visual Studio 2008)" }
                                0x00BB { "MASM (Visual Studio 2008)" }
                                0x00C7 { "C/C++ Compiler (Visual Studio 2010)" }
                                0x00DB { "C/C++ Compiler (Visual Studio 2012)" }
                                0x00DD { "MASM (Visual Studio 2012)" }
                                0x00EB { "C/C++ Compiler (Visual Studio 2013)" }
                                0x00EC { "MASM (Visual Studio 2013)" }
                                0x00FF { "C/C++ Compiler (Visual Studio 2015)" }
                                0x0105 { "MASM (Visual Studio 2015)" }
                                0x013D { "C/C++ Compiler (Visual Studio 2017)" }
                                0x013E { "MASM (Visual Studio 2017)" }
                                0x0147 { "C/C++ Compiler (Visual Studio 2019)" }
                                0x0148 { "MASM (Visual Studio 2019)" }
                                0x0151 { "C/C++ Compiler (Visual Studio 2022)" }
                                0x0152 { "MASM (Visual Studio 2022)" }
                                default { "Unknown Tool ID (0x{0:X4})" -f $prodId }
                            }
                            
                            $compilationInfo.RichHeader += "$toolName - Build $buildNum (Used $count times)"
                        }
                    }
                    break
                }
            }
        }
        
        # Parse section headers for additional compiler hints
        $sectionHeaderOffset = $optionalHeaderOffset + $optionalHeaderSize
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $sectionOffset = $sectionHeaderOffset + ($i * 40)
            if ($sectionOffset + 40 -le $bytes.Length) {
                $sectionNameBytes = $bytes[$sectionOffset..($sectionOffset + 7)]
                $nullIndex = [Array]::IndexOf($sectionNameBytes, [byte]0)
                $sectionName = if ($nullIndex -ge 0) {
                    [System.Text.Encoding]::ASCII.GetString($sectionNameBytes[0..($nullIndex-1)])
                } else {
                    [System.Text.Encoding]::ASCII.GetString($sectionNameBytes)
                }
                
                $virtualSize = [BitConverter]::ToInt32($bytes, $sectionOffset + 8)
                $sizeOfRawData = [BitConverter]::ToInt32($bytes, $sectionOffset + 16)
                
                $compilationInfo.SectionHeaders += "$sectionName (Virtual: $virtualSize, Raw: $sizeOfRawData)"
                
                # Check for compiler-specific section names
                if ($sectionName -match "^\.text|^CODE|^_TEXT") {
                    # Common in most compilers
                }
                elseif ($sectionName -match "UPX|upx") {
                    $compilationInfo.CompilerInfo += "Packed with UPX"
                }
                elseif ($sectionName -match "\.ndata|\.mdata") {
                    $compilationInfo.CompilerInfo += "Possible Delphi/Borland compiler"
                }
            }
        }
        
        # Additional compiler detection from imports
        if ($compilationInfo.CompilerInfo.Count -eq 0 -and $compilationInfo.RichHeader.Count -eq 0) {
            $compilationInfo.CompilerInfo += "Could not determine compiler from PE headers"
        }
        
    } catch {
        Write-Log "Error parsing PE file: $($_.Exception.Message)"
    }
    
    return $compilationInfo
}

# Start enumeration
Write-Log "File Enumeration Report (Enhanced with Compilation Data)"
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

# NEW SECTION: PE Compilation Information
Write-SectionHeader "COMPILATION INFORMATION (PE ANALYSIS)"
try {
    $peInfo = Get-PECompilationInfo -Path $FilePath
    
    if ($peInfo.IsPE) {
        Write-Log "File Type:        Portable Executable (PE)"
        Write-Log "Machine Type:     $($peInfo.Machine)"
        
        if ($peInfo.CompilationDate) {
            Write-Log "Compilation Date: $($peInfo.CompilationDate) UTC"
            Write-Log "                  (Timestamp from PE COFF header)"
        }
        
        if ($peInfo.LinkerVersion) {
            Write-Log "Linker Version:   $($peInfo.LinkerVersion)"
        }
        
        if ($peInfo.Subsystem) {
            Write-Log "Subsystem:        $($peInfo.Subsystem)"
        }
        
        if ($peInfo.Characteristics.Count -gt 0) {
            Write-Log ""
            Write-Log "--- PE Characteristics ---"
            foreach ($char in $peInfo.Characteristics) {
                Write-Log "  * $char"
            }
        }
        
        if ($peInfo.RichHeader.Count -gt 0) {
            Write-Log ""
            Write-Log "--- Rich Header (Compiler/Build Tools) ---"
            Write-Log "The Rich Header contains detailed information about the compiler"
            Write-Log "and build tools used to create this executable:"
            Write-Log ""
            foreach ($entry in $peInfo.RichHeader) {
                Write-Log "  * $entry"
            }
        } else {
            Write-Log ""
            Write-Log "--- Rich Header ---"
            Write-Log "No Rich Header found (may be stripped or non-Microsoft compiler)"
        }
        
        if ($peInfo.CompilerInfo.Count -gt 0) {
            Write-Log ""
            Write-Log "--- Additional Compiler Detection ---"
            foreach ($info in $peInfo.CompilerInfo) {
                Write-Log "  * $info"
            }
        }
        
        if ($peInfo.DebugInfo.Count -gt 0) {
            Write-Log ""
            Write-Log "--- Debug Information ---"
            foreach ($debug in $peInfo.DebugInfo) {
                Write-Log "  * $debug"
            }
        }
        
        if ($peInfo.SectionHeaders.Count -gt 0) {
            Write-Log ""
            Write-Log "--- Section Headers ---"
            foreach ($section in $peInfo.SectionHeaders) {
                Write-Log "  * $section"
            }
        }
        
    } else {
        Write-Log "File Type:        Not a PE executable"
        Write-Log "Note:             Compilation information only available for PE files"
    }
} catch {
    Write-Log "ERROR retrieving compilation info: $($_.Exception.Message)"
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
Get-Content $logFile