function Get-FileTrustSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName','Path')]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    begin {
        function Format-SizeHuman {
            param([Parameter(Mandatory)][long]$Bytes)

            $kb = [math]::Round($Bytes / 1KB, 2)
            if ($kb -gt 1000) {
                $mb = [math]::Round($Bytes / 1MB, 2)
                return "$mb MB"
            }
            return "$kb KB"
        }

        function New-CertSummary {
            param([Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

            [pscustomobject]@{
                Subject       = $Cert.Subject
                Issuer        = $Cert.Issuer
                NotBefore     = $Cert.NotBefore
                NotAfter      = $Cert.NotAfter
                Thumbprint    = $Cert.Thumbprint
                SerialNumber  = $Cert.SerialNumber
                HasPrivateKey = $Cert.HasPrivateKey
            }
        }
    }

    process {
        try {
            $resolved = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
        } catch {
            Write-Error "File not found or not accessible: $FilePath"
            return
        }

        $item = Get-Item -LiteralPath $resolved -ErrorAction Stop

        # Version / metadata
        $ver = $null
        try {
            $ver = $item.VersionInfo
        } catch {
            # non-PE files won't have VersionInfo
        }

        # File Hashes
        $sha1Hash = $null
        $sha256Hash = $null

        try { $sha1Hash   = (Get-FileHash -Algorithm SHA1   -LiteralPath $resolved -ErrorAction Stop).Hash } catch {}
        try { $sha256Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolved -ErrorAction Stop).Hash } catch {}

        # Authenticode signature
        $sig = $null
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $resolved -ErrorAction Stop
        } catch {}

        $hasCert  = $false
        $certObj  = $null
        $sigStatus = "Unknown"

        if ($sig) {
            $sigStatus = $sig.Status.ToString()

            if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
                $hasCert = $true
                $certObj = New-CertSummary -Cert ([System.Security.Cryptography.X509Certificates.X509Certificate2]$sig.SignerCertificate)
            }
        }

        [pscustomobject]@{
            FileName      = $item.Name
            FullPath      = $item.FullName
            Size          = (Format-SizeHuman -Bytes $item.Length)
            LastWriteTime = $item.LastWriteTime

            SHA1          = $sha1Hash
            SHA256        = $sha256Hash

            ProductName      = if ($ver) { $ver.ProductName } else { $null }
            FileDescription  = if ($ver) { $ver.FileDescription } else { $null }
            CompanyName      = if ($ver) { $ver.CompanyName } else { $null }
            ProductVersion   = if ($ver) { $ver.ProductVersion } else { $null }
            FileVersion      = if ($ver) { $ver.FileVersion } else { $null }
            OriginalFilename = if ($ver) { $ver.OriginalFilename } else { $null }
            Copyright        = if ($ver) { $ver.LegalCopyright } else { $null }

            SignatureStatus  = $sigStatus
            HasCertificate   = $hasCert
            Certificate      = $certObj
        }
    }
}