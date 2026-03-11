#Requires -Version 5.1
<#
.SYNOPSIS
    Malware Network Connection Analyzer for CrystalPDF / trojan.msil/barys
    Parses VirusTotal JSON report and hunts for active & historical network IOCs.

.DESCRIPTION
    This script:
    1. Parses a VirusTotal JSON behavior report to extract network IOCs
    2. Checks for ACTIVE connections to known malicious infrastructure
    3. Checks DNS cache for HISTORICAL resolution of malicious domains
    4. Inspects the local file system for known drop artifacts
    5. Produces a formatted IOC summary report

.PARAMETER VTReportPath
    Path to the VirusTotal JSON export file. If not provided, the script
    uses the hardcoded IOCs extracted from the analyzed sample.

.PARAMETER OutputPath
    Optional path to write the HTML report. Defaults to the current
    directory with a timestamped filename.

.PARAMETER IncludeRawConnections
    Switch to dump all current TCP connections in the report for
    full situational awareness.

.EXAMPLE
    .\Invoke-CrystalPDFNetworkHunt.ps1
    # Runs with embedded IOCs, outputs to console and HTML

.EXAMPLE
    .\Invoke-CrystalPDFNetworkHunt.ps1 -VTReportPath "C:\Cases\vt_report.json" -IncludeRawConnections
    # Parses a VT JSON file and includes all active TCP connections

.NOTES
    Author  : Ghost-Glitch04
    Date    : 2026-03-11
    Version : 1.0
    Threat  : CrystalPDF.exe / trojan.msil/barys
    SHA256  : 2252b67088e9fd0fec7f4a96fe442a7e4d77e9a5bb8ef803b8056a50ef19ea60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$VTReportPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\CrystalPDF_Hunt_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [switch]$IncludeRawConnections
)

# ============================================================================
# SECTION 0: BANNER & INITIALIZATION
# ============================================================================

$banner = @"

   ██████╗██████╗ ██╗   ██╗███████╗████████╗ █████╗ ██╗     
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██║     
  ██║     ██████╔╝ ╚████╔╝ ███████╗   ██║   ███████║██║     
  ██║     ██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██╔══██║██║     
  ╚██████╗██║  ██║   ██║   ███████║   ██║   ██║  ██║███████╗
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
        Network IOC Hunter — CrystalPDF / trojan.msil/barys
        Analyst: $env:USERNAME | Host: $env:COMPUTERNAME
        Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)

"@

Write-Host $banner -ForegroundColor Cyan

# Global results collector
$Script:Results = [ordered]@{
    ScanTimestamp       = (Get-Date -Format 'o')
    Hostname            = $env:COMPUTERNAME
    Analyst             = $env:USERNAME
    ThreatName          = "CrystalPDF / trojan.msil/barys"
    SHA256              = "2252b67088e9fd0fec7f4a96fe442a7e4d77e9a5bb8ef803b8056a50ef19ea60"
    IOCsExtracted       = @()
    ActiveConnections   = @()
    DNSCacheHits        = @()
    FileArtifacts       = @()
    ProcessHits         = @()
    OverallVerdict      = "CLEAN"
    FindingsCount       = 0
}

# ============================================================================
# SECTION 1: IOC EXTRACTION — Parse VT Report or Use Hardcoded IOCs
# ============================================================================

function Extract-IOCsFromVTReport {
    <#
    .SYNOPSIS
        Extracts network IOCs from a VirusTotal JSON behavior report.
    #>
    param([string]$ReportPath)

    $iocs = @{
        MaliciousDomains = [System.Collections.Generic.List[string]]::new()
        MaliciousIPs     = [System.Collections.Generic.List[string]]::new()
        MaliciousURLs    = [System.Collections.Generic.List[string]]::new()
        JA3Hashes        = [System.Collections.Generic.List[string]]::new()
        FileArtifacts    = [System.Collections.Generic.List[string]]::new()
        C2Endpoints      = [System.Collections.Generic.List[string]]::new()
    }

    if ($ReportPath -and (Test-Path $ReportPath)) {
        Write-Host "[*] Parsing VirusTotal JSON report: $ReportPath" -ForegroundColor Yellow

        try {
            $vtData = Get-Content -Path $ReportPath -Raw | ConvertFrom-Json

            # Handle both single object and array formats
            $behaviors = @()
            if ($vtData -is [array]) {
                $behaviors = $vtData
            } else {
                $behaviors = @($vtData)
            }

            foreach ($entry in $behaviors) {
                # Extract DNS lookups
                if ($entry.dns_lookups) {
                    foreach ($dns in $entry.dns_lookups) {
                        if ($dns.hostname -and
                            $dns.hostname -notmatch '(microsoft|windows|akamai|msn|msedge)') {
                            if (-not $iocs.MaliciousDomains.Contains($dns.hostname)) {
                                $iocs.MaliciousDomains.Add($dns.hostname)
                            }
                        }
                        if ($dns.resolved_ips) {
                            foreach ($ip in $dns.resolved_ips) {
                                if (-not $iocs.MaliciousIPs.Contains($ip)) {
                                    $iocs.MaliciousIPs.Add($ip)
                                }
                            }
                        }
                    }
                }

                # Extract HTTP conversations
                if ($entry.http_conversations) {
                    foreach ($http in $entry.http_conversations) {
                        if ($http.url -and -not $iocs.C2Endpoints.Contains($http.url)) {
                            $iocs.C2Endpoints.Add($http.url)
                        }
                    }
                }

                # Extract IP traffic
                if ($entry.ip_traffic) {
                    foreach ($traffic in $entry.ip_traffic) {
                        $ip = $traffic.destination_ip
                        if ($ip -and $ip -notmatch '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)' -and
                            $ip -notmatch ':') {
                            if (-not $iocs.MaliciousIPs.Contains($ip)) {
                                $iocs.MaliciousIPs.Add($ip)
                            }
                        }
                    }
                }

                # Extract JA3 digests
                if ($entry.ja3_digests) {
                    foreach ($ja3 in $entry.ja3_digests) {
                        if (-not $iocs.JA3Hashes.Contains($ja3)) {
                            $iocs.JA3Hashes.Add($ja3)
                        }
                    }
                }

                # Extract memory pattern URLs
                if ($entry.memory_pattern_urls) {
                    foreach ($url in $entry.memory_pattern_urls) {
                        if ($url -match '(ramiort|strongdwn|windwn|crystalpdf)') {
                            if (-not $iocs.MaliciousURLs.Contains($url)) {
                                $iocs.MaliciousURLs.Add($url)
                            }
                        }
                    }
                }

                # Extract memory pattern domains
                if ($entry.memory_pattern_domains) {
                    foreach ($domain in $entry.memory_pattern_domains) {
                        if ($domain -match '(ramiort|strongdwn|windwn|crystalpdf)') {
                            if (-not $iocs.MaliciousDomains.Contains($domain)) {
                                $iocs.MaliciousDomains.Add($domain)
                            }
                        }
                    }
                }

                # Extract file drop paths
                if ($entry.files_dropped) {
                    foreach ($file in $entry.files_dropped) {
                        $path = if ($file.path) { $file.path } else { $file }
                        if ($path -match '(FMCR|userId\.txt|CrystalPDF)') {
                            if (-not $iocs.FileArtifacts.Contains($path)) {
                                $iocs.FileArtifacts.Add($path)
                            }
                        }
                    }
                }
            }

            Write-Host "[+] Extracted IOCs from JSON report successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Failed to parse JSON report: $_" -ForegroundColor Red
            Write-Host "[*] Falling back to hardcoded IOCs..." -ForegroundColor Yellow
            return $null
        }
    }
    else {
        return $null
    }

    return $iocs
}

function Get-HardcodedIOCs {
    <#
    .SYNOPSIS
        Returns hardcoded IOCs extracted from the VT report analysis.
        Fallback when no JSON file is provided.
    #>
    return @{
        MaliciousDomains = @(
            "ramiort.com"           # Primary C2 server
            "strongdwn.com"         # Secondary C2 — download/convert ops
            "cnvr.windwn.com"       # Tertiary C2 — API endpoint
            "crystalpdf.com"        # Lure/social engineering domain
        )
        MaliciousIPs = @(
            "104.18.30.156"         # ramiort.com resolution
            "104.18.31.156"         # ramiort.com resolution (secondary)
        )
        MaliciousURLs = @(
            "https://ramiort.com/Cry"           # C2 POST endpoint
            "https://ramiort.com/st"            # C2 status endpoint
            "https://strongdwn.com/convert"     # Payload conversion
            "https://strongdwn.com/initiate"    # Initiation endpoint
            "https://strongdwn.com/merge"       # Payload merge
            "https://strongdwn.com/abg"         # Unknown C2 function
            "https://cnvr.windwn.com/api"       # API C2 endpoint
            "https://crystalpdf.com/policy"     # Lure page
            "https://crystalpdf.com/conditions" # Lure page
        )
        JA3Hashes = @(
            "3b5074b1b5d032e5620f69f9f700ff0e"  # CAPE sandbox TLS fingerprint
            "2d0c1aa81856c537394b05616d38dbae"  # Jujubox sandbox TLS fingerprint
            "3c4eb72b882d4d1442c67ce73f1292a9"  # Zenbox sandbox TLS fingerprint
        )
        FileArtifacts = @(
            "$env:APPDATA\FMCR"                         # Drop directory
            "$env:APPDATA\FMCR\userId.txt"              # User tracking file
            "$env:LOCALAPPDATA\Microsoft\CLR_v4.0\UsageLogs\CrystalPDF.exe.log"
        )
        C2Endpoints = @(
            "https://ramiort.com/Cry"   # Primary — confirmed POST with 200 response
        )
        ProcessNames = @(
            "CrystalPDF"
            "CrystalPDF.exe"
        )
        CertificateThumbprints = @(
            "ECE7440C53C235E5E69E57EACB9250154AF20DE0"  # LONG SOUND LTD — REVOKED
        )
        MITREATTCKTechniques = @(
            @{ ID = "T1071";     Name = "Application Layer Protocol" }
            @{ ID = "T1573";     Name = "Encrypted Channel (HTTPS)" }
            @{ ID = "T1082";     Name = "System Information Discovery" }
            @{ ID = "T1033";     Name = "System Owner/User Discovery" }
            @{ ID = "T1083";     Name = "File and Directory Discovery" }
            @{ ID = "T1057";     Name = "Process Discovery" }
            @{ ID = "T1027";     Name = "Obfuscated Files or Information" }
            @{ ID = "T1140";     Name = "Deobfuscate/Decode Files" }
            @{ ID = "T1620";     Name = "Reflective Code Loading" }
            @{ ID = "T1497";     Name = "Virtualization/Sandbox Evasion" }
            @{ ID = "T1070.006"; Name = "Timestomp" }
        )
    }
}

# Load IOCs
$iocs = $null
if ($VTReportPath) {
    $iocs = Extract-IOCsFromVTReport -ReportPath $VTReportPath
}
if (-not $iocs) {
    Write-Host "[*] Using hardcoded IOCs from analyzed VT report..." -ForegroundColor Yellow
    $iocs = Get-HardcodedIOCs
}

# Populate results
$Script:Results.IOCsExtracted = $iocs

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  IOCs LOADED" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  Malicious Domains : $($iocs.MaliciousDomains.Count)" -ForegroundColor White
Write-Host "  Malicious IPs     : $($iocs.MaliciousIPs.Count)" -ForegroundColor White
Write-Host "  Malicious URLs    : $($iocs.MaliciousURLs.Count)" -ForegroundColor White
Write-Host "  JA3 Fingerprints  : $($iocs.JA3Hashes.Count)" -ForegroundColor White
Write-Host "  File Artifacts    : $($iocs.FileArtifacts.Count)" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# ============================================================================
# SECTION 2: ACTIVE CONNECTION CHECK
# ============================================================================

function Test-ActiveConnections {
    <#
    .SYNOPSIS
        Checks all current TCP connections against known malicious IPs and
        resolves remote addresses to check against malicious domains.
    #>
    param([hashtable]$IOCs)

    Write-Host "[*] Checking ACTIVE network connections..." -ForegroundColor Yellow

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $_.State -eq 'Established' -or $_.State -eq 'SynSent' -or $_.State -eq 'TimeWait' }

        if (-not $connections) {
            Write-Host "  [!] Unable to retrieve TCP connections (may need elevation)." -ForegroundColor Red
            return $findings
        }

        $totalConns = $connections.Count
        Write-Host "  [*] Inspecting $totalConns active/recent TCP connections..." -ForegroundColor Gray

        $checkedIPs = @{}

        foreach ($conn in $connections) {
            $remoteIP   = $conn.RemoteAddress
            $remotePort = $conn.RemotePort
            $localPort  = $conn.LocalPort
            $state      = $conn.State
            $pid        = $conn.OwningProcess

            # Skip loopback and link-local
            if ($remoteIP -match '^(127\.|::1|0\.0\.0\.|fe80)') { continue }

            # Get process name
            $procName = "Unknown"
            try {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc) { $procName = $proc.ProcessName }
            } catch {}

            # --- Check 1: Direct IP match ---
            $ipMatch = $false
            foreach ($malIP in $IOCs.MaliciousIPs) {
                if ($remoteIP -eq $malIP) {
                    $ipMatch = $true
                    $finding = [PSCustomObject]@{
                        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        Type        = "ACTIVE_CONNECTION"
                        Severity    = "CRITICAL"
                        RemoteIP    = $remoteIP
                        RemotePort  = $remotePort
                        LocalPort   = $localPort
                        State       = $state
                        ProcessName = $procName
                        PID         = $pid
                        MatchedIOC  = $malIP
                        MatchType   = "Direct IP Match"
                        Detail      = "Active connection to known C2 IP: $malIP"
                    }
                    $findings.Add($finding)
                    Write-Host "  [!!] CRITICAL: Active connection to C2 IP $remoteIP`:$remotePort (PID: $pid / $procName)" -ForegroundColor Red
                }
            }

            # --- Check 2: Reverse DNS lookup to match domains ---
            if (-not $ipMatch -and -not $checkedIPs.ContainsKey($remoteIP)) {
                $checkedIPs[$remoteIP] = $true
                try {
                    $dnsResult = [System.Net.Dns]::GetHostEntry($remoteIP)
                    $hostName  = $dnsResult.HostName

                    foreach ($malDomain in $IOCs.MaliciousDomains) {
                        if ($hostName -like "*$malDomain*") {
                            $finding = [PSCustomObject]@{
                                Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                                Type        = "ACTIVE_CONNECTION"
                                Severity    = "CRITICAL"
                                RemoteIP    = $remoteIP
                                RemotePort  = $remotePort
                                LocalPort   = $localPort
                                State       = $state
                                ProcessName = $procName
                                PID         = $pid
                                MatchedIOC  = $malDomain
                                MatchType   = "Reverse DNS Match"
                                Detail      = "Connection resolves to malicious domain: $hostName (matched: $malDomain)"
                            }
                            $findings.Add($finding)
                            Write-Host "  [!!] CRITICAL: Connection to $remoteIP resolves to $hostName (C2: $malDomain)" -ForegroundColor Red
                        }
                    }
                } catch {
                    # Reverse DNS failed — not unusual
                }
            }

            # --- Check 3: Known C2 port patterns (443 to suspicious IPs in Cloudflare range) ---
            if ($remotePort -eq 443 -and -not $ipMatch) {
                # Check if the IP is in the 104.18.x.x range (Cloudflare — used by ramiort.com)
                if ($remoteIP -match '^104\.18\.\d+\.\d+$') {
                    $finding = [PSCustomObject]@{
                        Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        Type        = "ACTIVE_CONNECTION"
                        Severity    = "MEDIUM"
                        RemoteIP    = $remoteIP
                        RemotePort  = $remotePort
                        LocalPort   = $localPort
                        State       = $state
                        ProcessName = $procName
                        PID         = $pid
                        MatchedIOC  = "104.18.0.0/16 (Cloudflare range used by ramiort.com)"
                        MatchType   = "Subnet Proximity"
                        Detail      = "HTTPS connection to Cloudflare IP in same /16 as C2. Needs validation."
                    }
                    $findings.Add($finding)
                    Write-Host "  [?] MEDIUM: HTTPS to Cloudflare IP $remoteIP`:443 — same subnet as C2 (PID: $pid / $procName)" -ForegroundColor DarkYellow
                }
            }
        }

        if ($findings.Count -eq 0) {
            Write-Host "  [+] No active connections to known C2 infrastructure detected." -ForegroundColor Green
        }

    } catch {
        Write-Host "  [!] Error checking connections: $_" -ForegroundColor Red
    }

    return $findings
}

$Script:Results.ActiveConnections = @(Test-ActiveConnections -IOCs $iocs)
Write-Host ""

# ============================================================================
# SECTION 3: DNS CACHE INSPECTION (Historical Connections)
# ============================================================================

function Test-DNSCache {
    <#
    .SYNOPSIS
        Inspects the local DNS resolver cache for historical resolutions
        of known malicious domains.
    #>
    param([hashtable]$IOCs)

    Write-Host "[*] Checking DNS resolver cache for HISTORICAL connections..." -ForegroundColor Yellow

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue

        if (-not $dnsCache) {
            Write-Host "  [!] Unable to retrieve DNS cache. Trying ipconfig /displaydns..." -ForegroundColor DarkYellow

            # Fallback: parse ipconfig /displaydns
            $rawDns = ipconfig /displaydns 2>&1 | Out-String
            foreach ($domain in $IOCs.MaliciousDomains) {
                if ($rawDns -match [regex]::Escape($domain)) {
                    $finding = [PSCustomObject]@{
                        Timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                        Type       = "DNS_CACHE_HIT"
                        Severity   = "HIGH"
                        Domain     = $domain
                        ResolvedIP = "See ipconfig /displaydns output"
                        TTL        = "N/A"
                        RecordType = "N/A"
                        MatchedIOC = $domain
                        Detail     = "Malicious domain found in DNS cache (ipconfig fallback): $domain"
                    }
                    $findings.Add($finding)
                    Write-Host "  [!!] HIGH: '$domain' found in DNS cache!" -ForegroundColor Red
                }
            }
        }
        else {
            foreach ($entry in $dnsCache) {
                foreach ($domain in $IOCs.MaliciousDomains) {
                    if ($entry.Entry -like "*$domain*") {
                        $finding = [PSCustomObject]@{
                            Timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                            Type       = "DNS_CACHE_HIT"
                            Severity   = "HIGH"
                            Domain     = $entry.Entry
                            ResolvedIP = $entry.Data
                            TTL        = $entry.TimeToLive
                            RecordType = $entry.Type
                            MatchedIOC = $domain
                            Detail     = "Historical DNS resolution: $($entry.Entry) -> $($entry.Data)"
                        }
                        $findings.Add($finding)
                        Write-Host "  [!!] HIGH: DNS cache hit for '$($entry.Entry)' -> $($entry.Data) (TTL: $($entry.TimeToLive)s)" -ForegroundColor Red
                    }
                }
            }
        }

        # Also attempt forward lookups to see if domains currently resolve
        Write-Host "  [*] Attempting forward DNS resolution of C2 domains..." -ForegroundColor Gray
        foreach ($domain in $IOCs.MaliciousDomains) {
            try {
                $resolve = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue -DnsOnly
                if ($resolve) {
                    foreach ($record in $resolve) {
                        $ip = if ($record.IPAddress) { $record.IPAddress } else { $record.NameHost }
                        Write-Host "  [i] '$domain' currently resolves to: $ip (Type: $($record.Type))" -ForegroundColor Gray
                    }
                }
            } catch {
                Write-Host "  [i] '$domain' does not resolve (may be taken down)." -ForegroundColor DarkGray
            }
        }

        if ($findings.Count -eq 0) {
            Write-Host "  [+] No malicious domains found in DNS cache." -ForegroundColor Green
        }

    } catch {
        Write-Host "  [!] Error checking DNS cache: $_" -ForegroundColor Red
    }

    return $findings
}

$Script:Results.DNSCacheHits = @(Test-DNSCache -IOCs $iocs)
Write-Host ""

# ============================================================================
# SECTION 4: FILE ARTIFACT CHECK
# ============================================================================

function Test-FileArtifacts {
    <#
    .SYNOPSIS
        Checks for known file drop artifacts on disk.
    #>
    param([hashtable]$IOCs)

    Write-Host "[*] Checking for FILE ARTIFACTS on disk..." -ForegroundColor Yellow

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check defined artifact paths
    foreach ($artifactPath in $IOCs.FileArtifacts) {
        # Expand environment variables
        $expandedPath = [Environment]::ExpandEnvironmentVariables($artifactPath)

        if (Test-Path $expandedPath) {
            $item = Get-Item $expandedPath -ErrorAction SilentlyContinue
            $finding = [PSCustomObject]@{
                Timestamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Type         = "FILE_ARTIFACT"
                Severity     = "HIGH"
                Path         = $expandedPath
                Exists       = $true
                Size         = if ($item.PSIsContainer) { "Directory" } else { "$([math]::Round($item.Length / 1KB, 2)) KB" }
                Created      = $item.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                LastModified = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                LastAccessed = $item.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')
                MatchedIOC   = $artifactPath
                Detail       = "Known malware artifact found on disk: $expandedPath"
            }
            $findings.Add($finding)
            Write-Host "  [!!] HIGH: Artifact FOUND — $expandedPath" -ForegroundColor Red
            Write-Host "       Created: $($item.CreationTime) | Modified: $($item.LastWriteTime)" -ForegroundColor DarkYellow
        }
        else {
            Write-Host "  [+] Not found: $expandedPath" -ForegroundColor Green
        }
    }

    # Additional scan: search for CrystalPDF.exe across common locations
    Write-Host "  [*] Scanning for CrystalPDF.exe in common locations..." -ForegroundColor Gray
    $searchPaths = @(
        "$env:USERPROFILE\Desktop"
        "$env:USERPROFILE\Downloads"
        "$env:TEMP"
        "$env:APPDATA"
        "$env:LOCALAPPDATA\Temp"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $found = Get-ChildItem -Path $searchPath -Filter "CrystalPDF*" -Recurse -ErrorAction SilentlyContinue
            foreach ($f in $found) {
                $finding = [PSCustomObject]@{
                    Timestamp    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Type         = "FILE_ARTIFACT"
                    Severity     = "CRITICAL"
                    Path         = $f.FullName
                    Exists       = $true
                    Size         = "$([math]::Round($f.Length / 1KB, 2)) KB"
                    Created      = $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    LastModified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    LastAccessed = $f.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss')
                    MatchedIOC   = "CrystalPDF binary"
                    Detail       = "CrystalPDF binary or related file found: $($f.FullName)"
                }
                $findings.Add($finding)
                Write-Host "  [!!] CRITICAL: CrystalPDF file found — $($f.FullName)" -ForegroundColor Red
            }
        }
    }

    if ($findings.Count -eq 0) {
        Write-Host "  [+] No known file artifacts detected." -ForegroundColor Green
    }

    return $findings
}

$Script:Results.FileArtifacts = @(Test-FileArtifacts -IOCs $iocs)
Write-Host ""

# ============================================================================
# SECTION 5: PROCESS CHECK
# ============================================================================

function Test-RunningProcesses {
    <#
    .SYNOPSIS
        Checks for running processes matching the malware.
    #>
    param([hashtable]$IOCs)

    Write-Host "[*] Checking for RUNNING PROCESSES matching malware..." -ForegroundColor Yellow

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($proc in $processes) {
        foreach ($malProc in $IOCs.ProcessNames) {
            $matchName = $malProc -replace '\.exe$', ''
            if ($proc.ProcessName -eq $matchName) {
                $finding = [PSCustomObject]@{
                    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Type        = "RUNNING_PROCESS"
                    Severity    = "CRITICAL"
                    ProcessName = $proc.ProcessName
                    PID         = $proc.Id
                    Path        = try { $proc.Path } catch { "Access Denied" }
                    StartTime   = try { $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { "N/A" }
                    MemoryMB    = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    MatchedIOC  = $malProc
                    Detail      = "Malware process actively running: $($proc.ProcessName) (PID: $($proc.Id))"
                }
                $findings.Add($finding)
                Write-Host "  [!!] CRITICAL: '$($proc.ProcessName)' is RUNNING — PID: $($proc.Id)" -ForegroundColor Red
            }
        }
    }

    # Also check for the FMCR directory access pattern via handle (heuristic)
    foreach ($proc in $processes) {
        try {
            $modules = $proc.Modules | Where-Object { $_.FileName -match 'CrystalPDF' }
            if ($modules) {
                $finding = [PSCustomObject]@{
                    Timestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    Type        = "LOADED_MODULE"
                    Severity    = "HIGH"
                    ProcessName = $proc.ProcessName
                    PID         = $proc.Id
                    Path        = $modules.FileName -join "; "
                    StartTime   = try { $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { "N/A" }
                    MemoryMB    = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    MatchedIOC  = "CrystalPDF module"
                    Detail      = "Process has CrystalPDF module loaded: $($proc.ProcessName)"
                }
                $findings.Add($finding)
                Write-Host "  [!!] HIGH: Process '$($proc.ProcessName)' (PID: $($proc.Id)) has CrystalPDF module loaded!" -ForegroundColor Red
            }
        } catch {}
    }

    if ($findings.Count -eq 0) {
        Write-Host "  [+] No malware processes detected." -ForegroundColor Green
    }

    return $findings
}

$Script:Results.ProcessHits = @(Test-RunningProcesses -IOCs $iocs)
Write-Host ""

# ============================================================================
# SECTION 6: REGISTRY CHECK (Persistence / Tracing Artifacts)
# ============================================================================

function Test-RegistryArtifacts {
    Write-Host "[*] Checking REGISTRY for malware tracing artifacts..." -ForegroundColor Yellow

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Tracing\CrystalPDF_RASAPI32"
        "HKLM:\SOFTWARE\Microsoft\Tracing\CrystalPDF_RASMANCS"
    )

    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $finding = [PSCustomObject]@{
                Timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                Type       = "REGISTRY_ARTIFACT"
                Severity   = "HIGH"
                Path       = $regPath
                Detail     = "CrystalPDF tracing registry key exists — indicates prior execution"
            }
            $findings.Add($finding)
            Write-Host "  [!!] HIGH: Registry key found — $regPath" -ForegroundColor Red

            # Dump values
            try {
                $values = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($values) {
                    Write-Host "       FileDirectory   : $($values.FileDirectory)" -ForegroundColor DarkYellow
                    Write-Host "       EnableFileTracing: $($values.EnableFileTracing)" -ForegroundColor DarkYellow
                }
            } catch {}
        }
        else {
            Write-Host "  [+] Not found: $regPath" -ForegroundColor Green
        }
    }

    return $findings
}

$registryFindings = @(Test-RegistryArtifacts)
Write-Host ""

# ============================================================================
# SECTION 7: DETERMINE OVERALL VERDICT
# ============================================================================

$allFindings = @()
$allFindings += $Script:Results.ActiveConnections
$allFindings += $Script:Results.DNSCacheHits
$allFindings += $Script:Results.FileArtifacts
$allFindings += $Script:Results.ProcessHits
$allFindings += $registryFindings

$Script:Results.FindingsCount = $allFindings.Count

$criticalCount = ($allFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count

if ($criticalCount -gt 0) {
    $Script:Results.OverallVerdict = "CRITICAL — ACTIVE COMPROMISE DETECTED"
}
elseif ($highCount -gt 0) {
    $Script:Results.OverallVerdict = "HIGH — HISTORICAL COMPROMISE INDICATORS FOUND"
}
elseif ($mediumCount -gt 0) {
    $Script:Results.OverallVerdict = "MEDIUM — SUSPICIOUS ACTIVITY DETECTED"
}
else {
    $Script:Results.OverallVerdict = "CLEAN — NO IOCs DETECTED ON THIS HOST"
}

# ============================================================================
# SECTION 8: CONSOLE REPORT
# ============================================================================

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor White
Write-Host "║              CRYSTALPDF NETWORK HUNT — FINAL REPORT            ║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  Scan Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC' -AsUTC)                    ║" -ForegroundColor White
Write-Host "║  Host         : $($env:COMPUTERNAME.PadRight(40))║" -ForegroundColor White
Write-Host "║  Analyst      : $($env:USERNAME.PadRight(40))║" -ForegroundColor White
Write-Host "   ══════════════════════════════════════════════════════════════════╣" -ForegroundColor White

$verdictColor = switch -Wildcard ($Script:Results.OverallVerdict) {
    "CRITICAL*" { "Red" }
    "HIGH*"     { "DarkYellow" }
    "MEDIUM*"   { "Yellow" }
    default     { "Green" }
}

Write-Host "║  VERDICT: " -ForegroundColor White -NoNewline
Write-Host "$($Script:Results.OverallVerdict)" -ForegroundColor $verdictColor
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  Findings Summary:                                             ║" -ForegroundColor White
Write-Host "║    Active C2 Connections : $($Script:Results.ActiveConnections.Count.ToString().PadRight(36))║" -ForegroundColor $(if ($Script:Results.ActiveConnections.Count -gt 0) { "Red" } else { "Green" })
Write-Host "║    DNS Cache Hits        : $($Script:Results.DNSCacheHits.Count.ToString().PadRight(36))║" -ForegroundColor $(if ($Script:Results.DNSCacheHits.Count -gt 0) { "Red" } else { "Green" })
Write-Host "║    File Artifacts        : $($Script:Results.FileArtifacts.Count.ToString().PadRight(36))║" -ForegroundColor $(if ($Script:Results.FileArtifacts.Count -gt 0) { "Red" } else { "Green" })
Write-Host "║    Malware Processes     : $($Script:Results.ProcessHits.Count.ToString().PadRight(36))║" -ForegroundColor $(if ($Script:Results.ProcessHits.Count -gt 0) { "Red" } else { "Green" })
Write-Host "║    Registry Artifacts    : $($registryFindings.Count.ToString().PadRight(36))║" -ForegroundColor $(if ($registryFindings.Count -gt 0) { "Red" } else { "Green" })
Write-Host "║    ──────────────────────────────────────                      ║" -ForegroundColor DarkGray
Write-Host "║    TOTAL FINDINGS        : $($allFindings.Count.ToString().PadRight(36))║" -ForegroundColor White
Write-Host "╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor White
Write-Host "║  IOC Reference Table:                                          ║" -ForegroundColor White
Write-Host "║  ┌────────────┬──────────────────────────┬─────────────────┐   ║" -ForegroundColor DarkGray
Write-Host "║  │ Type       │ Indicator                │ Role            │   ║" -ForegroundColor DarkGray
Write-Host "║  ├──  ─────────┼──────────────────────────┼─────────────────┤   ║" -ForegroundColor DarkGray
Write-Host "║  │ Domain     │ ramiort.com              │ Primary C2      │   ║" -ForegroundColor White
Write-Host "║  │ Domain     │ strongdwn.com            │ Secondary C2    │   ║" -ForegroundColor White
Write-Host "║  │ Domain     │ cnvr.windwn.com          │ Tertiary C2     │   ║" -ForegroundColor White
Write-Host "║  │ Domain     │ crystalpdf.com           │ Lure Domain     │   ║" -ForegroundColor White
Write-Host "║  │ IP         │ 104.18.30.156            │ C2 Resolution   │   ║" -ForegroundColor White
Write-Host "║  │ IP         │ 104.18.31.156            │ C2 Resolution   │   ║" -ForegroundColor White
Write-Host "║  │ URL        │ ramiort.com/Cry          │ C2 POST EP      │   ║" -ForegroundColor White
Write-Host "║  │ File       │ %APPDATA%\FMCR\userId.txt│ Tracking File   │   ║" -ForegroundColor White
Write-Host "║  │ Cert       │ ECE744...(REVOKED)       │ Code Signing    │   ║" -ForegroundColor White
Write-Host "║  └────────────┴──────────────────────────┴─────────────────┘   ║" -ForegroundColor DarkGray
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor White

# Detail each finding
if ($allFindings.Count -gt 0) {
    Write-Host ""
    Write-Host "┌──────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkYellow
    Write-Host "│                      DETAILED FINDINGS                           │" -ForegroundColor DarkYellow
    Write-Host "└──────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkYellow

    $i = 1
    foreach ($finding in $allFindings) {
        $sevColor = switch ($finding.Severity) {
            "CRITICAL" { "Red" }
            "HIGH"     { "DarkYellow" }
            "MEDIUM"   { "Yellow" }
            default    { "Gray" }
        }

        Write-Host ""
        Write-Host "  Finding #$i" -ForegroundColor White
        Write-Host "  ─────────" -ForegroundColor DarkGray
        Write-Host "  Severity   : " -NoNewline -ForegroundColor Gray
        Write-Host "$($finding.Severity)" -ForegroundColor $sevColor
        Write-Host "  Type       : $($finding.Type)" -ForegroundColor Gray
        Write-Host "  Detail     : $($finding.Detail)" -ForegroundColor Gray
        Write-Host "  Matched IOC: $($finding.MatchedIOC)" -ForegroundColor Gray
        Write-Host "  Timestamp  : $($finding.Timestamp)" -ForegroundColor DarkGray
        $i++
    }
}

# ============================================================================
# SECTION 9: HTML REPORT GENERATION
# ============================================================================

function Export-HTMLReport {
    param(
        [hashtable]$Results,
        [array]$AllFindings,
        [array]$RegistryFindings,
        [string]$OutputPath
    )

    Write-Host ""
    Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow

    $verdictBgColor = switch -Wildcard ($Results.OverallVerdict) {
        "CRITICAL*" { "#dc3545" }
        "HIGH*"     { "#fd7e14" }
        "MEDIUM*"   { "#ffc107" }
        default     { "#28a745" }
    }

    $findingsHTML = ""
    foreach ($f in $AllFindings) {
        $rowColor = switch ($f.Severity) {
            "CRITICAL" { "#f8d7da" }
            "HIGH"     { "#fff3cd" }
            "MEDIUM"   { "#ffeeba" }
            default    { "#d4edda" }
        }
        $findingsHTML += @"
        <tr style="background-color: $rowColor;">
            <td>$($f.Timestamp)</td>
            <td><strong>$($f.Severity)</strong></td>
            <td>$($f.Type)</td>
            <td>$($f.Detail)</td>
            <td><code>$($f.MatchedIOC)</code></td>
        </tr>
"@
    }

    if (-not $findingsHTML) {
        $findingsHTML = '<tr><td colspan="5" style="text-align:center; color:green;">No findings — host appears clean.</td></tr>'
    }

    $mitreHTML = ""
    if ($Results.IOCsExtracted.MITREATTCKTechniques) {
        foreach ($t in $Results.IOCsExtracted.MITREATTCKTechniques) {
            $mitreHTML += "<tr><td><a href='https://attack.mitre.org/techniques/$($t.ID -replace '\.','/')/' target='_blank'>$($t.ID)</a></td><td>$($t.Name)</td></tr>"
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CrystalPDF Network Hunt Report — $($Results.Hostname)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #00d4ff; margin: 20px 0 10px 0; border-left: 4px solid #00d4ff; padding-left: 10px; }
        .verdict-box { background: $verdictBgColor; color: #fff; padding: 20px; border-radius: 8px; text-align: center; font-size: 1.4em; font-weight: bold; margin: 20px 0; }
        .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0; }
        .meta-item { background: #16213e; padding: 10px; border-radius: 4px; }
        .meta-item strong { color: #00d4ff; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #0f3460; color: #00d4ff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #333; color: #222; }
        tr:hover { opacity: 0.9; }
        .ioc-table td { color: #eee; background: #16213e; }
        .ioc-table tr:hover { background: #1a1a4e; }
        code { background: #0a0a23; color: #00ff88; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 15px 0; }
        .stat-box { background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-box .number { font-size: 2em; font-weight: bold; }
        .stat-box .label { color: #aaa; font-size: 0.9em; }
        .stat-critical .number { color: #dc3545; }
        .stat-high .number { color: #fd7e14; }
        .stat-medium .number { color: #ffc107; }
        .stat-clean .number { color: #28a745; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.8em; }
        a { color: #00d4ff; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 CrystalPDF / trojan.msil/barys — Network IOC Hunt Report</h1>

    <div class="meta-grid">
        <div class="meta-item"><strong>Hostname:</strong> $($Results.Hostname)</div>
        <div class="meta-item"><strong>Analyst:</strong> $($Results.Analyst)</div>
        <div class="meta-item"><strong>Scan Time:</strong> $($Results.ScanTimestamp)</div>
        <div class="meta-item"><strong>Malware SHA256:</strong> <code>$($Results.SHA256.Substring(0,16))...</code></div>
    </div>

    <div class="verdict-box">$($Results.OverallVerdict)</div>

    <div class="stats">
        <div class="stat-box stat-critical">
            <div class="number">$($Results.ActiveConnections.Count)</div>
            <div class="label">Active C2 Connections</div>
        </div>
        <div class="stat-box stat-high">
            <div class="number">$($Results.DNSCacheHits.Count)</div>
            <div class="label">DNS Cache Hits</div>
        </div>
        <div class="stat-box stat-high">
            <div class="number">$($Results.FileArtifacts.Count)</div>
            <div class="label">File Artifacts</div>
        </div>
        <div class="stat-box stat-critical">
            <div class="number">$($Results.ProcessHits.Count)</div>
            <div class="label">Malware Processes</div>
        </div>
        <div class="stat-box stat-high">
            <div class="number">$($RegistryFindings.Count)</div>
            <div class="label">Registry Artifacts</div>
        </div>
    </div>

    <h2>📋 All Findings</h2>
    <table>
        <tr><th>Timestamp</th><th>Severity</th><th>Type</th><th>Detail</th><th>Matched IOC</th></tr>
        $findingsHTML
    </table>

    <h2>🎯 IOC Reference Table</h2>
    <table class="ioc-table">
        <tr><th>Type</th><th>Indicator</th><th>Role / Context</th></tr>
        <tr><td>Domain</td><td><code>ramiort.com</code></td><td>Primary C2 — HTTPS POST to /Cry</td></tr>
        <tr><td>Domain</td><td><code>strongdwn.com</code></td><td>Secondary C2 — /convert, /initiate, /merge, /abg</td></tr>
        <tr><td>Domain</td><td><code>cnvr.windwn.com</code></td><td>Tertiary C2 — /api endpoint</td></tr>
        <tr><td>Domain</td><td><code>crystalpdf.com</code></td><td>Social engineering lure domain</td></tr>
        <tr><td>IP Address</td><td><code>104.18.30.156</code></td><td>ramiort.com — Cloudflare-proxied</td></tr>
        <tr><td>IP Address</td><td><code>104.18.31.156</code></td><td>ramiort.com — Cloudflare-proxied</td></tr>
        <tr><td>URL</td><td><code>https://ramiort.com/Cry</code></td><td>C2 beacon endpoint (POST, 200 OK)</td></tr>
        <tr><td>URL</td><td><code>https://ramiort.com/st</code></td><td>C2 status endpoint</td></tr>
        <tr><td>URL</td><td><code>https://strongdwn.com/convert</code></td><td>Payload conversion endpoint</td></tr>
        <tr><td>URL</td><td><code>https://strongdwn.com/initiate</code></td><td>C2 initiation</td></tr>
        <tr><td>URL</td><td><code>https://cnvr.windwn.com/api</code></td><td>API C2 endpoint</td></tr>
        <tr><td>File Path</td><td><code>%APPDATA%\FMCR\userId.txt</code></td><td>Victim tracking/persistence artifact</td></tr>
        <tr><td>File Path</td><td><code>CrystalPDF.exe</code></td><td>Main binary (3.49 MB, .NET, PE64)</td></tr>
        <tr><td>PDB Path</td><td><code>C:\Git\f-ver2\Fv2Ui\bin\Release\...\CrystalPDF.pdb</code></td><td>Build artifact — threat actor dev path</td></tr>
        <tr><td>Certificate</td><td><code>ECE7440C53C235E5E69E57EACB9250154AF20DE0</code></td><td>LONG SOUND LTD — REVOKED code signing cert</td></tr>
        <tr><td>JA3</td><td><code>3b5074b1b5d032e5620f69f9f700ff0e</code></td><td>Malware TLS client fingerprint</td></tr>
        <tr><td>JA3</td><td><code>2d0c1aa81856c537394b05616d38dbae</code></td><td>Malware TLS client fingerprint</td></tr>
        <tr><td>SHA256</td><td><code>2252b67088e9fd0fec7f4a96fe442a7e4d77e9a5bb8ef803b8056a50ef19ea60</code></td><td>CrystalPDF.exe binary hash</td></tr>
        <tr><td>MD5</td><td><code>b2954b6fa77568b64792ab5372ca6923</code></td><td>CrystalPDF.exe binary hash</td></tr>
        <tr><td>SHA1</td><td><code>953d123b102fc12b58d976168608bf52c035465f</code></td><td>CrystalPDF.exe binary hash</td></tr>
        <tr><td>SSDEEP</td><td><code>24576:SnsHEfl7QL0zS1a4yDmkKXe8CRT1Th2Z8...</code></td><td>Fuzzy hash for similarity matching</td></tr>
    </table>

    <h2>⚔️ MITRE ATT&CK Mapping</h2>
    <table class="ioc-table">
        <tr><th>Technique ID</th><th>Name</th></tr>
        $mitreHTML
    </table>

    <h2>🔬 Threat Summary</h2>
    <table class="ioc-table">
        <tr><td><strong>Threat Label</strong></td><td>trojan.msil/barys (VT Suggested)</td></tr>
        <tr><td><strong>Detection Ratio</strong></td><td>39/76 engines (as of 2026-02-28)</td></tr>
        <tr><td><strong>File Type</strong></td><td>PE32+ executable (GUI) x86-64 Mono/.NET assembly</td></tr>
        <tr><td><strong>.NET Version</strong></td><td>v4.0.30319 | Assembly: CrystalPDF</td></tr>
        <tr><td><strong>Signer</strong></td><td>LONG SOUND LTD (GlobalSign EV Code Signing) — <span style="color:#dc3545;font-weight:bold;">REVOKED</span></td></tr>
        <tr><td><strong>Compilation Timestamp</strong></td><td>2029-08-06 (TIMESTOMPED — future date)</td></tr>
        <tr><td><strong>First Seen</strong></td><td>2025-08-13</td></tr>
        <tr><td><strong>Key Behaviors</strong></td><td>C2 over HTTPS, Base64 encoding/decoding, reflective .NET assembly loading, process enumeration, user discovery, anti-debug/anti-VM checks, file read/write/delete</td></tr>
        <tr><td><strong>Persistence</strong></td><td>Creates %APPDATA%\FMCR\userId.txt for victim tracking; registers RAS tracing keys</td></tr>
    </table>

    <div class="footer">
        <p>Generated by Invoke-CrystalPDFNetworkHunt.ps1 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>This report is for authorized incident response use only.</p>
    </div>
</div>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "[+] HTML report saved to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to write HTML report: $_" -ForegroundColor Red
    }
}

Export-HTMLReport -Results $Script:Results -AllFindings $allFindings -RegistryFindings $registryFindings -OutputPath $OutputPath

# ============================================================================
# SECTION 10: OPTIONAL — DUMP ALL CONNECTIONS
# ============================================================================

if ($IncludeRawConnections) {
    Write-Host ""
    Write-Host "[*] Dumping ALL established TCP connections for review..." -ForegroundColor Yellow
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{Name='ProcessName'; Expression={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }} |
        Format-Table -AutoSize
}

# ============================================================================
# FINAL OUTPUT
# ============================================================================

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  SCAN COMPLETE — $($allFindings.Count) finding(s)" -ForegroundColor White
Write-Host "  Verdict: " -NoNewline
Write-Host "$($Script:Results.OverallVerdict)" -ForegroundColor $verdictColor
Write-Host "  Report : $OutputPath" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# Return structured results for pipeline usage
return [PSCustomObject]$Script:Results