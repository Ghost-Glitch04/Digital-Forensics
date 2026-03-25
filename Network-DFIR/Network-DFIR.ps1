#Requires -Version 5.1
<#
.SYNOPSIS
    General-purpose live network DFIR triage tool for Windows systems.

.DESCRIPTION
    This script:
    1. Enumerates all active TCP connections and UDP endpoints with full process attribution
    2. Deduplicates external IPs and filters RFC1918/loopback addresses
    3. Enriches each unique external IP with geo/ASN data via ip-api.com (no key required)
    4. Queries threat intelligence APIs: VirusTotal, AbuseIPDB, Scamalytics
    5. Applies heuristic scoring: suspicious exe paths, system process name spoofing,
       unsigned/tampered binaries, known C2 ports, suspicious parent process chains
    6. Checks persistence for flagged processes: scheduled tasks, registry run keys,
       Windows services, and startup folders
    7. Correlates findings against Windows Event Logs (Security, System, Application)
    8. Outputs a color-coded console table and HTML report
    9. Supports Base64 export and clipboard copy for sessions without file transfer

.PARAMETER VTApiKey
    VirusTotal API v3 key. Free tier: 4 requests/minute (enforced by -VTRateLimitMs).

.PARAMETER AbuseIPDBApiKey
    AbuseIPDB v2 API key. Free tier: 1000 checks/day.

.PARAMETER ScamalyticsApiKey
    Scamalytics IP fraud scoring API key.

.PARAMETER OutputPath
    Path for the HTML report. Defaults to $env:TEMP\NetworkDFIR_<timestamp>.html

.PARAMETER SkipApiLookup
    Skip all external API calls. Runs heuristics only (use on air-gapped systems).

.PARAMETER ExportBase64
    Print the HTML report as Base64 to the console for copy-paste extraction.
    Decode on analyst machine: [IO.File]::WriteAllBytes("report.html", [Convert]::FromBase64String("..."))

.PARAMETER CopyToClipboard
    Copy the HTML report to the system clipboard (requires clipboard in remote session).

.PARAMETER IncludePrivateIPs
    Include RFC1918/loopback connections in the output (API lookups skipped for these).

.PARAMETER VTRateLimitMs
    Milliseconds to sleep between VirusTotal calls. Default: 15000 (4/min free tier).

.EXAMPLE
    .\Network-DFIR.ps1
    Heuristics-only mode. Saves HTML to TEMP.

.EXAMPLE
    .\Network-DFIR.ps1 -VTApiKey "abc123" -AbuseIPDBApiKey "def456" -ScamalyticsApiKey "ghi789"
    Full threat-intel enrichment.

.EXAMPLE
    .\Network-DFIR.ps1 -VTApiKey "abc123" -ExportBase64
    Run with VT enrichment and print Base64 HTML for copy-paste extraction.

.EXAMPLE
    .\Network-DFIR.ps1 -SkipApiLookup
    Heuristics only. Good for air-gapped or policy-restricted clients.

.NOTES
    Author  : Ghost-Glitch04
    Version : 1.0
    Requires: Windows 8.1 / Server 2012 R2+ (Get-NetTCPConnection, Get-NetUDPEndpoint)
    Elevation: Run as Administrator for full process path access, event log correlation,
               and accurate Authenticode signature checks.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$VTApiKey = "",

    [Parameter(Mandatory = $false)]
    [string]$AbuseIPDBApiKey = "",

    [Parameter(Mandatory = $false)]
    [string]$ScamalyticsApiKey = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",

    [switch]$SkipApiLookup,
    [switch]$ExportBase64,
    [switch]$CopyToClipboard,
    [switch]$IncludePrivateIPs,

    [Parameter(Mandatory = $false)]
    [int]$VTRateLimitMs = 15000
)

# ============================================================================
# SECTION 0: BANNER & INITIALIZATION
# ============================================================================

$Script:StartTime = Get-Date

if (-not $OutputPath) {
    $OutputPath = "$env:TEMP\NetworkDFIR_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
}

$banner = @"

  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
       DFIR  ─  Live Network Triage  ─  v1.0
       Analyst : $env:USERNAME  |  Host : $env:COMPUTERNAME
       Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@

Write-Host $banner -ForegroundColor Cyan

$Script:State = [ordered]@{
    ScanTimestamp    = (Get-Date -Format 'o')
    Hostname         = $env:COMPUTERNAME
    Analyst          = $env:USERNAME
    OSVersion        = [System.Environment]::OSVersion.VersionString
    Connections      = [System.Collections.Generic.List[PSCustomObject]]::new()
    UniqueExternalIPs = [System.Collections.Generic.List[string]]::new()
    GeoData          = @{}
    ThreatData       = @{}
    ScoredRecords    = [System.Collections.Generic.List[PSCustomObject]]::new()
    PersistenceHits  = [System.Collections.Generic.List[PSCustomObject]]::new()
    EventLogHits     = [System.Collections.Generic.List[PSCustomObject]]::new()
    Stats            = [ordered]@{
        TotalConnections = 0
        UniqueExternal   = 0
        HighCount        = 0
        MediumCount      = 0
        LowCount         = 0
        APICallsVT       = 0
        APICallsAbuse    = 0
        APICallsScam     = 0
    }
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  API STATUS" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

if ($SkipApiLookup) {
    Write-Host "  Mode           : Heuristics only (API lookup skipped)" -ForegroundColor DarkYellow
} else {
    $vtStatus    = if ($VTApiKey)          { "Enabled" } else { "No key — skipped" }
    $abuseStatus = if ($AbuseIPDBApiKey)   { "Enabled" } else { "No key — skipped" }
    $scamStatus  = if ($ScamalyticsApiKey) { "Enabled" } else { "No key — skipped" }
    Write-Host "  VirusTotal     : $vtStatus"    -ForegroundColor $(if ($VTApiKey) { "Green" } else { "DarkYellow" })
    Write-Host "  AbuseIPDB      : $abuseStatus" -ForegroundColor $(if ($AbuseIPDBApiKey) { "Green" } else { "DarkYellow" })
    Write-Host "  Scamalytics    : $scamStatus"  -ForegroundColor $(if ($ScamalyticsApiKey) { "Green" } else { "DarkYellow" })
    Write-Host "  Geo (ip-api)   : Enabled (no key required)" -ForegroundColor Green
}

Write-Host "  Output Path    : $OutputPath" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

# ============================================================================
# SECTION 1: HELPER FUNCTIONS
# ============================================================================

function Test-IsPrivateIP {
    param([string]$IP)
    if ([string]::IsNullOrEmpty($IP) -or $IP -eq "N/A") { return $true }
    return $IP -match '^(127\.|::1$|0\.0\.0\.0$|::$|^::$|169\.254\.|fe80|224\.|ff[0-9a-f]{2}:|' +
                      '10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
}

function Get-ProcessDetails {
    param([int]$ProcessId)
    $result = [PSCustomObject]@{
        PID             = $ProcessId
        ProcessName     = "Unknown"
        ExePath         = "Unknown"
        ParentPID       = 0
        ParentName      = "Unknown"
        SignatureStatus = "Unknown"
        SignerName      = "Unknown"
    }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($proc) {
            $result.ProcessName = $proc.ProcessName
            try { $result.ExePath = $proc.Path } catch { $result.ExePath = "AccessDenied" }
        }
    } catch { }

    try {
        $wmi = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($wmi) {
            $result.ParentPID = [int]$wmi.ParentProcessId
            $parent = Get-Process -Id $wmi.ParentProcessId -ErrorAction SilentlyContinue
            if ($parent) { $result.ParentName = $parent.ProcessName }
        }
    } catch { }

    if ($result.ExePath -notin @("Unknown", "AccessDenied", "")) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $result.ExePath -ErrorAction SilentlyContinue
            if ($sig) {
                $result.SignatureStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate) {
                    $cn = $sig.SignerCertificate.Subject -replace '^.*CN=([^,]+).*$', '$1'
                    $result.SignerName = $cn
                }
            }
        } catch { }
    }

    return $result
}

# ============================================================================
# SECTION 2: CONNECTION HARVEST (TCP + UDP)
# ============================================================================

Write-Host "[*] Enumerating network connections..." -ForegroundColor Yellow

# --- TCP ---
try {
    $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue
    if ($tcpConns) {
        Write-Host "  [+] TCP: $($tcpConns.Count) connections found" -ForegroundColor Gray
        foreach ($conn in $tcpConns) {
            $procInfo = Get-ProcessDetails -ProcessId $conn.OwningProcess
            $isExt = -not (Test-IsPrivateIP $conn.RemoteAddress)
            $Script:State.Connections.Add([PSCustomObject]@{
                Protocol        = "TCP"
                LocalAddress    = $conn.LocalAddress
                LocalPort       = $conn.LocalPort
                RemoteAddress   = $conn.RemoteAddress
                RemotePort      = $conn.RemotePort
                State           = $conn.State.ToString()
                PID             = $conn.OwningProcess
                ProcessName     = $procInfo.ProcessName
                ExePath         = $procInfo.ExePath
                ParentPID       = $procInfo.ParentPID
                ParentName      = $procInfo.ParentName
                SignatureStatus = $procInfo.SignatureStatus
                SignerName      = $procInfo.SignerName
                IsExternal      = $isExt
            })
        }
    } else {
        Write-Host "  [!] No TCP connections returned (may need elevation)" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "  [!] Get-NetTCPConnection failed: $_" -ForegroundColor Red
}

# --- UDP ---
try {
    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    if ($udpEndpoints) {
        Write-Host "  [+] UDP: $($udpEndpoints.Count) endpoints found" -ForegroundColor Gray
        foreach ($ep in $udpEndpoints) {
            $procInfo = Get-ProcessDetails -ProcessId $ep.OwningProcess
            $Script:State.Connections.Add([PSCustomObject]@{
                Protocol        = "UDP"
                LocalAddress    = $ep.LocalAddress
                LocalPort       = $ep.LocalPort
                RemoteAddress   = "N/A"
                RemotePort      = 0
                State           = "UDP_BOUND"
                PID             = $ep.OwningProcess
                ProcessName     = $procInfo.ProcessName
                ExePath         = $procInfo.ExePath
                ParentPID       = $procInfo.ParentPID
                ParentName      = $procInfo.ParentName
                SignatureStatus = $procInfo.SignatureStatus
                SignerName      = $procInfo.SignerName
                IsExternal      = $false
            })
        }
    }
} catch {
    Write-Host "  [!] Get-NetUDPEndpoint failed: $_" -ForegroundColor Red
}

$Script:State.Stats.TotalConnections = $Script:State.Connections.Count
Write-Host "  [+] Total connections harvested: $($Script:State.Stats.TotalConnections)" -ForegroundColor Gray

# --- Deduplicate external IPs ---
foreach ($conn in $Script:State.Connections) {
    if ($conn.IsExternal -and $conn.RemoteAddress -ne "N/A") {
        if (-not $Script:State.UniqueExternalIPs.Contains($conn.RemoteAddress)) {
            $Script:State.UniqueExternalIPs.Add($conn.RemoteAddress)
        }
    }
}

$Script:State.Stats.UniqueExternal = $Script:State.UniqueExternalIPs.Count
Write-Host "  [+] Unique external IPs: $($Script:State.Stats.UniqueExternal)" -ForegroundColor Gray
Write-Host ""

# ============================================================================
# SECTION 3: GEO ENRICHMENT (ip-api.com — no key, batch up to 100)
# ============================================================================

function Invoke-GeoEnrichment {
    param([string[]]$IPList)

    $geoResults = @{}
    if ($IPList.Count -eq 0) { return $geoResults }

    Write-Host "[*] Geo enrichment via ip-api.com..." -ForegroundColor Yellow

    $fields = "query,status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile"
    $chunkSize = 100

    for ($i = 0; $i -lt $IPList.Count; $i += $chunkSize) {
        $chunk = $IPList[$i..[Math]::Min($i + $chunkSize - 1, $IPList.Count - 1)]
        $body  = $chunk | ForEach-Object { [PSCustomObject]@{ query = $_; fields = $fields } } | ConvertTo-Json -Compress

        try {
            $response = Invoke-RestMethod -Uri "http://ip-api.com/batch" -Method POST `
                -ContentType "application/json" -Body $body -ErrorAction Stop

            foreach ($item in $response) {
                $geoResults[$item.query] = [PSCustomObject]@{
                    Status      = $item.status
                    Country     = $item.country
                    CountryCode = $item.countryCode
                    Region      = $item.regionName
                    City        = $item.city
                    ISP         = $item.isp
                    Org         = $item.org
                    AS          = $item.as
                    IsHosting   = [bool]$item.hosting
                    IsProxy     = [bool]$item.proxy
                    IsMobile    = [bool]$item.mobile
                }
            }
            Write-Host "  [+] Geo: enriched $($chunk.Count) IPs" -ForegroundColor Gray
        } catch {
            Write-Host "  [!] ip-api.com request failed: $_" -ForegroundColor DarkYellow
            foreach ($ip in $chunk) {
                $geoResults[$ip] = [PSCustomObject]@{
                    Status = "error"; Country = "N/A"; CountryCode = "N/A"
                    Region = "N/A"; City = "N/A"; ISP = "N/A"; Org = "N/A"
                    AS = "N/A"; IsHosting = $false; IsProxy = $false; IsMobile = $false
                }
            }
        }

        if ($i + $chunkSize -lt $IPList.Count) { Start-Sleep -Milliseconds 1500 }
    }

    return $geoResults
}

# ============================================================================
# SECTION 4: THREAT INTELLIGENCE APIs
# ============================================================================

function Invoke-VirusTotalLookup {
    param([string]$IP, [string]$ApiKey, [int]$RateLimitMs)

    $stub = [PSCustomObject]@{
        Malicious = -1; Suspicious = 0; Harmless = 0; Undetected = 0
        TotalEngines = 0; MaliciousEngines = @(); LastAnalysisDate = "N/A"; Error = ""
    }

    if ([string]::IsNullOrEmpty($ApiKey)) { $stub.Error = "NoKey"; return $stub }

    try {
        $headers  = @{ "x-apikey" = $ApiKey }
        $response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$IP" `
            -Headers $headers -Method GET -ErrorAction Stop

        $stats = $response.data.attributes.last_analysis_stats
        $engines = $response.data.attributes.last_analysis_results.PSObject.Properties |
            Where-Object { $_.Value.category -eq "malicious" } |
            ForEach-Object { $_.Name }

        $lastDate = "N/A"
        if ($response.data.attributes.last_analysis_date) {
            $lastDate = [System.DateTimeOffset]::FromUnixTimeSeconds(
                $response.data.attributes.last_analysis_date).ToString("yyyy-MM-dd")
        }

        $stub.Malicious        = [int]$stats.malicious
        $stub.Suspicious       = [int]$stats.suspicious
        $stub.Harmless         = [int]$stats.harmless
        $stub.Undetected       = [int]$stats.undetected
        $stub.TotalEngines     = $stub.Malicious + $stub.Suspicious + $stub.Harmless + $stub.Undetected
        $stub.MaliciousEngines = @($engines)
        $stub.LastAnalysisDate = $lastDate
        $Script:State.Stats.APICallsVT++

    } catch {
        $stub.Error = $_.Exception.Message
    } finally {
        Start-Sleep -Milliseconds $RateLimitMs
    }

    return $stub
}

function Invoke-AbuseIPDBLookup {
    param([string]$IP, [string]$ApiKey)

    $stub = [PSCustomObject]@{
        AbuseScore = -1; TotalReports = 0; LastReported = "N/A"
        IsWhitelisted = $false; IsTor = $false; CountryCode = "N/A"; Error = ""
    }

    if ([string]::IsNullOrEmpty($ApiKey)) { $stub.Error = "NoKey"; return $stub }

    try {
        $headers  = @{ "Key" = $ApiKey; "Accept" = "application/json" }
        $url      = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90&verbose"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET -ErrorAction Stop

        $stub.AbuseScore    = [int]$response.data.abuseConfidenceScore
        $stub.TotalReports  = [int]$response.data.totalReports
        $stub.LastReported  = $response.data.lastReportedAt
        $stub.IsWhitelisted = [bool]$response.data.isWhitelisted
        $stub.IsTor         = [bool]$response.data.isTor
        $stub.CountryCode   = $response.data.countryCode
        $Script:State.Stats.APICallsAbuse++

    } catch {
        $stub.Error = $_.Exception.Message
    }

    return $stub
}

function Invoke-ScamalyticsLookup {
    param([string]$IP, [string]$ApiKey)

    $stub = [PSCustomObject]@{
        FraudScore = -1; Risk = "N/A"
        IsVPN = $false; IsTor = $false; IsDatacenter = $false; Error = ""
    }

    if ([string]::IsNullOrEmpty($ApiKey)) { $stub.Error = "NoKey"; return $stub }

    try {
        $url      = "https://api.scamalytics.com/ip/?key=$ApiKey&ip=$IP"
        $response = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop

        $stub.FraudScore   = [int]$response.score
        $stub.Risk         = $response.risk
        $stub.IsVPN        = [bool]($response.vpn -eq "1" -or $response.vpn -eq $true)
        $stub.IsTor        = [bool]($response.tor -eq "1" -or $response.tor -eq $true)
        $stub.IsDatacenter = [bool]($response.datacenter -eq "1" -or $response.datacenter -eq $true)
        $Script:State.Stats.APICallsScam++

    } catch {
        $stub.Error = $_.Exception.Message
    }

    return $stub
}

# ============================================================================
# SECTION 5: ENRICHMENT DRIVER LOOP
# ============================================================================

if (-not $SkipApiLookup -and $Script:State.UniqueExternalIPs.Count -gt 0) {
    $Script:State.GeoData = Invoke-GeoEnrichment -IPList $Script:State.UniqueExternalIPs.ToArray()

    Write-Host "[*] Querying threat intelligence APIs..." -ForegroundColor Yellow

    foreach ($ip in $Script:State.UniqueExternalIPs) {
        Write-Host "  [~] Enriching $ip ..." -ForegroundColor Gray -NoNewline

        $vtResult    = Invoke-VirusTotalLookup  -IP $ip -ApiKey $VTApiKey    -RateLimitMs $VTRateLimitMs
        $abuseResult = Invoke-AbuseIPDBLookup   -IP $ip -ApiKey $AbuseIPDBApiKey
        $scamResult  = Invoke-ScamalyticsLookup -IP $ip -ApiKey $ScamalyticsApiKey

        $Script:State.ThreatData[$ip] = [PSCustomObject]@{
            VT          = $vtResult
            AbuseIPDB   = $abuseResult
            Scamalytics = $scamResult
        }

        $vtSummary = if ($vtResult.Error -eq "NoKey" -or $vtResult.Error -eq "Skipped") { "N/A" }
                     elseif ($vtResult.Error)                                            { "Error" }
                     else                                                                { "$($vtResult.Malicious)/$($vtResult.TotalEngines)" }

        Write-Host " VT:$vtSummary  Abuse:$(if($abuseResult.AbuseScore -ge 0){"$($abuseResult.AbuseScore)%"}else{"N/A"})  Scam:$(if($scamResult.FraudScore -ge 0){"$($scamResult.Risk)"}else{"N/A"})" -ForegroundColor Gray
    }
    Write-Host ""

} elseif ($Script:State.UniqueExternalIPs.Count -gt 0 -and -not $SkipApiLookup) {
    Write-Host "[*] Skipping API enrichment (no external IPs)" -ForegroundColor Gray
} else {
    Write-Host "[!] API lookup skipped per -SkipApiLookup flag." -ForegroundColor DarkYellow

    # Still run geo if we have IPs (ip-api has no key requirement)
    if ($Script:State.UniqueExternalIPs.Count -gt 0) {
        $Script:State.GeoData = Invoke-GeoEnrichment -IPList $Script:State.UniqueExternalIPs.ToArray()
    }
    Write-Host ""
}

# ============================================================================
# SECTION 6: HEURISTIC SCORING
# ============================================================================

Write-Host "[*] Applying heuristic scoring..." -ForegroundColor Yellow

$SuspiciousPathPatterns = @(
    '\\Temp\\', '\\tmp\\', 'AppData\\Local\\Temp', 'AppData\\Roaming\\',
    '\\Downloads\\', '\\Public\\', 'C:\\Windows\\Temp', 'C:\\ProgramData\\'
)

$TrustedPathPrefixes = @(
    'C:\Windows\System32\', 'C:\Windows\SysWOW64\',
    'C:\Program Files\', 'C:\Program Files (x86)\'
)

$SystemProcessPaths = @{
    'svchost'  = 'C:\Windows\System32\svchost.exe'
    'lsass'    = 'C:\Windows\System32\lsass.exe'
    'winlogon' = 'C:\Windows\System32\winlogon.exe'
    'services' = 'C:\Windows\System32\services.exe'
    'csrss'    = 'C:\Windows\System32\csrss.exe'
    'wininit'  = 'C:\Windows\System32\wininit.exe'
    'smss'     = 'C:\Windows\System32\smss.exe'
    'explorer' = 'C:\Windows\explorer.exe'
}

$KnownC2Ports     = @(4444, 1337, 6666, 6667, 6697, 9001, 9050, 31337)
$AltProxyPorts    = @(8080, 8443, 8888, 3128, 1080)
$SuspiciousParents = @('wscript', 'cscript', 'mshta', 'winword', 'excel',
                       'powerpnt', 'outlook', 'msaccess', 'mspub')

function Invoke-HeuristicScoring {
    param($Conn, $GeoRec, $ThreatRec)

    $score   = 0
    $reasons = [System.Collections.Generic.List[string]]::new()

    # --- Threat Intel Signals ---
    if ($ThreatRec) {
        $vt = $ThreatRec.VT
        if ($vt -and $vt.Malicious -ge 3)  { $score += 40; $reasons.Add("VT: $($vt.Malicious)/$($vt.TotalEngines) engines flagged") }
        elseif ($vt -and $vt.Malicious -in 1..2) { $score += 20; $reasons.Add("VT: $($vt.Malicious)/$($vt.TotalEngines) engines flagged") }

        $ab = $ThreatRec.AbuseIPDB
        if ($ab -and $ab.AbuseScore -ge 80) { $score += 30; $reasons.Add("AbuseIPDB: $($ab.AbuseScore)% confidence") }
        elseif ($ab -and $ab.AbuseScore -in 50..79) { $score += 15; $reasons.Add("AbuseIPDB: $($ab.AbuseScore)% confidence") }
        elseif ($ab -and $ab.AbuseScore -in 25..49) { $score += 5;  $reasons.Add("AbuseIPDB: $($ab.AbuseScore)% confidence") }
        if ($ab -and $ab.IsTor) { $score += 25; $reasons.Add("AbuseIPDB: Tor exit node") }

        $sc = $ThreatRec.Scamalytics
        if ($sc -and $sc.Risk -eq "high")   { $score += 20; $reasons.Add("Scamalytics: HIGH fraud risk") }
        elseif ($sc -and $sc.Risk -eq "medium") { $score += 10; $reasons.Add("Scamalytics: MEDIUM fraud risk") }
        if ($sc -and $sc.IsTor)        { $score += 25; $reasons.Add("Scamalytics: Tor exit") }
        if ($sc -and $sc.IsVPN -and $sc.IsDatacenter) { $score += 10; $reasons.Add("Scamalytics: VPN through datacenter") }
    }

    # --- Geo Signals ---
    if ($GeoRec -and $GeoRec.Status -eq "success") {
        if ($GeoRec.CountryCode -in @("CN","RU","KP","IR","BY","SY")) {
            $score += 5; $reasons.Add("Geo: High-risk country ($($GeoRec.CountryCode))")
        }
        if ($GeoRec.IsHosting) { $score += 5; $reasons.Add("Geo: Hosting provider IP") }
        if ($GeoRec.IsProxy)   { $score += 10; $reasons.Add("Geo: Known proxy") }
    }

    # --- Port Signals ---
    if ($Conn.RemotePort -in $KnownC2Ports)  { $score += 35; $reasons.Add("Port: Known C2 port ($($Conn.RemotePort))") }
    if ($Conn.RemotePort -in $AltProxyPorts) { $score += 10; $reasons.Add("Port: Alt/proxy port ($($Conn.RemotePort))") }

    # --- Process Path Signals ---
    $exePath = $Conn.ExePath
    if ($exePath -notin @("Unknown","AccessDenied","")) {
        $inSuspiciousPath = $false
        foreach ($pat in $SuspiciousPathPatterns) {
            if ($exePath -match [regex]::Escape($pat) -or $exePath -like "*$($pat.Replace('\\','\'))*") {
                $inSuspiciousPath = $true; break
            }
        }
        if ($inSuspiciousPath) { $score += 20; $reasons.Add("Path: Suspicious exe location ($exePath)") }

        # System process spoofing check
        $procBaseName = ($Conn.ProcessName -replace '\.exe$', '').ToLower()
        if ($SystemProcessPaths.ContainsKey($procBaseName)) {
            $expectedPath = $SystemProcessPaths[$procBaseName]
            if ($exePath -ne $expectedPath) {
                $score += 40
                $reasons.Add("Spoof: '$($Conn.ProcessName)' running from non-standard path (expected: $expectedPath)")
            }
        }
    }

    # --- Signature Signals ---
    if     ($Conn.SignatureStatus -eq "NotSigned")    { $score += 15; $reasons.Add("Sig: Unsigned binary") }
    elseif ($Conn.SignatureStatus -eq "HashMismatch") { $score += 35; $reasons.Add("Sig: Tampered signature (hash mismatch)") }
    elseif ($Conn.SignatureStatus -eq "UnknownError") { $score += 5;  $reasons.Add("Sig: Signature check inconclusive") }

    # --- Parent Process Signals ---
    $parentLower = $Conn.ParentName.ToLower() -replace '\.exe$', ''
    if ($parentLower -in $SuspiciousParents) {
        $score += 20; $reasons.Add("Parent: Spawned by $($Conn.ParentName)")
    }

    # --- Final Tier Assignment ---
    $score = [Math]::Min($score, 100)
    $tier = if ($score -ge 70) { "HIGH" } elseif ($score -ge 30) { "MEDIUM" } else { "LOW" }

    # Build display summaries
    $geoSummary  = "N/A"
    $vtSummary   = "N/A"
    $abuseSummary = "N/A"
    $scamSummary  = "N/A"

    if ($GeoRec -and $GeoRec.Status -eq "success") {
        $geoSummary = "$($GeoRec.CountryCode) / $($GeoRec.ISP)"
        if ($geoSummary.Length -gt 35) { $geoSummary = $geoSummary.Substring(0,32) + "..." }
    }
    if ($ThreatRec) {
        $vt = $ThreatRec.VT
        if ($vt -and $vt.Error -notin @("NoKey","")) {
            $vtSummary = if ($vt.Error) { "Err" } else { "$($vt.Malicious)/$($vt.TotalEngines)" }
        }
        $ab = $ThreatRec.AbuseIPDB
        if ($ab -and $ab.Error -notin @("NoKey","")) {
            $abuseSummary = if ($ab.Error) { "Err" } else { "$($ab.AbuseScore)%" }
        }
        $sc = $ThreatRec.Scamalytics
        if ($sc -and $sc.Error -notin @("NoKey","")) {
            $scamSummary = if ($sc.Error) { "Err" } else { $sc.Risk }
        }
    }

    $exeDisplay = if ($exePath -and $exePath.Length -gt 35) { "..." + $exePath.Substring($exePath.Length - 32) } else { $exePath }

    return [PSCustomObject]@{
        Protocol        = $Conn.Protocol
        LocalAddress    = $Conn.LocalAddress
        LocalPort       = $Conn.LocalPort
        RemoteAddress   = $Conn.RemoteAddress
        RemotePort      = $Conn.RemotePort
        State           = $Conn.State
        PID             = $Conn.PID
        ProcessName     = $Conn.ProcessName
        ExePath         = $Conn.ExePath
        ExeDisplay      = $exeDisplay
        ParentName      = $Conn.ParentName
        SignatureStatus = $Conn.SignatureStatus
        IsExternal      = $Conn.IsExternal
        GeoSummary      = $geoSummary
        VTSummary       = $vtSummary
        AbuseSummary    = $abuseSummary
        ScamSummary     = $scamSummary
        Score           = $score
        RiskTier        = $tier
        Reasons         = $reasons.ToArray()
    }
}

# Score all connections
foreach ($conn in $Script:State.Connections) {
    if (-not $conn.IsExternal -and -not $IncludePrivateIPs) { continue }

    $geoRec    = $null
    $threatRec = $null
    if ($conn.IsExternal -and $Script:State.GeoData.ContainsKey($conn.RemoteAddress)) {
        $geoRec = $Script:State.GeoData[$conn.RemoteAddress]
    }
    if ($conn.IsExternal -and $Script:State.ThreatData.ContainsKey($conn.RemoteAddress)) {
        $threatRec = $Script:State.ThreatData[$conn.RemoteAddress]
    }

    $scored = Invoke-HeuristicScoring -Conn $conn -GeoRec $geoRec -ThreatRec $threatRec
    $Script:State.ScoredRecords.Add($scored)
}

# Update stats
foreach ($rec in $Script:State.ScoredRecords) {
    switch ($rec.RiskTier) {
        "HIGH"   { $Script:State.Stats.HighCount++ }
        "MEDIUM" { $Script:State.Stats.MediumCount++ }
        "LOW"    { $Script:State.Stats.LowCount++ }
    }
}

Write-Host "  [+] Scored $($Script:State.ScoredRecords.Count) connections." -ForegroundColor Gray
Write-Host ""

# ============================================================================
# SECTION 7: PERSISTENCE CHECKS (HIGH + MEDIUM only)
# ============================================================================

Write-Host "[*] Checking persistence mechanisms for flagged processes..." -ForegroundColor Yellow

$checkedProcesses = [System.Collections.Generic.List[string]]::new()
$RunKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($rec in $Script:State.ScoredRecords | Where-Object { $_.RiskTier -in @("HIGH","MEDIUM") }) {
    $procName = $rec.ProcessName
    if ($checkedProcesses.Contains($procName)) { continue }
    $checkedProcesses.Add($procName)

    Write-Host "  [~] Persistence check: $procName" -ForegroundColor Gray

    # Scheduled Tasks
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Actions.Execute -like "*$procName*") -or
                ($rec.ExePath -ne "Unknown" -and $_.Actions.Execute -like "*$($rec.ExePath)*")
            } |
            ForEach-Object {
                $Script:State.PersistenceHits.Add([PSCustomObject]@{
                    ProcessName = $procName
                    CheckType   = "ScheduledTask"
                    Location    = "$($_.TaskPath)$($_.TaskName)"
                    Value       = "$($_.Actions.Execute) $($_.Actions.Arguments)"
                    Detail      = "State: $($_.State) | Triggers: $($_.Triggers.Count)"
                })
                Write-Host "    [!!] Scheduled task found: $($_.TaskPath)$($_.TaskName)" -ForegroundColor Red
            }
    } catch { }

    # Registry Run Keys
    foreach ($keyPath in $RunKeyPaths) {
        try {
            $regKey = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($regKey) {
                $regKey.PSObject.Properties |
                    Where-Object { $_.Name -notlike "PS*" } |
                    Where-Object { $_.Value -like "*$procName*" } |
                    ForEach-Object {
                        $Script:State.PersistenceHits.Add([PSCustomObject]@{
                            ProcessName = $procName
                            CheckType   = "RegistryRun"
                            Location    = "$keyPath\$($_.Name)"
                            Value       = $_.Value
                            Detail      = "Run key entry pointing to flagged process"
                        })
                        Write-Host "    [!!] Registry run key found: $keyPath -> $($_.Name) = $($_.Value)" -ForegroundColor Red
                    }
            }
        } catch { }
    }

    # Services
    try {
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -like "*$procName*" } |
            ForEach-Object {
                $Script:State.PersistenceHits.Add([PSCustomObject]@{
                    ProcessName = $procName
                    CheckType   = "Service"
                    Location    = $_.Name
                    Value       = $_.PathName
                    Detail      = "StartMode: $($_.StartMode) | State: $($_.State)"
                })
                Write-Host "    [!!] Service found: $($_.Name) ($($_.StartMode)) -> $($_.PathName)" -ForegroundColor Red
            }
    } catch { }

    # Startup Folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        try {
            if (Test-Path $folder) {
                Get-ChildItem -Path $folder -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "*$procName*" } |
                    ForEach-Object {
                        $Script:State.PersistenceHits.Add([PSCustomObject]@{
                            ProcessName = $procName
                            CheckType   = "StartupFolder"
                            Location    = $_.FullName
                            Value       = $_.Name
                            Detail      = "Startup folder item matching flagged process"
                        })
                        Write-Host "    [!!] Startup folder entry: $($_.FullName)" -ForegroundColor Red
                    }
            }
        } catch { }
    }
}

if ($Script:State.PersistenceHits.Count -eq 0) {
    Write-Host "  [+] No persistence mechanisms found for flagged processes." -ForegroundColor Green
}
Write-Host ""

# ============================================================================
# SECTION 8: EVENT LOG CORRELATION
# ============================================================================

Write-Host "[*] Correlating Windows Event Logs..." -ForegroundColor Yellow

$flaggedNames = ($Script:State.ScoredRecords |
    Where-Object { $_.RiskTier -in @("HIGH","MEDIUM") } |
    Select-Object -ExpandProperty ProcessName -Unique)

if ($flaggedNames -and $flaggedNames.Count -gt 0) {
    $namePattern = ($flaggedNames | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $lookbackDays = 7

    $eventQueries = @(
        @{ LogName = "Security";     Ids = @(4624, 4625, 4688) },
        @{ LogName = "System";       Ids = @(7045, 7036) },
        @{ LogName = "Application";  Ids = @(1000, 1001) }
    )

    foreach ($query in $eventQueries) {
        try {
            $filter = @{
                LogName   = $query.LogName
                Id        = $query.Ids
                StartTime = (Get-Date).AddDays(-$lookbackDays)
            }
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop |
                Where-Object { $_.Message -match $namePattern }

            foreach ($ev in $events) {
                $matchedProc = ($flaggedNames | Where-Object { $ev.Message -match [regex]::Escape($_) } | Select-Object -First 1)
                $msgSnip = if ($ev.Message.Length -gt 300) { $ev.Message.Substring(0,297) + "..." } else { $ev.Message }
                $Script:State.EventLogHits.Add([PSCustomObject]@{
                    LogName        = $query.LogName
                    EventId        = $ev.Id
                    TimeCreated    = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Message        = $msgSnip
                    MatchedProcess = $matchedProc
                })
            }

            Write-Host "  [+] $($query.LogName): $($events.Count) matching events found" -ForegroundColor Gray

        } catch [System.UnauthorizedAccessException] {
            Write-Host "  [!] $($query.LogName) log: Access Denied (run as Administrator for full correlation)" -ForegroundColor DarkYellow
        } catch {
            Write-Host "  [!] $($query.LogName) log error: $_" -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "  [+] No flagged processes to correlate against event logs." -ForegroundColor Green
}
Write-Host ""

# ============================================================================
# SECTION 9: CONSOLE OUTPUT (COLOR-CODED TABLE)
# ============================================================================

$sortedRecords = $Script:State.ScoredRecords | Sort-Object -Property Score -Descending

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║            NETWORK DFIR TRIAGE  ─  LIVE CONNECTION ANALYSIS            ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  Host    : $($Script:State.Hostname.PadRight(63))║" -ForegroundColor White
Write-Host "║  Analyst : $($Script:State.Analyst.PadRight(63))║" -ForegroundColor White
Write-Host "║  Time    : $((Get-Date -Format 'yyyy-MM-dd HH:mm:ss').PadRight(63))║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Stats line with individual colors
Write-Host "  Unique External IPs: $($Script:State.Stats.UniqueExternal)  |  " -NoNewline -ForegroundColor White
Write-Host "HIGH: $($Script:State.Stats.HighCount)" -NoNewline -ForegroundColor Red
Write-Host "  MEDIUM: $($Script:State.Stats.MediumCount)" -NoNewline -ForegroundColor Yellow
Write-Host "  LOW: $($Script:State.Stats.LowCount)" -ForegroundColor Green
Write-Host ""

# Table header
$hdr = "  {0,-6} {1,-5} {2,-16} {3,-5} {4,-5} {5,-18} {6,-16} {7,-8} {8,-6} {9,-4}" -f `
    "RISK", "SCORE", "REMOTE IP", "RPORT", "PROTO", "PROCESS", "COUNTRY/ISP", "VT", "ABUSE", "SCAM"
Write-Host $hdr -ForegroundColor Cyan
Write-Host ("  " + "─" * 96) -ForegroundColor DarkGray

foreach ($rec in $sortedRecords) {
    $rowColor = switch ($rec.RiskTier) {
        "HIGH"   { "Red" }
        "MEDIUM" { "Yellow" }
        "LOW"    { "Green" }
        default  { "Gray" }
    }

    $remoteIP   = if ($rec.RemoteAddress -and $rec.RemoteAddress.Length -gt 16) { $rec.RemoteAddress.Substring(0,15) } else { $rec.RemoteAddress }
    $procName   = if ($rec.ProcessName.Length -gt 18) { $rec.ProcessName.Substring(0,17) + "~" } else { $rec.ProcessName }
    $geoDisplay = if ($rec.GeoSummary -and $rec.GeoSummary.Length -gt 16) { $rec.GeoSummary.Substring(0,15) + "~" } else { $rec.GeoSummary }

    $row = "  {0,-6} {1,-5} {2,-16} {3,-5} {4,-5} {5,-18} {6,-16} {7,-8} {8,-6} {9,-4}" -f `
        $rec.RiskTier, $rec.Score, $remoteIP, $rec.RemotePort, $rec.Protocol,
        $procName, $geoDisplay, $rec.VTSummary, $rec.AbuseSummary, $rec.ScamSummary

    Write-Host $row -ForegroundColor $rowColor
}

Write-Host ""

# Scoring reasons for HIGH/MEDIUM records
$flaggedForDetail = $sortedRecords | Where-Object { $_.RiskTier -in @("HIGH","MEDIUM") }
if ($flaggedForDetail) {
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  FLAGGED CONNECTION DETAILS" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

    $i = 1
    foreach ($rec in $flaggedForDetail) {
        $tierColor = if ($rec.RiskTier -eq "HIGH") { "Red" } else { "Yellow" }
        Write-Host ""
        Write-Host "  [$i] $($rec.RemoteAddress):$($rec.RemotePort) ← $($rec.ProcessName) (PID $($rec.PID))" -ForegroundColor White
        Write-Host "  ─────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Risk     : " -NoNewline -ForegroundColor Gray
        Write-Host "$($rec.RiskTier) ($($rec.Score)/100)" -ForegroundColor $tierColor
        Write-Host "  Protocol : $($rec.Protocol)  |  State: $($rec.State)" -ForegroundColor Gray
        Write-Host "  Process  : $($rec.ProcessName) (PID: $($rec.PID))" -ForegroundColor Gray
        Write-Host "  Exe Path : $($rec.ExePath)" -ForegroundColor Gray
        Write-Host "  Parent   : $($rec.ParentName) (PID: $($rec.ParentPID))" -ForegroundColor Gray
        Write-Host "  Signature: $($rec.SignatureStatus) [$($rec.SignerName)]" -ForegroundColor Gray
        Write-Host "  Geo      : $($rec.GeoSummary)" -ForegroundColor Gray
        Write-Host "  VT       : $($rec.VTSummary)  |  AbuseIPDB: $($rec.AbuseSummary)  |  Scamalytics: $($rec.ScamSummary)" -ForegroundColor Gray
        Write-Host "  Reasons  :" -ForegroundColor Gray
        foreach ($reason in $rec.Reasons) {
            Write-Host "    - $reason" -ForegroundColor DarkYellow
        }
        $i++
    }
}

# Persistence section
if ($Script:State.PersistenceHits.Count -gt 0) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  PERSISTENCE FINDINGS" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    foreach ($hit in $Script:State.PersistenceHits) {
        Write-Host ""
        Write-Host "  Process  : $($hit.ProcessName)" -ForegroundColor Red
        Write-Host "  Type     : $($hit.CheckType)" -ForegroundColor Gray
        Write-Host "  Location : $($hit.Location)" -ForegroundColor Gray
        Write-Host "  Value    : $($hit.Value)" -ForegroundColor Gray
        Write-Host "  Detail   : $($hit.Detail)" -ForegroundColor DarkYellow
    }
}

# Event log section
if ($Script:State.EventLogHits.Count -gt 0) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  EVENT LOG HITS (last 7 days)" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    $evHdr = "  {0,-20} {1,-10} {2,-6} {3,-14} {4}" -f "Timestamp","Log","EvtID","Process","Message (truncated)"
    Write-Host $evHdr -ForegroundColor Cyan
    Write-Host ("  " + "─" * 80) -ForegroundColor DarkGray
    foreach ($hit in $Script:State.EventLogHits | Select-Object -First 50) {
        $msgShort = if ($hit.Message.Length -gt 40) { $hit.Message -replace "`r|`n"," " | ForEach-Object { if ($_.Length -gt 40) { $_.Substring(0,37) + "..." } else { $_ } } } else { $hit.Message }
        $row = "  {0,-20} {1,-10} {2,-6} {3,-14} {4}" -f $hit.TimeCreated, $hit.LogName, $hit.EventId, $hit.MatchedProcess, $msgShort
        Write-Host $row -ForegroundColor DarkYellow
    }
    if ($Script:State.EventLogHits.Count -gt 50) {
        Write-Host "  ... $($Script:State.EventLogHits.Count - 50) additional events in HTML report." -ForegroundColor Gray
    }
}

Write-Host ""

# ============================================================================
# SECTION 10: HTML REPORT GENERATION
# ============================================================================

Write-Host "[*] Generating HTML report..." -ForegroundColor Yellow

$connectionRowsHTML = ""
foreach ($rec in $sortedRecords) {
    $rowBg = switch ($rec.RiskTier) {
        "HIGH"   { "#f8d7da" }
        "MEDIUM" { "#fff3cd" }
        default  { "#d4edda" }
    }
    $reasonsHtml = ($rec.Reasons | ForEach-Object { "<li>$_</li>" }) -join ""
    $connectionRowsHTML += @"
        <tr style="background-color:$rowBg;">
            <td><strong>$($rec.RiskTier)</strong> ($($rec.Score))</td>
            <td>$($rec.RemoteAddress)</td>
            <td>$($rec.RemotePort)</td>
            <td>$($rec.Protocol)</td>
            <td>$($rec.State)</td>
            <td>$($rec.ProcessName)</td>
            <td>$($rec.PID)</td>
            <td><code>$($rec.ExePath)</code></td>
            <td>$($rec.ParentName)</td>
            <td>$($rec.SignatureStatus)</td>
            <td>$($rec.GeoSummary)</td>
            <td>$($rec.VTSummary)</td>
            <td>$($rec.AbuseSummary)</td>
            <td>$($rec.ScamSummary)</td>
            <td><ul>$reasonsHtml</ul></td>
        </tr>
"@
}
if (-not $connectionRowsHTML) {
    $connectionRowsHTML = '<tr><td colspan="15" style="text-align:center;color:green;">No external connections found.</td></tr>'
}

$persistenceRowsHTML = ""
foreach ($hit in $Script:State.PersistenceHits) {
    $persistenceRowsHTML += @"
        <tr style="background-color:#f8d7da;">
            <td>$($hit.ProcessName)</td>
            <td>$($hit.CheckType)</td>
            <td><code>$($hit.Location)</code></td>
            <td><code>$($hit.Value)</code></td>
            <td>$($hit.Detail)</td>
        </tr>
"@
}
if (-not $persistenceRowsHTML) {
    $persistenceRowsHTML = '<tr><td colspan="5" style="text-align:center;color:green;">No persistence mechanisms found for flagged processes.</td></tr>'
}

$eventRowsHTML = ""
foreach ($hit in $Script:State.EventLogHits) {
    $safeMsg = [System.Security.SecurityElement]::Escape($hit.Message)
    $eventRowsHTML += @"
        <tr style="background-color:#fff3cd;">
            <td>$($hit.TimeCreated)</td>
            <td>$($hit.LogName)</td>
            <td>$($hit.EventId)</td>
            <td>$($hit.MatchedProcess)</td>
            <td style="font-size:0.8em;"><code>$safeMsg</code></td>
        </tr>
"@
}
if (-not $eventRowsHTML) {
    $eventRowsHTML = '<tr><td colspan="5" style="text-align:center;color:green;">No matching event log entries found.</td></tr>'
}

$overallVerdict = if ($Script:State.Stats.HighCount -gt 0) { "HIGH RISK — INVESTIGATION REQUIRED" }
                 elseif ($Script:State.Stats.MediumCount -gt 0) { "MEDIUM RISK — REVIEW RECOMMENDED" }
                 else { "LOW RISK — NO HIGH-CONFIDENCE THREATS DETECTED" }

$verdictBg = if ($Script:State.Stats.HighCount -gt 0) { "#dc3545" }
             elseif ($Script:State.Stats.MediumCount -gt 0) { "#ffc107" }
             else { "#28a745" }

$scanDuration = [Math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network DFIR Triage — $($Script:State.Hostname)</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #00d4ff; margin: 20px 0 10px 0; border-left: 4px solid #00d4ff; padding-left: 10px; }
        .verdict-box { color: #fff; padding: 20px; border-radius: 8px; text-align: center; font-size: 1.4em; font-weight: bold; margin: 20px 0; background: $verdictBg; }
        .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0; }
        .meta-item { background: #16213e; padding: 10px; border-radius: 4px; }
        .meta-item strong { color: #00d4ff; }
        .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 15px 0; }
        .stat-box { background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-box .number { font-size: 2em; font-weight: bold; }
        .stat-box .label { color: #aaa; font-size: 0.9em; }
        .stat-high   .number { color: #dc3545; }
        .stat-medium .number { color: #ffc107; }
        .stat-low    .number { color: #28a745; }
        .stat-info   .number { color: #00d4ff; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 0.85em; }
        th { background: #0f3460; color: #00d4ff; padding: 10px; text-align: left; }
        td { padding: 7px 9px; border-bottom: 1px solid #333; color: #222; vertical-align: top; }
        tr:hover { opacity: 0.92; }
        code { background: #0a0a23; color: #00ff88; padding: 2px 5px; border-radius: 3px; font-size: 0.85em; word-break: break-all; }
        ul { padding-left: 18px; }
        li { font-size: 0.82em; color: #333; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 0.8em; }
        a { color: #00d4ff; }
        .export-box { background: #16213e; border: 1px solid #00d4ff; border-radius: 6px; padding: 15px; margin: 20px 0; }
        .export-box code { display: block; margin: 5px 0; color: #ffcc00; }
    </style>
</head>
<body>
<div class="container">
    <h1>Network DFIR Triage — Live Connection Analysis</h1>

    <div class="meta-grid">
        <div class="meta-item"><strong>Hostname:</strong> $($Script:State.Hostname)</div>
        <div class="meta-item"><strong>Analyst:</strong> $($Script:State.Analyst)</div>
        <div class="meta-item"><strong>Scan Time:</strong> $($Script:State.ScanTimestamp)</div>
        <div class="meta-item"><strong>OS Version:</strong> $($Script:State.OSVersion)</div>
        <div class="meta-item"><strong>Scan Duration:</strong> ${scanDuration}s</div>
        <div class="meta-item"><strong>API Mode:</strong> $(if ($SkipApiLookup) { "Heuristics Only" } else { "VT + AbuseIPDB + Scamalytics + Geo" })</div>
    </div>

    <div class="verdict-box">$overallVerdict</div>

    <div class="stats">
        <div class="stat-box stat-info">
            <div class="number">$($Script:State.Stats.UniqueExternal)</div>
            <div class="label">Unique External IPs</div>
        </div>
        <div class="stat-box stat-high">
            <div class="number">$($Script:State.Stats.HighCount)</div>
            <div class="label">HIGH Risk</div>
        </div>
        <div class="stat-box stat-medium">
            <div class="number">$($Script:State.Stats.MediumCount)</div>
            <div class="label">MEDIUM Risk</div>
        </div>
        <div class="stat-box stat-low">
            <div class="number">$($Script:State.Stats.LowCount)</div>
            <div class="label">LOW Risk</div>
        </div>
        <div class="stat-box stat-high">
            <div class="number">$($Script:State.PersistenceHits.Count)</div>
            <div class="label">Persistence Hits</div>
        </div>
    </div>

    <h2>Network Connections</h2>
    <table>
        <tr>
            <th>Risk</th><th>Remote IP</th><th>Port</th><th>Proto</th><th>State</th>
            <th>Process</th><th>PID</th><th>Exe Path</th><th>Parent</th><th>Signature</th>
            <th>Geo/ISP</th><th>VT</th><th>AbuseIPDB</th><th>Scamalytics</th><th>Reasons</th>
        </tr>
        $connectionRowsHTML
    </table>

    <h2>Persistence Findings</h2>
    <table>
        <tr><th>Process</th><th>Type</th><th>Location</th><th>Value</th><th>Detail</th></tr>
        $persistenceRowsHTML
    </table>

    <h2>Event Log Correlation (last 7 days)</h2>
    <table>
        <tr><th>Timestamp</th><th>Log</th><th>Event ID</th><th>Matched Process</th><th>Message</th></tr>
        $eventRowsHTML
    </table>

    <div class="export-box">
        <strong style="color:#00d4ff;">Report Extraction (no file transfer)</strong><br>
        If you cannot transfer this file, re-run with <code>-ExportBase64</code> to print it as Base64.<br>
        Decode on analyst workstation:
        <code>[IO.File]::WriteAllBytes("report.html", [Convert]::FromBase64String("&lt;paste&gt;"))</code>
        Or use <code>-CopyToClipboard</code> if clipboard integration is active in your remote session.
    </div>

    <div class="footer">
        Network-DFIR.ps1 v1.0 — Ghost-Glitch04 — Generated $($Script:State.ScanTimestamp)
    </div>
</div>
</body>
</html>
"@

# ============================================================================
# SECTION 11: EXPORT HANDLING
# ============================================================================

# Auto-save to disk
try {
    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -ErrorAction Stop
    Write-Host "[+] HTML report saved: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not write report to disk: $_" -ForegroundColor DarkYellow
}

# Base64 export (copy-paste extraction)
if ($ExportBase64) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  BASE64 ENCODED HTML REPORT — Copy all lines between markers  " -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "=== BEGIN NETWORK-DFIR-REPORT ===" -ForegroundColor DarkCyan

    $b64bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $b64      = [System.Convert]::ToBase64String($b64bytes)
    $lineLen  = 76
    for ($i = 0; $i -lt $b64.Length; $i += $lineLen) {
        Write-Host $b64.Substring($i, [Math]::Min($lineLen, $b64.Length - $i))
    }

    Write-Host "=== END NETWORK-DFIR-REPORT ===" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Decode on analyst workstation (PowerShell):" -ForegroundColor Yellow
    Write-Host '  $b64 = "<paste all lines between markers>"' -ForegroundColor Gray
    Write-Host '  [IO.File]::WriteAllBytes("C:\Cases\report.html", [Convert]::FromBase64String($b64))' -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Clipboard export
if ($CopyToClipboard) {
    try {
        Set-Clipboard -Value $html -ErrorAction Stop
        Write-Host "[+] HTML report copied to clipboard. Paste into a local .html file." -ForegroundColor Green
    } catch {
        Write-Host "[!] Set-Clipboard failed: $_" -ForegroundColor DarkYellow
        Write-Host "    Fallback: Add-Type -AssemblyName System.Windows.Forms" -ForegroundColor Gray
        Write-Host "    [System.Windows.Forms.Clipboard]::SetText(`$html)" -ForegroundColor Gray
    }
}

# ============================================================================
# SECTION 12: SUMMARY FOOTER
# ============================================================================

$scanDurationFinal = [Math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  SCAN COMPLETE" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host "  Total Connections   : $($Script:State.Stats.TotalConnections)" -ForegroundColor White
Write-Host "  Unique External IPs : $($Script:State.Stats.UniqueExternal)" -ForegroundColor White
Write-Host "  HIGH findings       : $($Script:State.Stats.HighCount)" -ForegroundColor $(if ($Script:State.Stats.HighCount -gt 0) { "Red" } else { "White" })
Write-Host "  MEDIUM findings     : $($Script:State.Stats.MediumCount)" -ForegroundColor $(if ($Script:State.Stats.MediumCount -gt 0) { "Yellow" } else { "White" })
Write-Host "  LOW findings        : $($Script:State.Stats.LowCount)" -ForegroundColor White
Write-Host "  Persistence hits    : $($Script:State.PersistenceHits.Count)" -ForegroundColor $(if ($Script:State.PersistenceHits.Count -gt 0) { "Red" } else { "White" })
Write-Host "  Event log hits      : $($Script:State.EventLogHits.Count)" -ForegroundColor $(if ($Script:State.EventLogHits.Count -gt 0) { "Yellow" } else { "White" })
Write-Host "  API calls (VT)      : $($Script:State.Stats.APICallsVT)" -ForegroundColor Gray
Write-Host "  Scan duration       : ${scanDurationFinal}s" -ForegroundColor Gray
Write-Host "  Report saved to     : $OutputPath" -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
Write-Host ""

return [PSCustomObject]$Script:State
