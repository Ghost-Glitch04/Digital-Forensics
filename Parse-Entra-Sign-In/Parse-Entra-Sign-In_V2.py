"""
Parse-Entra-Sign-In_V2.py
Author  : Ghost-Glitch04
Version : 2.0
Date    : 2026-03-25

Entra sign-in log parser — Phase 2: subnet deduplication and blocklist preparation.
Extends V1 scoring to produce a clean, deduplicated list of /24 (IPv4) and /64 (IPv6)
subnets from high-risk sign-ins, ready for ASN enrichment and firewall blocking.

No external dependencies — stdlib only.

Export the CSV from:
  Entra Portal → Monitoring → Sign-in logs → Download → CSV

Usage:
  python Parse-Entra-Sign-In_V2.py -f SignIns.csv
      # Score, filter, deduplicate, and print the subnet summary table.

  python Parse-Entra-Sign-In_V2.py -f SignIns.csv --export-subnets subnets.txt
      # Write one CIDR per line to a TXT file (IPv4 then IPv6, ascending).

  python Parse-Entra-Sign-In_V2.py -f SignIns.csv --export-csv results.csv
      # Write the full deduplicated subnet records to a CSV for further analysis.

  ── FLAGS ────────────────────────────────────────────────────────────────────

  -f / --file PATH
      Path to Entra sign-in CSV export. Required.

  --export-subnets PATH
      Write deduplicated subnets to a TXT file.
      IPv4 /24 subnets first (ascending), then IPv6 /64 subnets (ascending).
      One CIDR per line — ready for Named Location import in Entra.

  --export-csv PATH
      Write one row per deduplicated subnet to a CSV file.
      Includes ASN, location, representative IP, hit count, and risk data.

  ── FILTERING (automatic) ────────────────────────────────────────────────────

  The following are silently excluded before deduplication:
    · Sign-ins where Location contains "ohio" (case-insensitive)
    · Sign-ins where ASN matches any entry in LEGITIMATE_ASNS
    · Records with a risk score of 59 or lower
"""

import argparse
import csv
import ipaddress
import re
import subprocess
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional


# ============================================================================
# Column name normalization
# Entra exports use slightly different headers depending on portal version.
# ============================================================================

COLUMN_MAP = {
    # Timestamp
    "date (utc)":               "date",
    "date":                     "date",
    "created date (utc)":       "date",
    "time":                     "date",

    # Identity
    "user display name":        "display_name",
    "user principal name":      "upn",
    "username":                 "upn",
    "user- username":           "upn",
    "user id":                  "user_id",

    # Application
    "application":              "app",
    "app":                      "app",
    "resource":                 "resource",
    "resource id":              "resource_id",
    "client app":               "client_app",
    "cross tenant access type": "cross_tenant_type",
    "incoming token type":      "incoming_token_type",

    # Network
    "ip address":               "ip",
    "location":                 "location",

    # Network / ASN
    "autonomous system number": "asn",
    "as number":                "asn",
    "asn":                      "asn",

    # User agent
    "user agent":               "user_agent",
    "useragent":                "user_agent",
    "user-agent":               "user_agent",

    # Result
    "status":                   "status",
    "sign-in error code":       "error_code",
    "sign in error code":       "error_code",
    "failure reason":           "failure_reason",

    # Device
    "device id":                "device_id",
    "browser":                  "browser",
    "operating system":         "os",
    "compliant":                "compliant",
    "managed":                  "managed",
    "join type":                "join_type",

    # MFA
    "multifactor authentication result":     "mfa_result",
    "multifactor authentication auth method":"mfa_method",
    "multifactor authentication auth detail":"mfa_detail",
    "multifactor auth result":               "mfa_result",
    "multifactor auth method":               "mfa_method",
    "multifactor auth detail":               "mfa_detail",

    # Policy
    "authentication requirement":            "auth_requirement",
    "conditional access":                    "ca_status",
    "flagged for review":                    "flagged",
    "token issuer type":                     "token_issuer",

    # Misc
    "latency (ms)":             "latency",
    "correlation id":           "correlation_id",
    "request id":               "request_id",
    "unique token identifier":  "token_id",
    "associated user":          "associated_user",
}


# ============================================================================
# Risk scoring constants
# ============================================================================

LEGACY_AUTH_CLIENTS = {
    "exchange activesync",
    "imap",
    "pop",
    "smtp",
    "mapi over http",
    "autodiscover",
    "other clients",
    "older office clients",
    "exchange web services",
}

HIGH_RISK_ERROR_CODES = {
    "50053": "Account locked (smart lockout triggered)",
    "50057": "Account disabled",
    "50074": "Strong auth required but not satisfied",
    "50076": "MFA required by policy — user did not complete",
    "50079": "User enrolled in MFA but attempted bypass",
    "50126": "Invalid credentials",
    "50158": "External security challenge not satisfied",
    "53003": "Access blocked by Conditional Access policy",
    "70044": "Session token expired — possible replay attempt",
}

MALICIOUS_USER_AGENTS = {
    "bav2ropc",  # OAuth ROPC abuse — legacy brute-force tooling
    "axios",     # Node.js HTTP client — used in credential stuffing
}


# ============================================================================
# Exclusion lists
# ============================================================================

LEGITIMATE_ASNS = {
    "797",    "3356",   "5650",   "6167",   "6389",   "7018",   "7155",
    "7843",   "7922",   "8075",   "10796",  "10967",  "13150",  "13335",
    "14593",  "14654",  "15081",  "15108",  "16504",  "16509",  "20057",
    "20940",  "21789",  "21928",  "22616",  "22773",  "22843",  "25645",
    "26375",  "27632",  "30036",  "32806",  "36183",  "40306",  "46475",
    "46887",  "47046",  "54113",  "398378", "400110",
}

LEGITIMATE_LOCATION_KEYWORDS = {"ohio"}


# ============================================================================
# CSV loading and column normalization
# ============================================================================

def normalize_header(h: str) -> str:
    key = " ".join(h.strip().lower().split())
    return COLUMN_MAP.get(key, key.replace(" ", "_").replace("-", "_"))


def parse_date(val: str) -> Optional[datetime]:
    if not val:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(val.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def load_csv(path: str) -> list[dict]:
    records = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            print("[ERROR] CSV has no headers.", file=sys.stderr)
            sys.exit(1)
        norm_fields = [normalize_header(f) for f in reader.fieldnames]
        for row in reader:
            normed         = {norm_fields[i]: v.strip() for i, v in enumerate(row.values())}
            normed["_dt"]  = parse_date(normed.get("date", ""))
            records.append(normed)
    return records


# ============================================================================
# Risk scoring (identical to V1)
# ============================================================================

def score_record(rec: dict) -> tuple[int, list[str]]:
    score   = 0
    reasons = []

    status     = rec.get("status", "").lower()
    client_app = rec.get("client_app", "").lower()
    mfa_result = rec.get("mfa_result", "").lower()
    auth_req   = rec.get("auth_requirement", "").lower()
    compliant  = rec.get("compliant", "").lower()
    managed    = rec.get("managed", "").lower()
    join_type  = rec.get("join_type", "").lower()
    ca_status  = rec.get("ca_status", "").lower()
    flagged    = rec.get("flagged", "").lower()
    inc_token  = rec.get("incoming_token_type", "").lower()
    error_code = rec.get("error_code", "").strip()

    if status == "failure":
        score += 15
        reasons.append("Failed authentication")
    elif status == "interrupted":
        score += 10
        reasons.append("Interrupted sign-in")

    if any(leg in client_app for leg in LEGACY_AUTH_CLIENTS):
        score += 25
        reasons.append(f"Legacy auth client: {rec.get('client_app')}")

    if ("not performed" in mfa_result or mfa_result == "") and (
        "multifactorauthentication" in auth_req or "mfa" in auth_req
    ):
        score += 20
        reasons.append("MFA required but not performed")

    if "denied" in mfa_result or "blocked" in mfa_result:
        score += 30
        reasons.append(f"MFA denied/blocked: {rec.get('mfa_result')}")

    if compliant in ("false", "no"):
        score += 15
        reasons.append("Non-compliant device")

    if managed in ("false", "no"):
        score += 10
        reasons.append("Unmanaged device")

    if join_type in ("", "unregistered", "none"):
        score += 8
        reasons.append("Device unregistered / unknown join type")

    if "failure" in ca_status or "not applied" in ca_status:
        score += 15
        reasons.append(f"Conditional Access issue: {rec.get('ca_status')}")

    if flagged in ("true", "yes", "1"):
        score += 30
        reasons.append("Flagged for review by Microsoft risk engine")

    if inc_token in ("external azure ad", "federated", "saml11", "saml20"):
        score += 10
        reasons.append(f"External/federated token type: {rec.get('incoming_token_type')}")

    for code, label in HIGH_RISK_ERROR_CODES.items():
        if error_code == code:
            score += 20
            reasons.append(f"Error {code}: {label}")
            break

    user_agent = rec.get("user_agent", "").lower()
    for ua in MALICIOUS_USER_AGENTS:
        if ua in user_agent:
            score += 60
            reasons.append(f"Malicious user agent detected: {rec.get('user_agent')}")
            break

    location = rec.get("location", "")
    if location:
        country_code = location.split(",")[-1].strip().upper()
        if country_code and country_code not in ("US", "CA", "MX"):
            score += 15
            reasons.append(f"Sign-in outside North America: {location}")

    return min(score, 100), reasons


def risk_label(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# ============================================================================
# Exclusion filter
# Returns True if the record should be DROPPED.
# ============================================================================

def should_exclude(rec: dict) -> bool:
    loc = rec.get("location", "").lower()
    if any(kw in loc for kw in LEGITIMATE_LOCATION_KEYWORDS):
        return True

    asn = rec.get("asn", "").strip()
    if asn in LEGITIMATE_ASNS:
        return True

    if rec.get("_risk_score", 0) <= 59:
        return True

    return False


# ============================================================================
# Team Cymru DNS lookup
# Queries the actual BGP-announced prefix and ASN for each IP via DNS TXT
# records — more accurate than guessing /24 or /64.
#
# IPv4: reverse octets + .origin.asn.cymru.com
#   45.135.26.134  →  134.26.135.45.origin.asn.cymru.com
#   TXT response:  "207990 | 45.135.26.0/24 | NL | ripencc | 2020-06-23"
#
# IPv6: reverse nibbles + .origin6.asn.cymru.com
#   Uses nslookup (Windows built-in) via subprocess. Falls back to /24 or /64
#   on timeout, DNS failure, or unparseable response.
# ============================================================================

def _cymru_reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _cymru_reverse_ipv6(ip: str) -> str:
    addr    = ipaddress.ip_address(ip)
    nibbles = addr.exploded.replace(":", "")   # 32 hex chars, no colons
    return ".".join(reversed(list(nibbles)))


def _fallback_subnet(ip: str) -> Optional[str]:
    """Return /24 (IPv4) or /64 (IPv6) as a last resort."""
    try:
        addr = ipaddress.ip_address(ip)
        prefix = 24 if isinstance(addr, ipaddress.IPv4Address) else 64
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return None


def cymru_lookup(ip: str) -> dict:
    """
    Query Team Cymru DNS for the BGP-announced prefix and ASN.
    Returns {"asn": "12345", "cidr": "1.2.3.0/24", "country": "NL"}
    or {} on any failure.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            query = f"{_cymru_reverse_ipv4(ip)}.origin.asn.cymru.com"
        else:
            query = f"{_cymru_reverse_ipv6(ip)}.origin6.asn.cymru.com"

        result = subprocess.run(
            ["nslookup", "-type=TXT", query],
            capture_output=True, text=True, timeout=10,
        )
        # TXT format: "ASN | CIDR | country | registry | date"
        # ASN may be a space-separated list for MOAS prefixes — take the first.
        match = re.search(
            r'"(\d+)[\d\s]*\|\s*([\da-fA-F.:\/]+)\s*\|\s*([A-Z]{2,})\s*\|\s*(\w+)',
            result.stdout,
        )
        if match:
            return {
                "asn":      match.group(1).strip(),
                "cidr":     match.group(2).strip(),
                "country":  match.group(3).strip(),
                "registry": match.group(4).strip(),
            }
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    except Exception:
        pass
    return {}


# ============================================================================
# Deduplication and Cymru enrichment
# Order of operations:
#   1. Deduplicate by IP (dict + integer compare — zero DNS calls)
#   2. Cymru DNS lookup per unique IP (one nslookup per IP, fallback to /24)
#   3. Second ASN exclusion pass using Cymru ASN (more reliable than CSV field)
#   4. Deduplicate by actual announced CIDR
#   5. Annotate each CIDR record with IP count, UPN count, and UPN list
# ============================================================================

def dedupe_and_lookup(records: list[dict], skip_cymru: bool = False) -> list[dict]:

    # ── Step 1: deduplicate by IP — no DNS calls yet ──────────────────────
    best_by_ip: dict[str, dict] = {}
    upns_by_ip: dict[str, set]  = defaultdict(set)

    for r in records:
        ip = r.get("ip", "").strip()
        if not ip:
            continue
        upn = r.get("upn") or r.get("display_name", "")
        if upn:
            upns_by_ip[ip].add(upn)
        if (ip not in best_by_ip or
                r.get("_risk_score", 0) > best_by_ip[ip].get("_risk_score", 0)):
            best_by_ip[ip] = r

    unique_ips = list(best_by_ip.keys())
    print(f"{CYAN}  Unique IPs      : {len(unique_ips)}{RESET}")

    # ── Step 2: Cymru DNS lookup per unique IP ────────────────────────────
    ip_cidr:    dict[str, str] = {}
    ip_asn:     dict[str, str] = {}
    ip_country: dict[str, str] = {}
    cymru_failed = 0

    if not skip_cymru:
        print(f"{CYAN}  Querying Team Cymru DNS ({len(unique_ips)} IPs) ...{RESET}")
        for i, ip in enumerate(unique_ips, 1):
            if i % 5 == 0 or i == len(unique_ips):
                print(f"  {GRAY}[{i}/{len(unique_ips)}]{RESET}", end="\r", flush=True)
            info = cymru_lookup(ip)
            if info:
                ip_cidr[ip]    = info["cidr"]
                ip_asn[ip]     = info["asn"]
                ip_country[ip] = info.get("country", "")
            else:
                fallback = _fallback_subnet(ip)
                if fallback:
                    ip_cidr[ip] = fallback
                ip_asn[ip] = best_by_ip[ip].get("asn", "")
                cymru_failed += 1
        print(f"  {' ' * 30}", end="\r")   # clear progress line
        if cymru_failed:
            print(f"{YELLOW}  Cymru fallback  : {cymru_failed} IPs used /24 or /64 (DNS timeout or no record){RESET}")
        else:
            print(f"{GREEN}  Cymru lookups   : all {len(unique_ips)} succeeded{RESET}")
    else:
        print(f"{YELLOW}  Cymru skipped   : using /24 and /64 fallback{RESET}")
        for ip in unique_ips:
            fallback = _fallback_subnet(ip)
            if fallback:
                ip_cidr[ip] = fallback
            ip_asn[ip] = best_by_ip[ip].get("asn", "")

    # ── Step 3: second ASN exclusion pass (Cymru ASN is more reliable) ────
    skipped_legit = 0
    filtered_ips  = []
    for ip in unique_ips:
        if ip_asn.get(ip, "") in LEGITIMATE_ASNS:
            skipped_legit += 1
        else:
            filtered_ips.append(ip)

    if skipped_legit:
        print(f"{YELLOW}  ASN re-check    : {skipped_legit} additional IPs removed (Cymru-verified legitimate ASN){RESET}")

    # ── Step 4: deduplicate by actual announced CIDR ──────────────────────
    best_by_cidr: dict[str, dict] = {}
    ips_by_cidr:  dict[str, set]  = defaultdict(set)
    upns_by_cidr: dict[str, set]  = defaultdict(set)

    for ip in filtered_ips:
        cidr = ip_cidr.get(ip)
        if not cidr:
            continue
        rep = best_by_ip[ip]
        ips_by_cidr[cidr].add(ip)
        upns_by_cidr[cidr].update(upns_by_ip[ip])
        if (cidr not in best_by_cidr or
                rep.get("_risk_score", 0) > best_by_cidr[cidr].get("_risk_score", 0)):
            enriched = dict(rep)
            enriched["_cymru_asn"]     = ip_asn.get(ip, "")
            enriched["_cymru_country"] = ip_country.get(ip, "")
            best_by_cidr[cidr] = enriched

    # ── Step 5: annotate and return ───────────────────────────────────────
    result = []
    for cidr, rep in best_by_cidr.items():
        rep["_subnet"]    = cidr
        rep["_ip_count"]  = len(ips_by_cidr[cidr])
        rep["_upn_count"] = len(upns_by_cidr[cidr])
        rep["_upns"]      = ", ".join(sorted(upns_by_cidr[cidr]))
        result.append(rep)

    return result


# ============================================================================
# CIDR sorting: IPv4 /24 ascending, then IPv6 /64 ascending
# ============================================================================

def sort_subnets(subnets: list[str]) -> tuple[list[str], list[str]]:
    ipv4 = []
    ipv6 = []
    for s in subnets:
        try:
            net = ipaddress.ip_network(s, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                ipv4.append(net)
            else:
                ipv6.append(net)
        except ValueError:
            pass
    ipv4.sort()
    ipv6.sort()
    return [str(n) for n in ipv4], [str(n) for n in ipv6]


# ============================================================================
# ANSI colors
# ============================================================================

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

def truncate(val: str, width: int) -> str:
    val = val or ""
    return val if len(val) <= width else val[: width - 1] + "…"


def print_banner(title: str) -> None:
    print(f"\n{CYAN}{'=' * 84}{RESET}")
    print(f"{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'=' * 84}{RESET}\n")


# ============================================================================
# Console subnet table
# ============================================================================

SUBNET_COL_WIDTHS = {
    "Subnet":   20,
    "IPs":       4,
    "UPNs":      5,
    "ASN":       8,
    "Location": 24,
    "Risk":      6,
}


def print_subnet_table(records: list[dict], max_rows: int = 500) -> None:
    header  = "  ".join(f"{k:<{v}}" for k, v in SUBNET_COL_WIDTHS.items())
    divider = GRAY + "-" * len(header) + RESET

    print(f"{BOLD}{CYAN}{header}{RESET}")
    print(divider)

    for i, r in enumerate(records):
        if i >= max_rows:
            print(f"{GRAY}  ... {len(records) - max_rows} more rows — use --export-csv to see all{RESET}")
            break

        subnet   = truncate(r.get("_subnet", ""), SUBNET_COL_WIDTHS["Subnet"])
        ip_count = str(r.get("_ip_count", 1))
        upn_cnt  = str(r.get("_upn_count", 1))
        asn      = truncate(r.get("_cymru_asn") or r.get("asn", ""), SUBNET_COL_WIDTHS["ASN"])
        location = truncate(r.get("location", ""), SUBNET_COL_WIDTHS["Location"])
        label    = r.get("_risk_label", "HIGH")

        risk_colored = f"{RED}{label}{RESET}" if label == "HIGH" else f"{YELLOW}{label}{RESET}"

        print(
            f"  {subnet:<{SUBNET_COL_WIDTHS['Subnet']}}"
            f"  {ip_count:<{SUBNET_COL_WIDTHS['IPs']}}"
            f"  {upn_cnt:<{SUBNET_COL_WIDTHS['UPNs']}}"
            f"  {asn:<{SUBNET_COL_WIDTHS['ASN']}}"
            f"  {location:<{SUBNET_COL_WIDTHS['Location']}}"
            f"  {risk_colored}"
        )


# ============================================================================
# Exports
# ============================================================================

def export_subnets_txt(ipv4: list[str], ipv6: list[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for cidr in ipv4:
            fh.write(f"{cidr}\n")
        for cidr in ipv6:
            fh.write(f"{cidr}\n")
    print(f"\n{GREEN}  Exported {len(ipv4)} IPv4 + {len(ipv6)} IPv6 subnets → {path}{RESET}")


EXPORT_CSV_FIELDS = [
    "_subnet", "_ip_count", "_upn_count", "_upns",
    "ip", "_cymru_asn", "_cymru_country", "asn", "location", "status",
    "app", "client_app", "mfa_result",
    "error_code", "failure_reason",
    "_risk_score", "_risk_label", "_risk_reasons",
]


def export_csv(records: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPORT_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            row = {f: r.get(f, "") for f in EXPORT_CSV_FIELDS}
            row["_risk_reasons"] = "; ".join(r.get("_risk_reasons") or [])
            writer.writerow(row)
    print(f"\n{GREEN}  Exported {len(records)} subnet records → {path}{RESET}")


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Entra sign-in subnet deduplicator for blocklist generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("-f", "--file",        required=True,  help="Path to Entra sign-in CSV export")
    parser.add_argument("--export-subnets",    metavar="PATH", help="Export deduplicated CIDRs to TXT (one per line)")
    parser.add_argument("--export-csv",        metavar="PATH", help="Export subnet records to CSV")
    parser.add_argument("--skip-cymru",        action="store_true",
                        help="Skip Team Cymru DNS lookups and fall back to /24 or /64 (faster, offline-safe)")

    args = parser.parse_args()

    # ── Load ──────────────────────────────────────────────────────────────
    if not os.path.isfile(args.file):
        print(f"{RED}[ERROR] File not found: {args.file}{RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{CYAN}Loading {args.file} ...{RESET}", end=" ", flush=True)
    records = load_csv(args.file)
    print(f"{GREEN}{len(records)} records loaded{RESET}")

    if not records:
        print(f"{YELLOW}No records found in file.{RESET}")
        sys.exit(0)

    # ── Score ─────────────────────────────────────────────────────────────
    for r in records:
        score, reasons     = score_record(r)
        r["_risk_score"]   = score
        r["_risk_label"]   = risk_label(score)
        r["_risk_reasons"] = reasons

    # ── Filter ────────────────────────────────────────────────────────────
    before  = len(records)
    records = [r for r in records if not should_exclude(r)]
    dropped = before - len(records)

    highs = sum(1 for r in records if r["_risk_label"] == "HIGH")
    meds  = sum(1 for r in records if r["_risk_label"] == "MEDIUM")

    print(f"{CYAN}After exclusions : {len(records)} records remain ({dropped} dropped — Ohio / legitimate ASN / score ≤ 59){RESET}")
    print(f"{CYAN}Risk breakdown   : {RED}{highs} HIGH{RESET}  {CYAN}|{RESET}  {YELLOW}{meds} MEDIUM{RESET}\n")

    if not records:
        print(f"{YELLOW}No qualifying records after exclusions.{RESET}")
        sys.exit(0)

    # ── Deduplicate and Cymru enrich ──────────────────────────────────────
    deduped = dedupe_and_lookup(records, skip_cymru=args.skip_cymru)
    deduped.sort(key=lambda r: -r.get("_risk_score", 0))

    label = "/24 and /64 subnets" if args.skip_cymru else "announced prefixes (Cymru)"
    print(f"\n{GREEN}Unique CIDRs     : {len(deduped)}  ({len(records)} qualifying records collapsed){RESET}")

    # ── Console table ─────────────────────────────────────────────────────
    print_banner(f"SUBNET SUMMARY  [{len(deduped)} unique {label} | sorted by risk score]")
    print_subnet_table(deduped)

    # ── Sort for export ───────────────────────────────────────────────────
    all_subnets             = [r["_subnet"] for r in deduped if r.get("_subnet")]
    ipv4_sorted, ipv6_sorted = sort_subnets(all_subnets)

    print(
        f"\n{BOLD}Subnet totals:{RESET}  "
        f"{CYAN}{len(ipv4_sorted)} IPv4 /24{RESET}  |  "
        f"{CYAN}{len(ipv6_sorted)} IPv6 /64{RESET}\n"
    )

    # ── Exports ───────────────────────────────────────────────────────────
    if args.export_subnets:
        export_subnets_txt(ipv4_sorted, ipv6_sorted, args.export_subnets)

    if args.export_csv:
        export_csv(deduped, args.export_csv)


if __name__ == "__main__":
    main()
