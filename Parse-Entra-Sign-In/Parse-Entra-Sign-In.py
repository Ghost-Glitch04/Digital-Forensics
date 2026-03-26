"""
Parse-Entra-Sign-In.py
Author  : Ghost-Glitch04
Version : 1.0
Date    : 2026-03-25

Parses Microsoft Entra ID Interactive Sign-In log CSV exports for incident response.
Provides filtering, risk scoring, anomaly detection, and summary reporting.
No external dependencies — stdlib only.

Export the CSV from:
  Entra Portal → Monitoring → Sign-in logs → Download → CSV

Usage:
  python Parse-Entra-Sign-In.py -f SignIns.csv
      # Minimum required flag. Loads the CSV and prints the event table.

  ── ACTIONS ──────────────────────────────────────────────────────────────────

  --summary
      Print a statistical overview: top users, source IPs, applications,
      locations, client apps, status breakdown, and risk level counts.

  --anomalies
      Run automated anomaly detection across all records:
        · Brute-force / password spray (configurable threshold)
        · Impossible travel (location change < 1 hour for same account)
        · Failure → Success pattern (possible account compromise)
        · MFA denied / blocked events (MFA fatigue indicator)

  --all
      Run --summary + --anomalies + event table in a single pass.
      Recommended starting point for a full triage.

  --table
      Explicitly print the event table. This is the default action
      if no other action flag is provided.

  --max-rows N
      Limit the event table to N rows (default: 200).
      Records beyond the limit are noted but not printed.
      Use --export to capture the full dataset.

  --sort {date|risk|user|ip|status}
      Sort the event table by the specified column (default: date).
      Use --sort risk to surface the highest-scoring records first.

  --export PATH
      Write all filtered records to a CSV file at PATH.
      Includes risk score, risk label, and risk reasons columns.

  --export-unique-ips PATH
      Same as --export but deduplicates by IP address first.
      Where an IP appears in multiple records, only the highest-risk
      record is kept. Useful for feeding a unique IP list into a
      threat intel platform or firewall blocklist.

  --brute-force-threshold N
      Number of failures required to flag an account as a brute-force
      candidate during --anomalies (default: 5). Lower this in targeted
      attack scenarios where the attacker is being slow/deliberate.

  ── FILTERS ──────────────────────────────────────────────────────────────────

  --user UPN
      Show only records matching a UPN or display name (partial match).
      Example: --user jdoe  or  --user jdoe@corp.com

  --ip IP
      Show only records matching a source IP address (partial match).
      Useful for pivoting on a suspicious IP identified elsewhere.

  --app APP
      Show only records for a specific application name (partial match).
      Example: --app "Exchange Online"

  --location LOCATION
      Show only records whose location field contains the given string.
      Example: --location "China"  or  --location "Delhi"

  --start YYYY-MM-DD
      Exclude records before this date (UTC). Useful for scoping to
      an incident window.

  --end YYYY-MM-DD
      Exclude records after this date (UTC).

  --failures-only
      Show failed sign-ins only. Strips all Success/Interrupted events.

  --success-only
      Show successful sign-ins only. Use with --anomalies to find
      compromised accounts that are now logging in successfully.

  --risky
      Show only records at or above the risk score threshold.
      Combine with --sort risk and --export for a suspicious-activity report.

  --risky-threshold SCORE
      Set the minimum risk score when using --risky (default: 30).
      30 = MEDIUM and above.  60 = HIGH only.

  --legacy-only
      Show only events using legacy / basic auth clients (IMAP, POP, SMTP,
      MAPI, EAS, etc.). These protocols bypass MFA and are a common
      attack vector even in MFA-protected tenants.

  --no-mfa
      Show only events where MFA was not performed, regardless of whether
      it was required. Helps identify gaps in MFA enforcement.

  --filter-remove-legitimate
      Remove records that match known-legitimate traffic baselines:
        · Location contains "Ohio"
        · Autonomous System Number matches a known-good ASN
      Use this to reduce noise when the environment is known and
      you want to focus on anomalous external traffic only.
"""

import argparse
import csv
import sys
import os
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional


# ============================================================================
# Column name normalization
# Entra exports use slightly different headers depending on portal version.
# Map known variants to a canonical internal name.
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
    "multifactor authentication result":    "mfa_result",
    "multifactor authentication auth method":"mfa_method",
    "multifactor authentication auth detail":"mfa_detail",
    "multifactor auth result":              "mfa_result",
    "multifactor auth method":              "mfa_method",
    "multifactor auth detail":              "mfa_detail",

    # Policy
    "authentication requirement":           "auth_requirement",
    "conditional access":                   "ca_status",
    "flagged for review":                   "flagged",
    "token issuer type":                    "token_issuer",

    # Network / ASN
    "autonomous system number": "asn",
    "as number":                "asn",
    "asn":                      "asn",

    # User agent
    "user agent":               "user_agent",
    "useragent":                "user_agent",
    "user-agent":               "user_agent",

    # Misc
    "latency (ms)":             "latency",
    "correlation id":           "correlation_id",
    "request id":               "request_id",
    "unique token identifier":  "token_id",
    "associated user":          "associated_user",
}


# ============================================================================
# Legacy / basic auth client values — high risk in IR context
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

# ============================================================================
# Legitimate traffic baselines — used by --filter-remove-legitimate
# ============================================================================

# User agent strings that are exclusively seen in malicious/automated sign-ins
MALICIOUS_USER_AGENTS = {
    "bav2ropc",  # OAuth ROPC (Resource Owner Password Credential) abuse — legacy brute-force tool
    "axios",     # Node.js HTTP client — used in credential stuffing and token spray tooling
}


LEGITIMATE_ASNS = {
    "797",
    "3356",
    "5650",
    "6167",
    "6389",
    "7018",
    "7155",
    "7843",
    "7922",
    "8075",
    "10796",
    "10967",
    "13150",
    "13335",
    "14593",
    "14654",
    "15081",
    "15108",
    "16504",
    "16509",
    "20057",
    "20940",
    "21789",
    "21928",
    "22616",
    "22773",
    "22843",
    "25645",
    "26375",
    "27632",
    "30036",
    "32806",
    "36183",
    "40306",
    "46475",
    "46887",
    "47046",
    "54113",
    "398378",
    "400110",
}

LEGITIMATE_LOCATION_KEYWORDS = {
    "ohio",
}


# High-risk error codes and what they mean
HIGH_RISK_ERROR_CODES = {
    "50053":  "Account locked (smart lockout triggered)",
    "50057":  "Account disabled",
    "50074":  "Strong auth required but not satisfied",
    "50076":  "MFA required by policy — user did not complete",
    "50079":  "User enrolled in MFA but attempted bypass",
    "50126":  "Invalid credentials",
    "50158":  "External security challenge not satisfied",
    "53003":  "Access blocked by Conditional Access policy",
    "70044":  "Session token expired — possible replay attempt",
}


# ============================================================================
# Risk scoring
# Each check contributes to a 0–100 score.
# Returns (score, [reason_strings])
# ============================================================================

def score_record(rec: dict) -> tuple[int, list[str]]:
    score   = 0
    reasons = []

    status      = rec.get("status", "").lower()
    client_app  = rec.get("client_app", "").lower()
    mfa_result  = rec.get("mfa_result", "").lower()
    auth_req    = rec.get("auth_requirement", "").lower()
    compliant   = rec.get("compliant", "").lower()
    managed     = rec.get("managed", "").lower()
    join_type   = rec.get("join_type", "").lower()
    ca_status   = rec.get("ca_status", "").lower()
    flagged     = rec.get("flagged", "").lower()
    inc_token   = rec.get("incoming_token_type", "").lower()
    error_code  = rec.get("error_code", "").strip()

    # Sign-in outcome
    if status == "failure":
        score += 15
        reasons.append("Failed authentication")
    elif status == "interrupted":
        score += 10
        reasons.append("Interrupted sign-in")

    # Legacy / basic auth
    if any(leg in client_app for leg in LEGACY_AUTH_CLIENTS):
        score += 25
        reasons.append(f"Legacy auth client: {rec.get('client_app')}")

    # MFA not performed when required
    if ("not performed" in mfa_result or mfa_result == "") and (
        "multifactorauthentication" in auth_req or "mfa" in auth_req
    ):
        score += 20
        reasons.append("MFA required but not performed")

    # MFA explicitly denied or blocked by user/attacker
    if "denied" in mfa_result or "blocked" in mfa_result:
        score += 30
        reasons.append(f"MFA denied/blocked: {rec.get('mfa_result')}")

    # Non-compliant device
    if compliant in ("false", "no"):
        score += 15
        reasons.append("Non-compliant device")

    # Unmanaged device
    if managed in ("false", "no"):
        score += 10
        reasons.append("Unmanaged device")

    # Unregistered device
    if join_type in ("", "unregistered", "none"):
        score += 8
        reasons.append("Device unregistered / unknown join type")

    # Conditional Access failure
    if "failure" in ca_status or "not applied" in ca_status:
        score += 15
        reasons.append(f"Conditional Access issue: {rec.get('ca_status')}")

    # Flagged by Microsoft risk engine
    if flagged in ("true", "yes", "1"):
        score += 30
        reasons.append("Flagged for review by Microsoft risk engine")

    # External/federated token (cross-tenant abuse vector)
    if inc_token in ("external azure ad", "federated", "saml11", "saml20"):
        score += 10
        reasons.append(f"External/federated token type: {rec.get('incoming_token_type')}")

    # High-risk error codes
    for code, label in HIGH_RISK_ERROR_CODES.items():
        if error_code == code:
            score += 20
            reasons.append(f"Error {code}: {label}")
            break

    # Malicious user agent strings
    user_agent = rec.get("user_agent", "").lower()
    for ua in MALICIOUS_USER_AGENTS:
        if ua in user_agent:
            score += 60
            reasons.append(f"Malicious user agent detected: {rec.get('user_agent')}")
            break

    # Geographic risk — sign-in outside North America
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
# Anomaly detection across the full dataset
# ============================================================================

def detect_brute_force(records: list[dict], threshold: int) -> dict[str, list[str]]:
    """
    Flag accounts with >= threshold failures.
    Also flags password spray: many failures from distinct IPs.
    """
    alerts  = defaultdict(list)
    by_upn  = defaultdict(list)

    for r in records:
        by_upn[r.get("upn") or r.get("display_name", "unknown")].append(r)

    for upn, entries in by_upn.items():
        sorted_e  = sorted(entries, key=lambda x: x.get("_dt") or datetime.min.replace(tzinfo=timezone.utc))
        failures  = [e for e in sorted_e if e.get("status", "").lower() == "failure"]
        successes = [e for e in sorted_e if e.get("status", "").lower() == "success"]

        if len(failures) >= threshold:
            suffix = f", followed by {len(successes)} success(es)" if successes else ""
            alerts[upn].append(f"Brute-force candidate: {len(failures)} failures{suffix}")

        # Password spray: many failures from 3+ distinct IPs
        failure_ips = set(e.get("ip", "") for e in failures)
        if len(failure_ips) >= 3 and len(failures) >= threshold:
            alerts[upn].append(
                f"Password spray: {len(failures)} failures from {len(failure_ips)} distinct IPs"
            )

    return dict(alerts)


def detect_impossible_travel(records: list[dict]) -> list[str]:
    """
    Flag location changes < 1 hour apart for the same account.
    Uses the country/city portion of the location string.
    """
    alerts  = []
    by_upn  = defaultdict(list)

    for r in records:
        if r.get("_dt") and r.get("location"):
            by_upn[r.get("upn") or r.get("display_name", "unknown")].append(r)

    for upn, entries in by_upn.items():
        sorted_e = sorted(entries, key=lambda x: x["_dt"])
        for i in range(1, len(sorted_e)):
            prev = sorted_e[i - 1]
            curr = sorted_e[i]
            if not prev.get("_dt") or not curr.get("_dt"):
                continue
            delta     = curr["_dt"] - prev["_dt"]
            prev_loc  = (prev.get("location") or "").split(",")[0].strip()
            curr_loc  = (curr.get("location") or "").split(",")[0].strip()
            if prev_loc and curr_loc and prev_loc != curr_loc and delta.total_seconds() < 3600:
                alerts.append(
                    f"[IMPOSSIBLE TRAVEL] {upn}: "
                    f"{prev_loc} → {curr_loc} in {delta.total_seconds() / 60:.0f} min "
                    f"({prev['_dt'].strftime('%Y-%m-%d %H:%M')} UTC)"
                )

    return alerts


def detect_failure_then_success(records: list[dict], min_failures: int = 2) -> list[tuple]:
    """
    Accounts where failures precede a successful login — compromise indicator.
    Returns list of (upn, failure_count, success_count).
    """
    candidates = []
    by_upn     = defaultdict(list)

    for r in records:
        by_upn[r.get("upn") or r.get("display_name", "unknown")].append(r)

    for upn, entries in by_upn.items():
        sorted_e  = sorted(entries, key=lambda x: x.get("_dt") or datetime.min.replace(tzinfo=timezone.utc))
        failures  = [e for e in sorted_e if e.get("status", "").lower() == "failure"]
        successes = [e for e in sorted_e if e.get("status", "").lower() == "success"]
        if (
            len(failures) >= min_failures
            and successes
            and sorted_e[-1].get("status", "").lower() == "success"
        ):
            candidates.append((upn, len(failures), len(successes)))

    return sorted(candidates, key=lambda x: -x[1])


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
            normed       = {norm_fields[i]: v.strip() for i, v in enumerate(row.values())}
            normed["_dt"] = parse_date(normed.get("date", ""))
            records.append(normed)
    return records


# ============================================================================
# Filtering
# ============================================================================

def apply_filters(
    records:              list[dict],
    user:                 Optional[str],
    ip:                   Optional[str],
    app:                  Optional[str],
    location:             Optional[str],
    failures_only:        bool,
    success_only:         bool,
    risky:                bool,
    risky_threshold:      int,
    start_date:           Optional[datetime],
    end_date:             Optional[datetime],
    legacy_only:          bool,
    no_mfa:               bool,
    filter_legitimate:    bool,
) -> list[dict]:
    out = []
    for r in records:
        if user and user.lower() not in (r.get("upn", "") + " " + r.get("display_name", "")).lower():
            continue
        if ip and ip not in r.get("ip", ""):
            continue
        if app and app.lower() not in r.get("app", "").lower():
            continue
        if location and location.lower() not in r.get("location", "").lower():
            continue
        if failures_only and r.get("status", "").lower() != "failure":
            continue
        if success_only and r.get("status", "").lower() != "success":
            continue
        if risky and r.get("_risk_score", 0) < risky_threshold:
            continue
        if start_date and r.get("_dt") and r["_dt"] < start_date:
            continue
        if end_date and r.get("_dt") and r["_dt"] > end_date:
            continue
        if legacy_only and not any(leg in r.get("client_app", "").lower() for leg in LEGACY_AUTH_CLIENTS):
            continue
        if no_mfa:
            mfa = r.get("mfa_result", "").lower()
            if "not performed" not in mfa and mfa != "":
                continue
        if filter_legitimate:
            loc = r.get("location", "").lower()
            if any(kw in loc for kw in LEGITIMATE_LOCATION_KEYWORDS):
                continue
            asn = r.get("asn", "").strip()
            if asn in LEGITIMATE_ASNS:
                continue
        out.append(r)
    return out


# ============================================================================
# Console colors (ANSI — works in Windows Terminal, VSCode, most SSH)
# ============================================================================

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
GRAY    = "\033[90m"
DKCYAN  = "\033[36m"


def color_status(status: str) -> str:
    s = status.lower()
    if s == "success":
        return f"{GREEN}{status}{RESET}"
    if s == "failure":
        return f"{RED}{status}{RESET}"
    return f"{YELLOW}{status}{RESET}"


def color_risk(label: str) -> str:
    if label == "HIGH":
        return f"{RED}{label}{RESET}"
    if label == "MEDIUM":
        return f"{YELLOW}{label}{RESET}"
    return f"{GREEN}{label}{RESET}"


def truncate(val: str, width: int) -> str:
    val = val or ""
    return val if len(val) <= width else val[: width - 1] + "…"


def print_banner(title: str) -> None:
    print(f"\n{CYAN}{'=' * 84}{RESET}")
    print(f"{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'=' * 84}{RESET}\n")


# ============================================================================
# Console table — fixed-width, safe for web shells and narrow terminals
# ============================================================================

COL_WIDTHS = {
    "Date (UTC)":   20,
    "UPN":          30,
    "IP":           16,
    "Location":     18,
    "App":          22,
    "Client App":   20,
    "Status":        9,
    "MFA":          16,
    "Risk":          6,
}

# ANSI escape sequences add invisible bytes — pad colored values by this much
# to keep columns aligned: 9 bytes for standard ANSI color + reset pairs.
_COLOR_PAD = 9


def _header_row() -> str:
    return "  ".join(f"{k:<{v}}" for k, v in COL_WIDTHS.items())


def print_table(records: list[dict], max_rows: int = 200) -> None:
    header  = _header_row()
    divider = GRAY + "-" * len(header) + RESET

    print(f"{BOLD}{CYAN}{header}{RESET}")
    print(divider)

    for i, r in enumerate(records):
        if i >= max_rows:
            print(f"{GRAY}  ... {len(records) - max_rows} more rows — use --export to see all{RESET}")
            break

        dt_str  = r["_dt"].strftime("%Y-%m-%d %H:%M:%S") if r.get("_dt") else r.get("date", "")
        upn     = truncate(r.get("upn") or r.get("display_name", ""), COL_WIDTHS["UPN"])
        ip      = truncate(r.get("ip", ""), COL_WIDTHS["IP"])
        loc     = truncate(r.get("location", ""), COL_WIDTHS["Location"])
        app     = truncate(r.get("app", ""), COL_WIDTHS["App"])
        client  = truncate(r.get("client_app", ""), COL_WIDTHS["Client App"])
        status  = truncate(r.get("status", ""), COL_WIDTHS["Status"])
        mfa     = truncate(r.get("mfa_result", ""), COL_WIDTHS["MFA"])
        risk    = r.get("_risk_label", "LOW")

        # color_status/color_risk add ANSI bytes, so we adjust padding manually
        status_col = color_status(status)
        risk_col   = color_risk(risk)

        print(
            f"  {dt_str:<{COL_WIDTHS['Date (UTC)']}}"
            f"  {upn:<{COL_WIDTHS['UPN']}}"
            f"  {ip:<{COL_WIDTHS['IP']}}"
            f"  {loc:<{COL_WIDTHS['Location']}}"
            f"  {app:<{COL_WIDTHS['App']}}"
            f"  {client:<{COL_WIDTHS['Client App']}}"
            f"  {status_col:<{COL_WIDTHS['Status'] + _COLOR_PAD}}"
            f"  {mfa:<{COL_WIDTHS['MFA']}}"
            f"  {risk_col}"
        )


# ============================================================================
# Summary report
# ============================================================================

def print_summary(records: list[dict]) -> None:
    total = len(records)
    if total == 0:
        print(f"{YELLOW}No records to summarize.{RESET}")
        return

    statuses  = defaultdict(int)
    upns      = defaultdict(int)
    ips       = defaultdict(int)
    apps      = defaultdict(int)
    clients   = defaultdict(int)
    locations = defaultdict(int)
    risks     = defaultdict(int)

    for r in records:
        statuses[r.get("status", "Unknown").capitalize()] += 1
        upns[r.get("upn") or r.get("display_name", "Unknown")]  += 1
        ips[r.get("ip", "Unknown")]                             += 1
        apps[r.get("app", "Unknown")]                           += 1
        clients[r.get("client_app", "Unknown")]                 += 1
        loc = (r.get("location") or "").split(",")[0].strip() or "Unknown"
        locations[loc] += 1
        risks[r.get("_risk_label", "LOW")] += 1

    print_banner("SUMMARY")

    print(f"  {BOLD}Total records : {total}{RESET}\n")

    print(f"  {BOLD}{'Status':<22} {'Count':>6}  {'%':>6}{RESET}")
    for k, v in sorted(statuses.items(), key=lambda x: -x[1]):
        print(f"    {color_status(k):<{22 + _COLOR_PAD}} {v:>6}  {v / total * 100:>5.1f}%")

    print()
    print(f"  {BOLD}{'Risk Level':<12} {'Count':>6}{RESET}")
    for label in ("HIGH", "MEDIUM", "LOW"):
        v = risks.get(label, 0)
        print(f"    {color_risk(label):<{12 + _COLOR_PAD}} {v:>6}")

    _top10_section("Top 10 Users",               upns)
    _top10_section("Top 10 Source IPs",           ips,    width=22)
    _top10_section("Top 10 Applications",         apps)
    _top10_section("Top 10 Locations (country)",  locations)

    print(f"\n  {BOLD}Top 10 Client Apps (auth method){RESET}")
    for k, v in sorted(clients.items(), key=lambda x: -x[1])[:10]:
        flag = f"  {RED}[LEGACY AUTH]{RESET}" if any(leg in k.lower() for leg in LEGACY_AUTH_CLIENTS) else ""
        print(f"    {truncate(k, 38):<38}  {v:>5} events{flag}")


def _top10_section(title: str, counter: dict, width: int = 40) -> None:
    print(f"\n  {BOLD}{title}{RESET}")
    for k, v in sorted(counter.items(), key=lambda x: -x[1])[:10]:
        print(f"    {truncate(k, width):<{width}}  {v:>5} events")


# ============================================================================
# Anomaly report
# ============================================================================

def print_anomalies(records: list[dict], bf_threshold: int) -> None:
    print_banner("ANOMALY DETECTION")

    # ── Brute force / password spray ─────────────────────────────────────
    bf = detect_brute_force(records, bf_threshold)
    if bf:
        print(f"  {BOLD}{RED}Brute-Force / Password Spray Candidates{RESET}")
        for upn, alerts in sorted(bf.items()):
            for a in alerts:
                print(f"    {YELLOW}▶{RESET} {upn}:  {a}")
        print()
    else:
        print(f"  {GREEN}No brute-force patterns detected (threshold: {bf_threshold} failures){RESET}\n")

    # ── Impossible travel ─────────────────────────────────────────────────
    it = detect_impossible_travel(records)
    if it:
        print(f"  {BOLD}{RED}Impossible Travel{RESET}")
        for a in it:
            print(f"    {YELLOW}▶{RESET} {a}")
        print()
    else:
        print(f"  {GREEN}No impossible travel detected{RESET}\n")

    # ── Failure → Success (compromise indicator) ──────────────────────────
    fts = detect_failure_then_success(records)
    if fts:
        print(f"  {BOLD}{RED}Failure → Success Pattern  (possible account compromise){RESET}")
        for upn, fail_n, succ_n in fts:
            print(f"    {YELLOW}▶{RESET} {upn}:  {fail_n} failure(s) followed by {succ_n} success(es)")
        print()
    else:
        print(f"  {GREEN}No failure→success compromise patterns detected{RESET}\n")

    # ── Accounts with MFA denied ──────────────────────────────────────────
    mfa_denied = defaultdict(int)
    for r in records:
        mfa = r.get("mfa_result", "").lower()
        if "denied" in mfa or "blocked" in mfa:
            mfa_denied[r.get("upn") or r.get("display_name", "unknown")] += 1

    if mfa_denied:
        print(f"  {BOLD}{RED}MFA Denied / Blocked (MFA Fatigue Indicator){RESET}")
        for upn, count in sorted(mfa_denied.items(), key=lambda x: -x[1]):
            print(f"    {YELLOW}▶{RESET} {upn}:  {count} MFA denial/block event(s)")
        print()
    else:
        print(f"  {GREEN}No MFA denial/block events detected{RESET}\n")


# ============================================================================
# CSV export
# ============================================================================

EXPORT_FIELDS = [
    "date", "upn", "ip", "location", "asn",
    "app", "resource", "client_app",
    "status", "error_code", "failure_reason",
    "mfa_result", "mfa_method", "auth_requirement",
    "compliant", "managed", "join_type",
    "ca_status", "flagged", "incoming_token_type",
    "browser", "os", "device_id",
    "correlation_id", "request_id",
    "_risk_score", "_risk_label", "_risk_reasons",
]


def export_csv(records: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            row = {f: r.get(f, "") for f in EXPORT_FIELDS}
            row["_risk_reasons"] = "; ".join(r.get("_risk_reasons") or [])
            writer.writerow(row)
    print(f"\n{GREEN}  Exported {len(records)} records → {path}{RESET}")


def dedupe_by_ip(records: list[dict]) -> list[dict]:
    """
    Return one record per unique IP address.
    Where an IP appears multiple times, keep the record with the highest
    risk score. Records with no IP are kept as-is.
    """
    seen: dict[str, dict] = {}
    no_ip = []
    for r in records:
        ip = r.get("ip", "").strip()
        if not ip:
            no_ip.append(r)
            continue
        if ip not in seen or r.get("_risk_score", 0) > seen[ip].get("_risk_score", 0):
            seen[ip] = r
    return list(seen.values()) + no_ip


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Entra Interactive Sign-In log parser for incident response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("-f", "--file", required=True, help="Path to Entra sign-in CSV export")

    # ── Filters ───────────────────────────────────────────────────────────
    filt = parser.add_argument_group("Filters")
    filt.add_argument("--user",             metavar="UPN",          help="Filter by UPN or display name (partial)")
    filt.add_argument("--ip",               metavar="IP",           help="Filter by source IP (partial)")
    filt.add_argument("--app",              metavar="APP",          help="Filter by application name (partial)")
    filt.add_argument("--location",         metavar="LOCATION",     help="Filter by location string (partial)")
    filt.add_argument("--start",            metavar="YYYY-MM-DD",   help="Start date (UTC)")
    filt.add_argument("--end",              metavar="YYYY-MM-DD",   help="End date (UTC)")
    filt.add_argument("--failures-only",    action="store_true",    help="Show failed sign-ins only")
    filt.add_argument("--success-only",     action="store_true",    help="Show successful sign-ins only")
    filt.add_argument("--risky",            action="store_true",    help="Show records above risk threshold")
    filt.add_argument("--risky-threshold",  type=int, default=None,  metavar="SCORE",
                      help="Risk score threshold — implies --risky (default: 30)")
    filt.add_argument("--legacy-only",      action="store_true",    help="Show legacy/basic auth events only")
    filt.add_argument("--no-mfa",                  action="store_true",  help="Show events where MFA was not performed")
    filt.add_argument("--filter-remove-legitimate", action="store_true",  help="Remove known-legitimate traffic (Ohio locations, known-good ASNs)")

    # ── Actions ───────────────────────────────────────────────────────────
    act = parser.add_argument_group("Actions")
    act.add_argument("--summary",   action="store_true", help="Print statistical summary")
    act.add_argument("--anomalies", action="store_true", help="Run anomaly detection")
    act.add_argument("--all",       action="store_true", help="Run summary + anomalies + table")
    act.add_argument("--table",     action="store_true", help="Print event table (default if no action given)")
    act.add_argument("--max-rows",  type=int, default=200, metavar="N",
                     help="Max table rows (default: 200)")
    act.add_argument("--sort",
                     choices=["date", "risk", "user", "ip", "status"], default="date",
                     help="Table sort order (default: date)")
    act.add_argument("--brute-force-threshold", type=int, default=5, metavar="N",
                     help="Failure count to flag brute force (default: 5)")
    act.add_argument("--export",            metavar="PATH", help="Export filtered results to CSV")
    act.add_argument("--export-unique-ips", metavar="PATH", help="Export one record per unique IP (highest-risk kept) to CSV")

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

    # ── Score every record ─────────────────────────────────────────────────
    for r in records:
        score, reasons     = score_record(r)
        r["_risk_score"]   = score
        r["_risk_label"]   = risk_label(score)
        r["_risk_reasons"] = reasons

    # ── Parse date filters ────────────────────────────────────────────────
    start_dt = parse_date(args.start) if args.start else None
    end_dt   = parse_date(args.end)   if args.end   else None

    # ── Resolve risky filter — --risky-threshold alone implies --risky ────
    risky_threshold = args.risky_threshold if args.risky_threshold is not None else 30
    risky           = args.risky or args.risky_threshold is not None

    # ── Apply filters ──────────────────────────────────────────────────────
    filtered = apply_filters(
        records,
        user                 = args.user,
        ip                   = args.ip,
        app                  = args.app,
        location             = args.location,
        failures_only        = args.failures_only,
        success_only         = args.success_only,
        risky                = risky,
        risky_threshold      = risky_threshold,
        start_date           = start_dt,
        end_date             = end_dt,
        legacy_only          = args.legacy_only,
        no_mfa               = args.no_mfa,
        filter_legitimate    = args.filter_remove_legitimate,
    )

    print(f"{CYAN}Matched: {len(filtered)} / {len(records)} records{RESET}")

    # ── Sort ───────────────────────────────────────────────────────────────
    sort_keys = {
        "date":   lambda r: r.get("_dt") or datetime.min.replace(tzinfo=timezone.utc),
        "risk":   lambda r: -r.get("_risk_score", 0),
        "user":   lambda r: (r.get("upn") or r.get("display_name") or ""),
        "ip":     lambda r: r.get("ip", ""),
        "status": lambda r: r.get("status", ""),
    }
    filtered.sort(key=sort_keys[args.sort])

    # ── Determine which actions to run ────────────────────────────────────
    run_all     = args.all
    run_summary = args.summary  or run_all
    run_anomaly = args.anomalies or run_all
    run_table   = args.table    or run_all or not any([
        args.summary, args.anomalies, args.export, args.export_unique_ips
    ])

    if run_summary:
        print_summary(filtered)

    if run_anomaly:
        print_anomalies(filtered, args.brute_force_threshold)

    if run_table:
        print_banner(f"SIGN-IN EVENTS  [{len(filtered)} records | sorted by {args.sort}]")
        print_table(filtered, args.max_rows)

    if args.export:
        export_csv(filtered, args.export)

    if args.export_unique_ips:
        unique = dedupe_by_ip(filtered)
        export_csv(unique, args.export_unique_ips)
        print(f"{CYAN}  Unique IPs: {len(unique)} records ({len(filtered) - len(unique)} duplicates removed){RESET}")

    # ── Risk tally footer ─────────────────────────────────────────────────
    highs = sum(1 for r in filtered if r.get("_risk_label") == "HIGH")
    meds  = sum(1 for r in filtered if r.get("_risk_label") == "MEDIUM")
    lows  = len(filtered) - highs - meds

    print(
        f"\n{BOLD}Risk tally:{RESET}  "
        f"{RED}{highs} HIGH{RESET}  |  "
        f"{YELLOW}{meds} MEDIUM{RESET}  |  "
        f"{GREEN}{lows} LOW{RESET}\n"
    )


if __name__ == "__main__":
    main()
