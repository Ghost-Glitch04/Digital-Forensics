"""
Parse-EntraSignInLogs.py
Author  : Ghost-Glitch04
Version : 1.0
Date    : 2026-03-25

Parses Microsoft Entra ID Interactive Sign-In log CSV exports for incident response.
Provides filtering, risk scoring, anomaly detection, and summary reporting.

Export the CSV from:
  Entra Portal → Monitoring → Sign-in logs → Download → CSV

Usage:
  python Parse-EntraSignInLogs.py -f SignIns.csv
  python Parse-EntraSignInLogs.py -f SignIns.csv --user jdoe@corp.com
  python Parse-EntraSignInLogs.py -f SignIns.csv --ip 1.2.3.4
  python Parse-EntraSignInLogs.py -f SignIns.csv --failures-only
  python Parse-EntraSignInLogs.py -f SignIns.csv --risky --export suspicious.csv
  python Parse-EntraSignInLogs.py -f SignIns.csv --summary
  python Parse-EntraSignInLogs.py -f SignIns.csv --brute-force-threshold 5
"""

import argparse
import csv
import sys
import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Optional

# ============================================================================
# Column name normalization — Entra exports use slightly different headers
# depending on portal version and export method. Map known variants to a
# canonical internal name.
# ============================================================================

COLUMN_MAP = {
    # Timestamp
    "date (utc)": "date",
    "date": "date",
    "created date (utc)": "date",
    "time": "date",

    # Identity
    "user display name": "display_name",
    "user principal name": "upn",
    "username": "upn",
    "user- username": "upn",
    "user id": "user_id",

    # Application
    "application": "app",
    "app": "app",
    "resource": "resource",
    "resource id": "resource_id",
    "client app": "client_app",
    "cross tenant access type": "cross_tenant_type",
    "incoming token type": "incoming_token_type",

    # Network
    "ip address": "ip",
    "location": "location",

    # Result
    "status": "status",
    "sign-in error code": "error_code",
    "failure reason": "failure_reason",
    "sign in error code": "error_code",

    # Device
    "device id": "device_id",
    "browser": "browser",
    "operating system": "os",
    "compliant": "compliant",
    "managed": "managed",
    "join type": "join_type",

    # MFA
    "multifactor authentication result": "mfa_result",
    "multifactor authentication auth method": "mfa_method",
    "multifactor authentication auth detail": "mfa_detail",
    "multifactor auth result": "mfa_result",
    "multifactor auth method": "mfa_method",
    "multifactor auth detail": "mfa_detail",

    # Policy
    "authentication requirement": "auth_requirement",
    "conditional access": "ca_status",
    "flagged for review": "flagged",
    "token issuer type": "token_issuer",

    # Misc
    "latency (ms)": "latency",
    "correlation id": "correlation_id",
    "request id": "request_id",
    "unique token identifier": "token_id",
}

# ============================================================================
# Legacy / basic auth client app values — high risk in IR context
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
# Risk scoring weights
# Each check returns (score_delta, label)
# ============================================================================

def score_record(rec: dict) -> tuple[int, list[str]]:
    """
    Returns (risk_score 0-100, list_of_risk_reasons).
    Higher = more suspicious.
    """
    score = 0
    reasons = []

    status = rec.get("status", "").lower()
    client_app = rec.get("client_app", "").lower()
    mfa_result = rec.get("mfa_result", "").lower()
    auth_req = rec.get("auth_requirement", "").lower()
    compliant = rec.get("compliant", "").lower()
    managed = rec.get("managed", "").lower()
    join_type = rec.get("join_type", "").lower()
    token_issuer = rec.get("token_issuer", "").lower()
    ca_status = rec.get("ca_status", "").lower()
    flagged = rec.get("flagged", "").lower()
    incoming_token = rec.get("incoming_token_type", "").lower()
    location = rec.get("location", "")
    error_code = rec.get("error_code", "").strip()

    # Failed sign-in
    if status == "failure":
        score += 15
        reasons.append("Failed authentication")

    # Interrupted / risky state
    if status == "interrupted":
        score += 10
        reasons.append("Interrupted sign-in")

    # Legacy / basic auth
    if any(legacy in client_app for legacy in LEGACY_AUTH_CLIENTS):
        score += 25
        reasons.append(f"Legacy auth client: {rec.get('client_app')}")

    # No MFA when MFA was required or available
    if "not performed" in mfa_result or mfa_result == "":
        if "multifactorauthentication" in auth_req or "mfa" in auth_req:
            score += 20
            reasons.append("MFA required but not performed")

    # MFA denied / blocked
    if "denied" in mfa_result or "blocked" in mfa_result:
        score += 30
        reasons.append(f"MFA denied/blocked: {rec.get('mfa_result')}")

    # Non-compliant device
    if compliant == "false" or compliant == "no":
        score += 15
        reasons.append("Non-compliant device")

    # Unmanaged device
    if managed == "false" or managed == "no":
        score += 10
        reasons.append("Unmanaged device")

    # Azure AD joined = lower risk; unregistered = higher
    if join_type in ("", "unregistered", "none"):
        score += 8
        reasons.append("Device unregistered / unknown join type")

    # Conditional Access not applied / failed
    if "failure" in ca_status or "not applied" in ca_status:
        score += 15
        reasons.append(f"Conditional Access issue: {rec.get('ca_status')}")

    # Flagged by Microsoft
    if flagged in ("true", "yes", "1"):
        score += 30
        reasons.append("Flagged for review by Microsoft")

    # External / cross-tenant token
    if incoming_token in ("external azure ad", "federated", "saml11", "saml20"):
        score += 10
        reasons.append(f"External/federated token: {rec.get('incoming_token_type')}")

    # Specific high-risk error codes
    HIGH_RISK_CODES = {
        "50074": "Strong auth required but not satisfied",
        "50076": "MFA required by policy",
        "50079": "User enrolled in MFA but bypassed",
        "50158": "External security challenge not satisfied",
        "53003":  "Access blocked by Conditional Access",
        "70044": "Session expired — token replay possible",
        "AADSTS50057": "Account disabled",
        "AADSTS50053": "Account locked (smart lockout)",
        "AADSTS50126": "Invalid credentials",
    }
    for code, label in HIGH_RISK_CODES.items():
        if error_code == code or code in (rec.get("failure_reason") or ""):
            score += 20
            reasons.append(f"High-risk error {code}: {label}")
            break

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

def detect_brute_force(records: list[dict], threshold: int = 5) -> dict[str, list[str]]:
    """
    Find users/IPs with >= threshold failures, especially where a success follows.
    Returns dict of upn -> list of alert strings.
    """
    alerts = defaultdict(list)

    # Group by UPN
    by_upn = defaultdict(list)
    for r in records:
        by_upn[r.get("upn", "unknown")].append(r)

    for upn, entries in by_upn.items():
        sorted_entries = sorted(entries, key=lambda x: x.get("_dt") or datetime.min)
        failures = [e for e in sorted_entries if e.get("status", "").lower() == "failure"]
        successes = [e for e in sorted_entries if e.get("status", "").lower() == "success"]

        if len(failures) >= threshold:
            alerts[upn].append(
                f"Brute-force candidate: {len(failures)} failures"
                + (f", followed by {len(successes)} success(es)" if successes else "")
            )

        # Password spray: many failures from different IPs in short window
        failure_ips = set(e.get("ip", "") for e in failures)
        if len(failure_ips) >= 3 and len(failures) >= threshold:
            alerts[upn].append(
                f"Possible password spray: {len(failures)} failures from {len(failure_ips)} distinct IPs"
            )

    return dict(alerts)


def detect_impossible_travel(records: list[dict], min_speed_kmh: int = 900) -> list[str]:
    """
    Very rough impossible travel check based on location string changes within
    a short time window. Flags location changes < 1 hour apart.
    Returns list of alert strings.
    """
    alerts = []
    by_upn = defaultdict(list)
    for r in records:
        if r.get("_dt") and r.get("location"):
            by_upn[r.get("upn", "unknown")].append(r)

    for upn, entries in by_upn.items():
        sorted_entries = sorted(entries, key=lambda x: x["_dt"])
        for i in range(1, len(sorted_entries)):
            prev = sorted_entries[i - 1]
            curr = sorted_entries[i]
            if not prev.get("_dt") or not curr.get("_dt"):
                continue
            delta = curr["_dt"] - prev["_dt"]
            prev_loc = (prev.get("location") or "").split(",")[0].strip()
            curr_loc = (curr.get("location") or "").split(",")[0].strip()
            if prev_loc and curr_loc and prev_loc != curr_loc:
                hours = delta.total_seconds() / 3600
                if hours < 1:
                    alerts.append(
                        f"[IMPOSSIBLE TRAVEL] {upn}: "
                        f"{prev_loc} → {curr_loc} in {delta.total_seconds()/60:.0f} min "
                        f"at {prev['_dt'].strftime('%Y-%m-%d %H:%M')} UTC"
                    )
    return alerts


# ============================================================================
# CSV loading and column normalization
# ============================================================================

def normalize_header(h: str) -> str:
    return COLUMN_MAP.get(h.strip().lower(), h.strip().lower().replace(" ", "_").replace("-", "_"))


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
            normed = {norm_fields[i]: v.strip() for i, v in enumerate(row.values())}
            normed["_dt"] = parse_date(normed.get("date", ""))
            records.append(normed)
    return records


# ============================================================================
# Filtering helpers
# ============================================================================

def apply_filters(
    records: list[dict],
    user: Optional[str],
    ip: Optional[str],
    app: Optional[str],
    failures_only: bool,
    success_only: bool,
    risky: bool,
    risky_threshold: int,
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    location: Optional[str],
    legacy_only: bool,
    no_mfa: bool,
) -> list[dict]:
    out = []
    for r in records:
        if user and user.lower() not in (r.get("upn", "") + r.get("display_name", "")).lower():
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
        if legacy_only and not any(
            leg in r.get("client_app", "").lower() for leg in LEGACY_AUTH_CLIENTS
        ):
            continue
        if no_mfa:
            mfa = r.get("mfa_result", "").lower()
            if not ("not performed" in mfa or mfa == ""):
                continue
        out.append(r)
    return out


# ============================================================================
# Display helpers
# ============================================================================

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
GRAY    = "\033[90m"
MAGENTA = "\033[95m"


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
    if not val:
        return ""
    return val if len(val) <= width else val[: width - 1] + "…"


def print_banner(title: str) -> None:
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}  {title}{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}\n")


def print_table(records: list[dict], max_rows: int = 200) -> None:
    """Fixed-width console table — safe for web shells and narrow terminals."""
    COL_W = {
        "Date (UTC)":   20,
        "UPN":          28,
        "IP":           16,
        "Location":     16,
        "App":          22,
        "Client App":   18,
        "Status":       11,
        "MFA":          14,
        "Risk":          7,
    }

    header = "  ".join(f"{k:<{v}}" for k, v in COL_W.items())
    divider = "-" * len(header)

    print(f"{BOLD}{CYAN}{header}{RESET}")
    print(GRAY + divider + RESET)

    shown = 0
    for r in records:
        if shown >= max_rows:
            print(f"{GRAY}  ... {len(records) - max_rows} more rows (use --export to see all){RESET}")
            break

        dt_str = r["_dt"].strftime("%Y-%m-%d %H:%M:%S") if r.get("_dt") else r.get("date", "")
        upn    = truncate(r.get("upn") or r.get("display_name", ""), COL_W["UPN"])
        ip     = truncate(r.get("ip", ""), COL_W["IP"])
        loc    = truncate(r.get("location", ""), COL_W["Location"])
        app    = truncate(r.get("app", ""), COL_W["App"])
        client = truncate(r.get("client_app", ""), COL_W["Client App"])
        status = truncate(r.get("status", ""), COL_W["Status"])
        mfa    = truncate(r.get("mfa_result", ""), COL_W["MFA"])
        risk   = r.get("_risk_label", "LOW")

        row = (
            f"  {dt_str:<{COL_W['Date (UTC)']}}"
            f"  {upn:<{COL_W['UPN']}}"
            f"  {ip:<{COL_W['IP']}}"
            f"  {loc:<{COL_W['Location']}}"
            f"  {app:<{COL_W['App']}}"
            f"  {client:<{COL_W['Client App']}}"
            f"  {color_status(status):<{COL_W['Status'] + 10}}"
            f"  {mfa:<{COL_W['MFA']}}"
            f"  {color_risk(risk)}"
        )
        print(row)
        shown += 1


def print_summary(records: list[dict]) -> None:
    total = len(records)
    if total == 0:
        print(f"{YELLOW}No records to summarize.{RESET}")
        return

    statuses   = defaultdict(int)
    upns       = defaultdict(int)
    ips        = defaultdict(int)
    apps       = defaultdict(int)
    clients    = defaultdict(int)
    locations  = defaultdict(int)
    risks      = defaultdict(int)

    for r in records:
        statuses[r.get("status", "Unknown").capitalize()] += 1
        upns[r.get("upn") or r.get("display_name", "Unknown")] += 1
        ips[r.get("ip", "Unknown")] += 1
        apps[r.get("app", "Unknown")] += 1
        clients[r.get("client_app", "Unknown")] += 1
        loc = (r.get("location") or "").split(",")[0].strip() or "Unknown"
        locations[loc] += 1
        risks[r.get("_risk_label", "LOW")] += 1

    print_banner("SUMMARY")

    print(f"  {BOLD}Total records:{RESET} {total}")
    print()

    print(f"  {BOLD}{'Status':<20} {'Count':>6}  {'%':>6}{RESET}")
    for k, v in sorted(statuses.items(), key=lambda x: -x[1]):
        pct = v / total * 100
        print(f"    {color_status(k):<30} {v:>6}  {pct:>5.1f}%")

    print()
    print(f"  {BOLD}{'Risk Level':<20} {'Count':>6}{RESET}")
    for label in ("HIGH", "MEDIUM", "LOW"):
        v = risks.get(label, 0)
        print(f"    {color_risk(label):<30} {v:>6}")

    print()
    print(f"  {BOLD}Top 10 Users{RESET}")
    for k, v in sorted(upns.items(), key=lambda x: -x[1])[:10]:
        print(f"    {k:<40}  {v:>5} events")

    print()
    print(f"  {BOLD}Top 10 Source IPs{RESET}")
    for k, v in sorted(ips.items(), key=lambda x: -x[1])[:10]:
        print(f"    {k:<20}  {v:>5} events")

    print()
    print(f"  {BOLD}Top 10 Applications{RESET}")
    for k, v in sorted(apps.items(), key=lambda x: -x[1])[:10]:
        print(f"    {truncate(k, 40):<40}  {v:>5} events")

    print()
    print(f"  {BOLD}Top 10 Client Apps (auth method){RESET}")
    for k, v in sorted(clients.items(), key=lambda x: -x[1])[:10]:
        flag = f"  {RED}[LEGACY]{RESET}" if any(
            leg in k.lower() for leg in LEGACY_AUTH_CLIENTS
        ) else ""
        print(f"    {truncate(k, 36):<36}  {v:>5} events{flag}")

    print()
    print(f"  {BOLD}Top 10 Locations (country){RESET}")
    for k, v in sorted(locations.items(), key=lambda x: -x[1])[:10]:
        print(f"    {k:<30}  {v:>5} events")


def print_anomalies(records: list[dict], bf_threshold: int) -> None:
    print_banner("ANOMALY DETECTION")

    # Brute force
    bf = detect_brute_force(records, bf_threshold)
    if bf:
        print(f"  {BOLD}{RED}Brute-Force / Password Spray{RESET}")
        for upn, alerts in sorted(bf.items()):
            for a in alerts:
                print(f"    {YELLOW}▶{RESET} {upn}: {a}")
        print()
    else:
        print(f"  {GREEN}No brute-force patterns detected (threshold: {bf_threshold} failures){RESET}\n")

    # Impossible travel
    it = detect_impossible_travel(records)
    if it:
        print(f"  {BOLD}{RED}Impossible Travel{RESET}")
        for a in it:
            print(f"    {YELLOW}▶{RESET} {a}")
        print()
    else:
        print(f"  {GREEN}No impossible travel detected{RESET}\n")

    # Accounts with failures then success (compromised indicator)
    by_upn = defaultdict(list)
    for r in records:
        by_upn[r.get("upn", "unknown")].append(r)

    compromised_candidates = []
    for upn, entries in by_upn.items():
        sorted_e = sorted(entries, key=lambda x: x.get("_dt") or datetime.min)
        has_failure = any(e.get("status", "").lower() == "failure" for e in sorted_e)
        has_success = any(e.get("status", "").lower() == "success" for e in sorted_e)
        if has_failure and has_success:
            failures = [e for e in sorted_e if e.get("status", "").lower() == "failure"]
            successes = [e for e in sorted_e if e.get("status", "").lower() == "success"]
            # Check if any success comes AFTER a failure
            if sorted_e[-1].get("status", "").lower() == "success" and len(failures) >= 2:
                compromised_candidates.append((upn, len(failures), len(successes)))

    if compromised_candidates:
        print(f"  {BOLD}{RED}Failure → Success Pattern (Possible Compromise){RESET}")
        for upn, fail_count, succ_count in sorted(compromised_candidates, key=lambda x: -x[1]):
            print(f"    {YELLOW}▶{RESET} {upn}: {fail_count} failures followed by {succ_count} success(es)")
        print()
    else:
        print(f"  {GREEN}No failure→success compromise patterns detected{RESET}\n")


# ============================================================================
# CSV export
# ============================================================================

EXPORT_FIELDS = [
    "date", "upn", "display_name", "ip", "location", "app", "resource",
    "client_app", "status", "error_code", "failure_reason",
    "mfa_result", "mfa_method", "auth_requirement",
    "compliant", "managed", "join_type",
    "ca_status", "flagged", "incoming_token_type",
    "browser", "os", "device_id", "correlation_id",
    "_risk_score", "_risk_label", "_risk_reasons",
]


def export_csv(records: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            row = {f: r.get(f, "") for f in EXPORT_FIELDS}
            row["_risk_reasons"] = "; ".join(r.get("_risk_reasons", []))
            writer.writerow(row)
    print(f"\n{GREEN}Exported {len(records)} records → {path}{RESET}")


# ============================================================================
# Entry point
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Entra Interactive Sign-In log CSV for incident response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Input
    parser.add_argument("-f", "--file", required=True, help="Path to Entra sign-in CSV export")

    # Filters
    filt = parser.add_argument_group("Filters")
    filt.add_argument("--user",          metavar="UPN/NAME",    help="Filter by UPN or display name (partial match)")
    filt.add_argument("--ip",            metavar="IP",          help="Filter by source IP (partial match)")
    filt.add_argument("--app",           metavar="APP",         help="Filter by application name (partial match)")
    filt.add_argument("--location",      metavar="COUNTRY/CITY",help="Filter by location string (partial match)")
    filt.add_argument("--start",         metavar="YYYY-MM-DD",  help="Start date filter (UTC)")
    filt.add_argument("--end",           metavar="YYYY-MM-DD",  help="End date filter (UTC)")
    filt.add_argument("--failures-only", action="store_true",   help="Show only failed sign-ins")
    filt.add_argument("--success-only",  action="store_true",   help="Show only successful sign-ins")
    filt.add_argument("--risky",         action="store_true",   help="Show only records above risk threshold")
    filt.add_argument("--risky-threshold", type=int, default=30,metavar="SCORE", help="Risk score threshold for --risky (default: 30)")
    filt.add_argument("--legacy-only",   action="store_true",   help="Show only legacy/basic auth events")
    filt.add_argument("--no-mfa",        action="store_true",   help="Show only events without MFA")

    # Actions
    act = parser.add_argument_group("Actions")
    act.add_argument("--summary",        action="store_true",   help="Print statistical summary")
    act.add_argument("--anomalies",      action="store_true",   help="Run anomaly detection (brute force, impossible travel)")
    act.add_argument("--all",            action="store_true",   help="Run summary + anomalies + table")
    act.add_argument("--table",          action="store_true",   help="Print event table (default when no action specified)")
    act.add_argument("--max-rows",       type=int, default=200, metavar="N",   help="Max table rows to print (default: 200)")
    act.add_argument("--brute-force-threshold", type=int, default=5, metavar="N",
                     help="Failure count to flag as brute force (default: 5)")
    act.add_argument("--export",         metavar="PATH",        help="Export filtered results to CSV")
    act.add_argument("--sort",           choices=["date","risk","user","ip","status"], default="date",
                     help="Sort order for table (default: date)")

    args = parser.parse_args()

    # ── Load ──────────────────────────────────────────────────────────────
    if not os.path.isfile(args.file):
        print(f"{RED}[ERROR] File not found: {args.file}{RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"{CYAN}Loading {args.file} ...{RESET}", end=" ", flush=True)
    records = load_csv(args.file)
    print(f"{GREEN}{len(records)} records loaded{RESET}")

    if not records:
        print(f"{YELLOW}No records found.{RESET}")
        sys.exit(0)

    # ── Score every record ─────────────────────────────────────────────────
    for r in records:
        score, reasons = score_record(r)
        r["_risk_score"] = score
        r["_risk_label"] = risk_label(score)
        r["_risk_reasons"] = reasons

    # ── Date filters ───────────────────────────────────────────────────────
    start_dt = parse_date(args.start) if args.start else None
    end_dt   = parse_date(args.end)   if args.end   else None

    # ── Apply filters ──────────────────────────────────────────────────────
    filtered = apply_filters(
        records,
        user          = args.user,
        ip            = args.ip,
        app           = args.app,
        failures_only = args.failures_only,
        success_only  = args.success_only,
        risky         = args.risky,
        risky_threshold = args.risky_threshold,
        start_date    = start_dt,
        end_date      = end_dt,
        location      = args.location,
        legacy_only   = args.legacy_only,
        no_mfa        = args.no_mfa,
    )

    print(f"{CYAN}Filtered: {len(filtered)} / {len(records)} records match{RESET}")

    # ── Sort ───────────────────────────────────────────────────────────────
    sort_keys = {
        "date":   lambda r: r.get("_dt") or datetime.min.replace(tzinfo=timezone.utc),
        "risk":   lambda r: -r.get("_risk_score", 0),
        "user":   lambda r: r.get("upn", ""),
        "ip":     lambda r: r.get("ip", ""),
        "status": lambda r: r.get("status", ""),
    }
    filtered.sort(key=sort_keys[args.sort])

    # ── Actions ────────────────────────────────────────────────────────────
    run_all     = args.all
    run_summary = args.summary or run_all
    run_anomaly = args.anomalies or run_all
    run_table   = args.table or run_all or (not any([args.summary, args.anomalies, args.export]))

    if run_summary:
        print_summary(filtered)

    if run_anomaly:
        print_anomalies(filtered, args.brute_force_threshold)

    if run_table:
        print_banner(f"SIGN-IN EVENTS  [{len(filtered)} records | sorted by {args.sort}]")
        print_table(filtered, args.max_rows)

    if args.export:
        export_csv(filtered, args.export)

    # ── Quick risk tally at the end ────────────────────────────────────────
    highs = sum(1 for r in filtered if r.get("_risk_label") == "HIGH")
    meds  = sum(1 for r in filtered if r.get("_risk_label") == "MEDIUM")
    print(f"\n{BOLD}Risk tally:{RESET}  "
          f"{RED}{highs} HIGH{RESET}  |  "
          f"{YELLOW}{meds} MEDIUM{RESET}  |  "
          f"{GREEN}{len(filtered) - highs - meds} LOW{RESET}")
    print()


if __name__ == "__main__":
    main()
