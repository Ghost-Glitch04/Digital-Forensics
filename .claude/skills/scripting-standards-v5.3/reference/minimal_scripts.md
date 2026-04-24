# Minimal Script Scaffolds

This file contains the **minimal-first** scaffold for each of the three supported languages. Use these as your starting point when writing a new script. Grow into the full phased template only when the script hits the complexity threshold described in SKILL.md ("When to Grow into the Full Script").

Each minimal scaffold is standard-compliant. A 40-line script that follows this shape needs nothing added to satisfy Ghost's standards — it is not a "simplified" version. It is a complete answer for simple scripts.

All three scaffolds in this file were **run end-to-end** during V4_5 authorship — dry-run, normal, debug, and missing-input paths. Bugs found during that verification are fixed here. See the "Verified" markers at the bottom of each scaffold.

---

## What "Minimal" Includes (and Excludes)

**Includes:**
- Script header (name, purpose, date, version, usage)
- Error code reference block
- Log helper (file + console, `--debug` gating)
- Argument parsing with at minimum `--dry-run` and `--debug` when side effects exist
- `SCRIPT_START` + environment snapshot logged once at the top
- Fail-fast input validation
- The work itself, with `[DRY-RUN]` guards before any write or mutation
- `SCRIPT_COMPLETE` + total duration at the end

**Excludes (these come with the full template):**
- Phase gates (`--stop-after-phase`)
- Per-unit timer context managers
- Dedicated verification units
- Retry helpers (add only if the script makes external calls)
- Partial success evaluation (add only if processing collections with expected failures)

---

## When to Stay Minimal

- Short utility scripts — one-shot conversions, simple renames, lookups
- No external service calls
- No multi-step data transformations
- Run time short enough that restarting from scratch is cheap
- Readable top-to-bottom in a single screen

---

## Python — Minimal Scaffold

```python
#!/usr/bin/env python3
"""
Script  : minimal_example.py
Purpose : One-line description of what this script does.
Author  : Ghost
Created : 2026-04-11
Version : 1.0.0

Usage:
    python minimal_example.py --input /path/to/file [--dry-run] [--debug]
"""

# ============================================================
# ERROR CODE REFERENCE
# 0  = Success
# 10 = Input file not found or unreadable
# 20 = Processing failure
# 99 = Unexpected / unhandled error
# ============================================================

import argparse
import logging
import os
import platform
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# Normalize level names to match Bash/PowerShell scaffolds so cross-language
# greps like `grep -E "WARN|FATAL"` work across any log this skill produces.
# Python's defaults are "WARNING" / "CRITICAL" — rename them at import time.
logging.addLevelName(logging.WARNING, "WARN")
logging.addLevelName(logging.CRITICAL, "FATAL")


# ============================================================
# HELPER: setup_logger
# ============================================================
def setup_logger(log_path: Path, debug_mode: bool = False) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_path)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug_mode else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--log-dir", type=Path, default=Path("./logs"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--debug", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log_path = args.log_dir / f"minimal-{datetime.now():%Y%m%d-%H%M%S}.log"
    logger = setup_logger(log_path, debug_mode=args.debug)
    start = time.perf_counter()

    logger.info(f"SCRIPT_START: {Path(__file__).name} | User: {os.getenv('USER')} | Host: {platform.node()}")
    logger.info(f"ENV_SNAPSHOT: python={platform.python_version()} | os={platform.platform()} | cwd={Path.cwd()}")
    params_str = " | ".join(f"{k}={v}" for k, v in vars(args).items())
    logger.info(f"PARAMS: {params_str}")
    if args.dry_run: logger.warning("DRY-RUN MODE ACTIVE")
    if args.debug:   logger.info("DEBUG MODE ACTIVE")

    try:
        # --- Fail-fast input validation ---
        if not args.input.exists() or not args.input.is_file():
            logger.error(f"UNIT_FAILED: validate_input | Path not found: {args.input}")
            sys.exit(10)

        # --- The work ---
        logger.info(f"UNIT_START: do_work | input={args.input}")
        # ... read, transform, compute ...
        result_count = 0  # replace with real work

        # --- Writes go through a dry-run guard ---
        if args.dry_run:
            logger.info(f"[DRY-RUN] Would write {result_count} results")
        else:
            # ... write the output ...
            logger.info(f"Wrote {result_count} results")
        logger.info(f"UNIT_END: do_work")

        total = time.perf_counter() - start
        logger.info(f"SCRIPT_COMPLETE: Success | Total Duration: {total:.3f}s")
        sys.exit(0)

    except SystemExit:
        raise  # Allow deliberate sys.exit() calls through; only catch unexpected exceptions.
    except Exception as exc:
        total = time.perf_counter() - start
        logger.critical(f"SCRIPT_FAILED: Unhandled error | {exc} | Total Duration: {total:.3f}s")
        logger.debug(f"STACK_TRACE:\n{traceback.format_exc()}")
        sys.exit(99)


if __name__ == "__main__":
    main()
```

*Verified 2026-04-11 on Python 3.13.12 (Kali). Ran `--dry-run`, normal, `--debug`, and missing-input paths. Exit codes 0/0/0/10. All SCRIPT_START / ENV_SNAPSHOT / PARAMS / UNIT_START / UNIT_END / SCRIPT_COMPLETE lines emit correctly. Bug fixed during verification: added `logging.addLevelName` calls so WARN/FATAL replace Python's default WARNING/CRITICAL, matching Bash and PowerShell logs.*

### Growth triggers for Python

Add from `reference/python.md` when:
- **External service call appears** → add `invoke_with_retry` + connection verification unit
- **Script grows past ~150 lines or 3 logical steps** → add `unit_timer` and phased structure
- **Multiple output files or complex output shape** → add `verify_file_output` / `verify_csv_output`
- **Processing collections where some failures are tolerable** → add `FAILURE_THRESHOLD_PCT` and partial success evaluation

---

## Bash — Minimal Scaffold

```bash
#!/usr/bin/env bash
# ============================================================
# Script  : minimal_example.sh
# Purpose : One-line description of what this script does.
# Author  : Ghost
# Created : 2026-04-11
# Version : 1.0.0
#
# Usage:
#   ./minimal_example.sh --input /path/to/file [--dry-run] [--debug]
# ============================================================

set -euo pipefail

# ============================================================
# ERROR CODE REFERENCE
# 0  = Success
# 10 = Input file not found or unreadable
# 20 = Processing failure
# 99 = Unexpected / unhandled error
# ============================================================

# --- Defaults ---
INPUT_PATH=""
LOG_DIR="./logs"
DRY_RUN=0
DEBUG_MODE=0
SCRIPT_NAME="$(basename "$0")"

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input)   INPUT_PATH="$2"; shift 2 ;;
    --log-dir) LOG_DIR="$2";   shift 2 ;;
    --dry-run) DRY_RUN=1;      shift   ;;
    --debug)   DEBUG_MODE=1;   shift   ;;
    *) echo "Unknown arg: $1" >&2; exit 99 ;;
  esac
done

# --- Log helper ---
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/minimal-$(date +%Y%m%d-%H%M%S).log"
log() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
  local line="[$ts] [$level] $msg"
  echo "$line" >> "$LOG_FILE"
  # Console: suppress DEBUG unless --debug
  if [[ "$level" != "DEBUG" || $DEBUG_MODE -eq 1 ]]; then
    echo "$line"
  fi
}

START_TS=$(date +%s)

log INFO "SCRIPT_START: $SCRIPT_NAME | User: ${USER:-unknown} | Host: $(hostname)"
log INFO "ENV_SNAPSHOT: bash=$BASH_VERSION | os=$(uname -a) | cwd=$(pwd)"
log INFO "PARAMS: input=$INPUT_PATH | log_dir=$LOG_DIR | dry_run=$DRY_RUN | debug=$DEBUG_MODE"
[[ $DRY_RUN   -eq 1 ]] && log WARN "DRY-RUN MODE ACTIVE"
[[ $DEBUG_MODE -eq 1 ]] && log INFO "DEBUG MODE ACTIVE"

# --- Fail-fast input validation ---
if [[ -z "$INPUT_PATH" || ! -f "$INPUT_PATH" || ! -r "$INPUT_PATH" ]]; then
  log ERROR "UNIT_FAILED: validate_input | Path not found or unreadable: $INPUT_PATH"
  exit 10
fi

# --- The work ---
log INFO "UNIT_START: do_work | input=$INPUT_PATH"
RESULT_COUNT=0  # replace with real work

if [[ $DRY_RUN -eq 1 ]]; then
  log INFO "[DRY-RUN] Would write $RESULT_COUNT results"
else
  log INFO "Wrote $RESULT_COUNT results"
fi
log INFO "UNIT_END: do_work"

# --- Completion ---
END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
log INFO "SCRIPT_COMPLETE: Success | Total Duration: ${DURATION}s"
exit 0
```

*Verified 2026-04-11 on Bash 5.3.9 (Kali). Ran `--dry-run`, normal, `--debug`, missing-input, and unknown-arg paths. Exit codes 0/0/0/10/99. All log prefixes emit correctly. Known limitation: `DURATION` is integer seconds (whole-second resolution from `date +%s`). For sub-second timing, promote to the full template's unit_timer — that is a growth trigger, not a bug in the minimal form.*

### Bash minimal caveats

- **`set -euo pipefail`** is non-negotiable. Without it, silent failures are the default behavior.
- **Array handling and word-splitting** is the #1 source of bash bugs. Quote everything.
- **Bash runs on zsh too** — `#!/usr/bin/env bash` makes the shell explicit when the script is invoked via a tool or agent runtime that defaults to another shell.
- **When testing via an agent**, wrap commands in `bash <<'EOF' ... EOF` rather than passing free-form args — the parent shell's word-splitting will mangle inputs otherwise.

### Growth triggers for Bash

Add from `reference/bash.md` when:
- **Any curl / ssh / external command that might be transient** → add `invoke_with_retry`
- **Two or more distinct processing steps** → break into named units and add `invoke_phase_start`/`invoke_phase_gate`
- **File outputs with structure** → add `verify_file_output` / `verify_csv_output`

---

## PowerShell — Minimal Scaffold

```powershell
<#
.SYNOPSIS
    One-line description of what this script does.

.DESCRIPTION
    Script  : Minimal-Example.ps1
    Author  : Ghost
    Created : 2026-04-11
    Version : 1.0.0

.PARAMETER InputPath
    Path to the input file.

.EXAMPLE
    .\Minimal-Example.ps1 -InputPath C:\data\input.csv -DryRun -DebugMode
#>

# ============================================================
# ERROR CODE REFERENCE
# 0  = Success
# 10 = Input file not found or unreadable
# 20 = Processing failure
# 99 = Unexpected / unhandled error
# ============================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InputPath,
    [string]$LogDir = ".\logs",
    [switch]$DryRun,
    [switch]$DebugMode
)

# --- Log helper ---
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$script:LogFile = Join-Path $LogDir ("minimal-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

function Write-Log {
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR','FATAL')][string]$Level,
        [string]$Message
    )
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line
    # Console gets everything except DEBUG; DEBUG appears on console only when --debug is passed.
    # File always gets all levels — DEBUG is there for post-mortem triage without being noisy during normal runs.
    if ($Level -ne 'DEBUG' -or $DebugMode) {
        Write-Host $line
    }
}

$ScriptStart = Get-Date

# Cross-platform user/host: $env:USERNAME and $env:COMPUTERNAME are Windows-only.
# On Linux/macOS pwsh they're unset, producing empty User/Host fields in logs.
# Fall back to $env:USER and [System.Net.Dns]::GetHostName() so SCRIPT_START is
# always populated regardless of where the script runs.
$UserName = if ($env:USERNAME) { $env:USERNAME } else { $env:USER }
$HostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

Write-Log INFO "SCRIPT_START: $($MyInvocation.MyCommand.Name) | User: $UserName | Host: $HostName"
Write-Log INFO "ENV_SNAPSHOT: ps_version=$($PSVersionTable.PSVersion) | os=$($PSVersionTable.OS) | cwd=$PWD"
Write-Log INFO "PARAMS: input_path=$InputPath | log_dir=$LogDir | dry_run=$DryRun | debug_mode=$DebugMode"
if ($DryRun)    { Write-Log WARN "DRY-RUN MODE ACTIVE" }
if ($DebugMode) { Write-Log INFO "DEBUG MODE ACTIVE" }

try {
    # --- Fail-fast input validation ---
    if (-not (Test-Path $InputPath -PathType Leaf)) {
        Write-Log ERROR "UNIT_FAILED: Validate-Input | Path not found: $InputPath"
        exit 10
    }

    # --- The work ---
    Write-Log INFO "UNIT_START: Do-Work | input=$InputPath"
    $resultCount = 0   # replace with real work

    if ($DryRun) {
        Write-Log INFO "[DRY-RUN] Would write $resultCount results"
    } else {
        Write-Log INFO "Wrote $resultCount results"
    }
    Write-Log INFO "UNIT_END: Do-Work"

    $duration = (Get-Date) - $ScriptStart
    Write-Log INFO ("SCRIPT_COMPLETE: Success | Total Duration: {0:N3}s" -f $duration.TotalSeconds)
    exit 0
}
catch {
    $duration = (Get-Date) - $ScriptStart
    Write-Log FATAL ("SCRIPT_FAILED: Unhandled error | {0} | Total Duration: {1:N3}s" -f $_.Exception.Message, $duration.TotalSeconds)
    Write-Log DEBUG "STACK_TRACE: $($_.ScriptStackTrace)"
    exit 99
}
```

*Verified 2026-04-11 on PowerShell 7.5.4 (Kali Linux). Ran `-DryRun`, normal, `-DebugMode`, and missing-input paths. Exit codes 0/0/0/10. Bug fixed during verification: `$env:USERNAME` and `$env:COMPUTERNAME` are Windows-only and silently produced empty User/Host fields on Linux pwsh ("User:  | Host: "). Added `$env:USER` and `[System.Net.Dns]::GetHostName()` fallbacks so SCRIPT_START is populated on all platforms.*

### Growth triggers for PowerShell

Add from `reference/powershell.md` when:
- **Any Graph / Azure / Entra call** → add `Verify-EntraConnection` and `Invoke-WithRetry`
- **Multiple processing stages** → add `Invoke-PhaseStart` / `Invoke-PhaseGate`
- **Structured outputs (CSV, JSON)** → add `Verify-CsvOutput` / `Verify-TextOutput`

---

## Growth Checklist

When graduating a script from minimal to full, add these in order — not all at once. Each addition should be justified by actual complexity the script has already grown into, not anticipated complexity.

1. **Phase gates** (`--stop-after-phase`) — when you want to run Preflight without continuing, or inspect Collection output before Processing
2. **Unit timer** — when individual units run long enough that duration matters for diagnosis
3. **Retry helper** — when an external call has started showing transient failures
4. **Verification units** — when an output file's correctness is not obvious by inspection
5. **Partial success evaluation** — when processing a collection where some per-record failures are expected and tolerable
6. **Connection verification unit** (often added later in a script's life, but logically belongs first in Phase 1 / preflight) — when external-service auth or scope could be wrong in ways that only show up mid-run

**Anti-pattern:** adding all six up front because "that's what the full template has." The full template exists to show the end state of a script that has grown into its complexity. Premature expansion produces ceremonial scripts that are harder to read than they need to be.

---

## What Verification Surfaced (V4_5)

Running the three scaffolds on real interpreters — which V4_4 authorship promised and did not do — caught two real bugs on the first pass:

1. **Python log level name inconsistency.** Python's `logging` module ships with `WARNING` and `CRITICAL` as the default level names. Bash and PowerShell scaffolds emit `WARN` and `FATAL`. A `grep -E "WARN|FATAL" *.log` across a mixed-language run would silently miss every Python warning. Fixed with two `logging.addLevelName()` calls at import time.

2. **PowerShell Windows-only env vars.** The scaffold used `$env:USERNAME` and `$env:COMPUTERNAME` — both Windows-specific. On Linux `pwsh`, they're unset, and the `SCRIPT_START` line rendered as `User:  | Host: ` with empty fields. No error, no warning — the log was just wrong. Fixed with platform-safe fallbacks to `$env:USER` and `[System.Net.Dns]::GetHostName()`.

Neither bug would have been caught by code review. Both were found in under five minutes of actual execution. That is the full argument for prove-first, stated in the form of its own rule being caught violating itself one minor version earlier.
