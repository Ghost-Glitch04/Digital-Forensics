#!/usr/bin/env bash
# ============================================================
# SCRIPT  : verify-integrations.sh
# PURPOSE : Detect drift between integration-tracking markers in source
#           files and .integration-map.md at project root. Implements the
#           Integration Grep Protocol Q6 queries defined in
#           reference/integration-tracking.md.
# AUTHOR  : Ghost
# CREATED : 2026-04-22
# VERSION : 1.0.0
#
# USAGE   : ./verify-integrations.sh [--project-root PATH] [--map-path PATH]
#                                    [--stop-after-phase PHASE] [--debug]
#
# Recognizes the '# DRIFT-EXPECTED:' escape hatch at the top of the map
# file. When present, drift findings are downgraded from ERROR to WARN
# and the script exits 0 instead of 40.
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ============================================================
# ERROR CODE REFERENCE
# 0  = Success (no drift, or drift downgraded via DRIFT-EXPECTED)
# 10 = Map file not found
# 11 = Map file unreadable
# 20 = Processing failure
# 40 = Drift detected
# 99 = Unexpected / unhandled error
# ============================================================

# ============================================================
# CONFIGURATION
# ============================================================
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"

# Default project root is current directory; overridable via --project-root
PROJECT_ROOT="$(pwd)"
MAP_PATH=""
STOP_AFTER_PHASE="None"
DEBUG_MODE=false

# Marker patterns — invariants I1, I3, I4, I5 in integration-tracking.md
readonly CONTRACT_REGEX='<CONTRACT[[:space:]]+id="([^"]+)"[[:space:]]+version="([0-9]+)"[[:space:]]+scope="([^"]+)"'
readonly USES_REGEX='<USES[[:space:]]+contract="([^"]+)"[[:space:]]+version="([0-9]+)"'
readonly MAP_CONTRACT_REGEX='^##[[:space:]]+<contract:([^>]+)>'
readonly MAP_CONSUMER_REGEX='^-[[:space:]]+CONSUMER:[[:space:]]+([^:]+):([0-9]+)'
readonly DRIFT_EXPECTED_REGEX='^#[[:space:]]+DRIFT-EXPECTED:'

# ============================================================
# ARGUMENT PARSING
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-root)      PROJECT_ROOT="$2";       shift 2 ;;
        --map-path)          MAP_PATH="$2";           shift 2 ;;
        --stop-after-phase)  STOP_AFTER_PHASE="$2";   shift 2 ;;
        --debug)             DEBUG_MODE=true;         shift ;;
        -h|--help)
            grep '^#' "$0" | head -20
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 99
            ;;
    esac
done

[[ -z "$MAP_PATH" ]] && MAP_PATH="${PROJECT_ROOT}/.integration-map.md"

readonly LOG_DIR="${PROJECT_ROOT}/logs"
readonly LOG_FILE="${LOG_DIR}/verify-integrations-${TIMESTAMP}.log"

mkdir -p "$LOG_DIR"

# Collections populated during Collection phase.
# NOTE: Bash quirk — `${#assoc_array[@]}` triggers `unbound variable` under
# `set -u` for associative arrays that were declared but never assigned to.
# Initialize each with a dummy key and immediately unset it so the array is
# "touched". See Verification History entry [V1.0.0] at the bottom of this
# script.
declare -A CODE_CONTRACT_VERSION=([__init__]=1); unset 'CODE_CONTRACT_VERSION[__init__]'
declare -A CODE_CONTRACT_LOC=([__init__]=1);     unset 'CODE_CONTRACT_LOC[__init__]'
declare -A MAP_CONTRACTS=([__init__]=1);         unset 'MAP_CONTRACTS[__init__]'
declare -a CODE_USES=()             # "contract|version|file|line"
declare -a MAP_CONSUMERS=()         # "path|line"
DRIFT_EXPECTED=false

# Drift findings (pipe-separated: direction|contract_id|location|detail)
declare -a DRIFT=()

# Phase timing
PHASE_START_EPOCH=0
SCRIPT_START_EPOCH=$(date +%s)
CURRENT_PHASE=""

# ============================================================
# HELPERS
# ============================================================

log() {
    # Usage: log LEVEL PREFIX "message"
    local level="$1" prefix="$2" message="${3:-}"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"

    local line
    if [[ -n "$message" ]]; then
        line="[$ts] [$level] ${prefix}: $message"
    else
        line="[$ts] [$level] ${prefix}"
    fi

    echo "$line" >> "$LOG_FILE"

    # Console: suppress DEBUG unless --debug
    if [[ "$level" != "DEBUG" ]] || [[ "$DEBUG_MODE" == "true" ]]; then
        case "$level" in
            ERROR|FATAL) echo -e "\033[31m${line}\033[0m" >&2 ;;
            WARN)        echo -e "\033[33m${line}\033[0m" ;;
            *)           echo "$line" ;;
        esac
    fi
}

phase_start() {
    CURRENT_PHASE="$1"
    PHASE_START_EPOCH=$(date +%s)
    log INFO PHASE_START "$CURRENT_PHASE"
}

phase_end() {
    local summary="${1:-}"
    local now; now=$(date +%s)
    local duration=$((now - PHASE_START_EPOCH))
    if [[ -n "$summary" ]]; then
        log INFO PHASE_SUMMARY "$CURRENT_PHASE | $summary"
    fi
    log INFO PHASE_END "$CURRENT_PHASE | Phase Duration: ${duration}s"
}

phase_gate() {
    local phase="$1"
    if [[ "$STOP_AFTER_PHASE" == "$phase" ]]; then
        local now; now=$(date +%s)
        local total=$((now - SCRIPT_START_EPOCH))
        log INFO PHASE_GATE "Stopping cleanly after phase '$phase' | Total Duration: ${total}s"
        exit 0
    fi
}

# Error trap — emits structured failure log with line number
on_error() {
    local exit_code=$?
    local line_no=${1:-$LINENO}
    local cmd="${BASH_COMMAND:-unknown}"
    log DEBUG STACK_TRACE "line=$line_no | cmd=$cmd"
    log FATAL SCRIPT_FAILED "Unhandled error | line=$line_no | exit=${exit_code:-99}"
    exit "${exit_code:-99}"
}
trap 'on_error $LINENO' ERR

# ============================================================
# UNITS
# ============================================================

# <CONTRACT id="read_map_file" version="1" scope="internal">
#   PARAMS (positional):
#     $1  path  required  absolute path to .integration-map.md
#   EXIT_CODES:
#     0   success, global arrays MAP_CONTRACTS + MAP_CONSUMERS populated
#     10  file not found
#     11  file unreadable
#   STDOUT: (none)
#   SIDE_EFFECTS: populates MAP_CONTRACTS, MAP_CONSUMERS, DRIFT_EXPECTED
# </CONTRACT>
# ============================================================
# UNIT: read_map_file
# Purpose : Parse the Integration Map into globals
# Inputs  : path to .integration-map.md
# Outputs : MAP_CONTRACTS, MAP_CONSUMERS, DRIFT_EXPECTED (globals)
# Depends : None
# ============================================================
read_map_file() {
    local path="$1"
    log INFO UNIT_START "read_map_file | path=$path"

    if [[ ! -f "$path" ]]; then
        log ERROR UNIT_FAILED "read_map_file | path=$path | reason=file_not_found | exit=10"
        exit 10
    fi

    if [[ ! -r "$path" ]]; then
        log ERROR UNIT_FAILED "read_map_file | path=$path | reason=not_readable | exit=11"
        exit 11
    fi

    local line
    while IFS= read -r line; do
        if [[ "$line" =~ $DRIFT_EXPECTED_REGEX ]]; then
            DRIFT_EXPECTED=true
            log DEBUG DRIFT_EXPECTED_DETECTED "line=$line"
        fi
        if [[ "$line" =~ $MAP_CONTRACT_REGEX ]]; then
            MAP_CONTRACTS["${BASH_REMATCH[1]}"]=1
        fi
        if [[ "$line" =~ $MAP_CONSUMER_REGEX ]]; then
            MAP_CONSUMERS+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}")
        fi
    done < "$path"

    log INFO UNIT_END "read_map_file | contracts=${#MAP_CONTRACTS[@]} | consumers=${#MAP_CONSUMERS[@]} | drift_expected=$DRIFT_EXPECTED"
}

# ============================================================
# UNIT: collect_source_markers
# Purpose : Scan source files for CONTRACT and USES markers
# Inputs  : project root directory
# Outputs : CODE_CONTRACT_VERSION, CODE_CONTRACT_LOC, CODE_USES (globals)
# Depends : None
# ============================================================
collect_source_markers() {
    local root="$1"
    log INFO UNIT_START "collect_source_markers | root=$root"

    local files_scanned=0
    local file line line_num

    # Collect source files via find; handle spaces in paths safely
    while IFS= read -r -d '' file; do
        files_scanned=$((files_scanned + 1))
        line_num=0

        # Skip files inside logs/ or .git/ to avoid self-reference noise
        case "$file" in
            */logs/*|*/.git/*) continue ;;
        esac

        while IFS= read -r line || [[ -n "$line" ]]; do
            line_num=$((line_num + 1))
            if [[ "$line" =~ $CONTRACT_REGEX ]]; then
                local id="${BASH_REMATCH[1]}"
                local ver="${BASH_REMATCH[2]}"
                CODE_CONTRACT_VERSION["$id"]="$ver"
                CODE_CONTRACT_LOC["$id"]="${file}:${line_num}"
            fi
            if [[ "$line" =~ $USES_REGEX ]]; then
                CODE_USES+=("${BASH_REMATCH[1]}|${BASH_REMATCH[2]}|${file}|${line_num}")
            fi
        done < "$file"
    done < <(find "$root" -type f \
        \( -name '*.sh' -o -name '*.bash' \
        -o -name '*.ps1' -o -name '*.psm1' \
        -o -name '*.py' \) -print0 2>/dev/null)

    log INFO UNIT_END "collect_source_markers | contracts=${#CODE_CONTRACT_VERSION[@]} | uses=${#CODE_USES[@]} | files_scanned=$files_scanned"
}

# ============================================================
# UNIT: find_drift
# Purpose : Compute drift in three directions; populate DRIFT global
# Inputs  : (none; reads globals)
# Outputs : DRIFT (global)
# Depends : read_map_file, collect_source_markers
# ============================================================
find_drift() {
    log INFO UNIT_START "find_drift"

    # Direction 1: code-ahead-of-map
    local id
    for id in "${!CODE_CONTRACT_VERSION[@]}"; do
        if [[ -z "${MAP_CONTRACTS[$id]:-}" ]]; then
            DRIFT+=("code_ahead_of_map|${id}|${CODE_CONTRACT_LOC[$id]}|CONTRACT defined in source but no heading in map")
        fi
    done

    local use_entry contract_id
    for use_entry in "${CODE_USES[@]}"; do
        contract_id="${use_entry%%|*}"
        if [[ -z "${MAP_CONTRACTS[$contract_id]:-}" ]]; then
            DRIFT+=("code_ahead_of_map|${contract_id}|(use site)|USES references a contract with no heading in map")
        fi
    done

    # Direction 2: map-ahead-of-code
    local consumer path line full_path
    for consumer in "${MAP_CONSUMERS[@]}"; do
        path="${consumer%%|*}"
        line="${consumer##*|}"
        if [[ "$path" == /* ]]; then
            full_path="$path"
        else
            full_path="${PROJECT_ROOT}/${path}"
        fi
        if [[ ! -f "$full_path" ]]; then
            DRIFT+=("map_ahead_of_code|(any)|${path}:${line}|CONSUMER entry points to file that does not exist")
        fi
    done

    # Direction 3: version mismatch
    local use_id use_ver use_file use_line current_ver
    for use_entry in "${CODE_USES[@]}"; do
        IFS='|' read -r use_id use_ver use_file use_line <<< "$use_entry"
        current_ver="${CODE_CONTRACT_VERSION[$use_id]:-}"
        if [[ -n "$current_ver" ]] && [[ "$use_ver" != "$current_ver" ]]; then
            DRIFT+=("version_mismatch|${use_id}|${use_file}:${use_line}|USES version=${use_ver} but contract is now version=${current_ver}")
        fi
    done

    log INFO UNIT_END "find_drift | drift_count=${#DRIFT[@]}"
}

# ============================================================
# MAIN
# ============================================================

USER_NAME="${USER:-${USERNAME:-unknown}}"
HOST_NAME="$(hostname 2>/dev/null || echo unknown)"

log INFO SCRIPT_START "${SCRIPT_NAME} | User: ${USER_NAME} | Host: ${HOST_NAME}"
log INFO ENV_SNAPSHOT "bash=${BASH_VERSION} | os=$(uname -s) | cwd=${PROJECT_ROOT}"
log INFO PARAMS "ProjectRoot=${PROJECT_ROOT} | MapPath=${MAP_PATH} | StopAfterPhase=${STOP_AFTER_PHASE} | DebugMode=${DEBUG_MODE}"

[[ "$DEBUG_MODE" == "true" ]] && log INFO DEBUG_MODE_ACTIVE ""

# --- Phase 1: Preflight ---
phase_start "Preflight"
if [[ ! -d "$PROJECT_ROOT" ]]; then
    log FATAL SCRIPT_FAILED "ProjectRoot not found | path=${PROJECT_ROOT} | exit=10"
    exit 10
fi
log INFO VERIFY_OK "ProjectRoot exists | path=${PROJECT_ROOT}"
phase_end "ProjectRoot: verified"
phase_gate "Preflight"

# --- Phase 2: Collection ---
phase_start "Collection"
read_map_file "$MAP_PATH"
collect_source_markers "$PROJECT_ROOT"
phase_end "Map contracts: ${#MAP_CONTRACTS[@]} | Code contracts: ${#CODE_CONTRACT_VERSION[@]} | Code uses: ${#CODE_USES[@]}"
phase_gate "Collection"

# --- Phase 3: Analysis ---
phase_start "Analysis"
find_drift
phase_end "Drift findings: ${#DRIFT[@]} | DRIFT-EXPECTED active: ${DRIFT_EXPECTED}"
phase_gate "Analysis"

# --- Phase 4: Output ---
phase_start "Output"

drift_level="ERROR"
[[ "$DRIFT_EXPECTED" == "true" ]] && drift_level="WARN"

for entry in "${DRIFT[@]:-}"; do
    [[ -z "$entry" ]] && continue
    IFS='|' read -r direction contract_id location detail <<< "$entry"
    log "$drift_level" CONTRACT_DRIFT "direction=${direction} | contract_id=${contract_id} | location=${location} | detail=${detail}"
done

if [[ ${#DRIFT[@]} -eq 0 ]]; then
    log INFO INTEGRATION_MAP_UPDATED "No drift detected | contracts=${#MAP_CONTRACTS[@]} | consumers=${#MAP_CONSUMERS[@]}"
elif [[ "$DRIFT_EXPECTED" == "true" ]]; then
    log WARN VERIFY_WARN "Drift detected but DRIFT-EXPECTED active | drift_count=${#DRIFT[@]}"
else
    log ERROR VERIFY_FAILED "Drift detected | drift_count=${#DRIFT[@]} | exit=40"
fi

phase_end "Drift reported: ${#DRIFT[@]} at level ${drift_level}"

# --- Exit ---
now=$(date +%s)
total_duration=$((now - SCRIPT_START_EPOCH))

if [[ ${#DRIFT[@]} -gt 0 ]] && [[ "$DRIFT_EXPECTED" != "true" ]]; then
    log INFO SCRIPT_COMPLETE "Total Duration: ${total_duration}s | exit=40"
    exit 40
else
    log INFO SCRIPT_COMPLETE "Total Duration: ${total_duration}s | exit=0"
    exit 0
fi

# ============================================================
# VERIFICATION HISTORY
# ============================================================
# Bugs caught by running this script end-to-end against a test project.
# Matches the convention in reference/powershell.md, reference/python.md,
# and reference/minimal_scripts.md: the script documents its own real
# post-authoring bugs so a future editor doesn't reintroduce them.
#
# [V1.0.0] Empty associative array triggers `unbound variable` under set -u
# -----------------------------------------------------------
# Caught when: Phase 4d Test 8 — running against an empty project with no
# CONTRACT or USES markers. The script aborted in read_map_file at:
#
#   log INFO UNIT_END "... contracts=${#MAP_CONTRACTS[@]} ..."
#
# Bash 5.2 under `set -u` treats ${#ASSOC[@]} on a never-assigned
# associative array as an unbound variable, even when the array was
# declared with `declare -A`. Indexed arrays declared with `declare -a
# FOO=()` do not have this problem; associative arrays do.
#
# Fix: initialize each associative array at declaration time with a dummy
# key and immediately `unset` it. This "touches" the array so subsequent
# ${#ARR[@]} accesses succeed even when no real keys have been added.
# Applied to CODE_CONTRACT_VERSION, CODE_CONTRACT_LOC, MAP_CONTRACTS.
#
# Generalizable rule: any Bash script using `set -u` together with
# `declare -A` must touch each associative array before reading its size
# or iterating its keys. The `=([x]=1); unset 'ARR[x]'` idiom is the
# minimal fix. Regular indexed arrays declared with `=()` are unaffected.
# ============================================================
