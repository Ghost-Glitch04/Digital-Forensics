#!/usr/bin/env bash
# ============================================================
# UNIT: verify-l2.sh
# Purpose : L2 verification harness for scripting-standards skill.
#           Tests that canonical grep patterns for each L2-covered
#           invariant match their worked-template identifiers in the
#           reference files. Catches format drift between invariant
#           patterns and the templates that demonstrate them.
# Inputs  : None. Reads reference/grep_first.md and
#           reference/integration-tracking.md from REPO_ROOT.
# Outputs : Minimal line on success (F2 convention);
#           full skill log format per failed check on failure.
# Depends : bash 4+, grep, tr, git (for repo root resolution), mktemp
# Exit    : 0 = all checks passed
#           40 = one or more L2 checks failed (commit aborted)
#           99 = harness internal error (missing file, env issue)
# ============================================================
#
# This harness is the institutional form of the /tmp/l2_verify.sh
# pattern named in <lesson:2026-04-22:l2-harness-must-be-line-ending-aware>
# — moved from temp-file authoring discipline to shipped pre-commit
# mechanical enforcement.
#
# Governance: registry patterns must stay byte-identical to the canonical
# patterns documented in the reference files. See README.md § Governance
# and <devlog:2026-04-23:v5-3-crlf-pre-normalize> for why the harness
# pre-normalizes file input rather than rewriting patterns for CRLF
# tolerance.
#
# Cross-refs:
#   <lesson:2026-04-22:l2-harness-must-be-line-ending-aware>
#   <lesson:2026-04-22:format-drift-in-self-authored-patches>
#   <lesson:2026-04-22:verification-applies-at-skill-level>
#   <devlog:2026-04-22:v5-2-formal-invariants-over-workflow-guidance>
#   <devlog:2026-04-23:v5-3-registry-inline-bash-array>
#   <devlog:2026-04-23:v5-3-crlf-pre-normalize>
#   <devlog:2026-04-23:v5-3-output-format-minimal-on-success-full-on-failure>
#   reference/grep_first.md § Per-Category Invariants and Workflow
#   reference/integration-tracking.md § Format Contract § Invariants I1-I6

set -euo pipefail

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

log_fail() {
    # Full skill log format per F2: verbose on failure.
    local invariant="$1" check_name="$2" pattern="$3" file="$4"
    echo "[$(timestamp)] [ERROR] VERIFY_FAILED: invariant=${invariant} | check=${check_name} | pattern='${pattern}' | file=${file}" >&2
}

fatal() {
    # Harness-intrinsic errors → exit 99 per E1 convention.
    echo "[$(timestamp)] [FATAL] ${1}" >&2
    exit 99
}

# Bash-native whitespace trim. NOT xargs — xargs interprets quotes and
# backslashes inside its input, which corrupts grep patterns containing
# `"`, `'`, `` ` ``, or `\`. Parameter expansion has no such interpretation.
trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

# Resolve repository root. Harness MUST run inside a git working tree —
# invoked by pre-commit hook or manually for regression testing.
if ! REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    fatal "Not inside a git working tree; cannot resolve REPO_ROOT"
fi

# Single reusable tmpfile for CRLF-normalized content, overwritten per check.
# Trapping EXIT guarantees cleanup even on harness error (signal, set -e exit).
if ! TMPFILE="$(mktemp)"; then
    fatal "mktemp failed; cannot create scratch file for CRLF normalization"
fi
trap 'rm -f "$TMPFILE"' EXIT

# ---------------------------------------------------------------------------
# L2-COVERED INVARIANT SET
# ---------------------------------------------------------------------------
# 15 invariants, 21 concrete checks across G1-G9 (grep_first.md) and I1-I6
# (integration-tracking.md). Some invariants have multiple checks where the
# worked template uses multiple representative identifiers (e.g., G1's
# rename example uses both the old and new names). Each check is:
#
#     "INVARIANT_ID | CHECK_NAME | GREP_PATTERN | TEMPLATE_FILE"
#
# Patterns are copy-exact from the canonical patterns documented in the
# reference files. Any drift between a registry pattern and its source
# canonical pattern is the exact failure mode this harness exists to
# prevent (reproduced inside the enforcement tool). See
# <lesson:2026-04-22:format-drift-in-self-authored-patches>.
#
# Updates: governed per README.md § Governance. Adding, removing, or
# revising a check triggers a vocabulary version bump in
# reference/grep_first.md § Format Contract § Governance Rule.
# ---------------------------------------------------------------------------

L2_CHECKS=(
    # G1 — Error and exit codes
    "G1 | E_CONN_LOST            | \bE_CONN_LOST\b            | reference/grep_first.md"
    "G1 | E_UPSTREAM_UNAVAILABLE | \bE_UPSTREAM_UNAVAILABLE\b | reference/grep_first.md"
    # G2 — Log prefixes
    "G2 | SCRIPT_START           | \bSCRIPT_START\b           | reference/grep_first.md"
    "G2 | PARTIAL_SUCCESS        | \bPARTIAL_SUCCESS\b        | reference/grep_first.md"
    # G3 — Configuration keys
    "G3 | database_url           | [\"']database_url[\"']     | reference/grep_first.md"
    # G4 — API endpoints
    "G4 | /api/users             | [\"'\`]/api/users\b        | reference/grep_first.md"
    "G4 | /api/accounts          | [\"'\`]/api/accounts\b     | reference/grep_first.md"
    # G5 — Environment variables
    "G5 | DATABASE_URL           | \bDATABASE_URL\b           | reference/grep_first.md"
    # G6 — Constants and enum values
    "G6 | MAX_RETRIES            | \bMAX_RETRIES\b            | reference/grep_first.md"
    # G7 — Function and class names
    "G7 | get_user_token         | \bget_user_token\b         | reference/grep_first.md"
    "G7 | Get-UserToken          | \bGet-UserToken\b          | reference/grep_first.md"
    # G8 — Type definitions
    "G8 | UserToken              | \bUserToken\b              | reference/grep_first.md"
    # G9 — File paths referenced across scripts
    "G9 | /var/log/myapp/        | /var/log/myapp/            | reference/grep_first.md"
    "G9 | config/default.yaml    | \bconfig/default\.yaml\b   | reference/grep_first.md"
    "G9 | logs/run.log           | \blogs/run\.log\b          | reference/grep_first.md"
    # I1 — CONTRACT block opening
    "I1 | CONTRACT_opening       | <CONTRACT id=\"            | reference/integration-tracking.md"
    # I2 — CONTRACT block closing
    "I2 | CONTRACT_closing       | </CONTRACT>                | reference/integration-tracking.md"
    # I3 — USES marker
    "I3 | USES_marker            | <USES contract=\"          | reference/integration-tracking.md"
    # I4 — Map contract heading
    "I4 | contract_heading       | ^## <contract:             | reference/integration-tracking.md"
    # I5 — Map CONSUMER entry
    "I5 | CONSUMER_entry         | ^- CONSUMER:               | reference/integration-tracking.md"
    # I6 — Change Log entry opening
    "I6 | change_log_entry       | ^### <change:              | reference/integration-tracking.md"
)

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

declare -i PASS_COUNT=0
declare -a FAILURES=()

for check in "${L2_CHECKS[@]}"; do
    # Parse pipe-separated entry; trim whitespace on each field.
    # NOTE: patterns MUST NOT contain literal `|` — that breaks IFS parsing.
    # See README.md § Governance for delimiter constraints on registry entries.
    IFS='|' read -r f_invariant f_check f_pattern f_file <<< "$check"
    invariant="$(trim "$f_invariant")"
    check_name="$(trim "$f_check")"
    pattern="$(trim "$f_pattern")"
    file="$(trim "$f_file")"

    abs_file="${REPO_ROOT}/${file}"

    if [[ ! -f "$abs_file" ]]; then
        log_fail "$invariant" "$check_name" "$pattern" "${file} (FILE MISSING)"
        FAILURES+=("${invariant}:${check_name}")
        continue
    fi

    # Pre-normalize CRLF→LF per <devlog:2026-04-23:v5-3-crlf-pre-normalize>.
    # Registry patterns stay byte-identical to canonical; CRLF is handled as
    # input pre-processing rather than by rewriting patterns.
    if ! tr -d '\r' < "$abs_file" > "$TMPFILE"; then
        fatal "tr failed while normalizing $abs_file"
    fi

    # Grep-test: pattern must match in the pre-normalized worked-template file.
    if grep -qE "$pattern" "$TMPFILE"; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        log_fail "$invariant" "$check_name" "$pattern" "$file"
        FAILURES+=("${invariant}:${check_name}")
    fi
done

# ---------------------------------------------------------------------------
# SUMMARY — F2 output format
# ---------------------------------------------------------------------------

TOTAL=${#L2_CHECKS[@]}
FAIL_COUNT=${#FAILURES[@]}

if [[ $FAIL_COUNT -eq 0 ]]; then
    # Minimal on success.
    echo "L2 verification: ${PASS_COUNT}/${TOTAL} checks passed"
    exit 0
fi

# Verbose on failure — per-check VERIFY_FAILED lines already emitted above.
# Summary line follows, then exit 40.
echo "" >&2
echo "[$(timestamp)] [ERROR] VERIFY_FAILED: ${FAIL_COUNT}/${TOTAL} L2 checks failed — commit aborted" >&2
exit 40
