#!/usr/bin/env bash
# ============================================================
# UNIT: test-verify-l2.sh
# Purpose : Regression test suite for verify-l2.sh.
#           10 scenarios / 19 assertions covering reliability,
#           effectiveness, CRLF-blindness, failure paths,
#           output format, exit codes, idempotence, tmpfile
#           cleanup, and registry iteration.
# Inputs  : None. Reads verify-l2.sh (sibling) and
#           reference/grep_first.md + reference/integration-tracking.md
#           (two levels up) from the repository's own layout.
# Outputs : PASS/FAIL assertion list; final tally; exit 0 on
#           all-pass, 1 on any-fail.
# Depends : bash 4+, grep, sed, tr, git, mktemp, file (coreutils);
#           sibling verify-l2.sh; reference files at ../../reference/.
# Exit    : 0 = all assertions passed
#           1 = one or more assertions failed
# ============================================================
#
# Run manually when the harness or its registry changes:
#
#     ./skill_development/authoring-helpers/test-verify-l2.sh
#
# This suite is NOT invoked by the pre-commit hook — it is
# maintainer tooling for validating verify-l2.sh end-to-end
# after any change. The pre-commit hook runs verify-l2.sh
# only; this suite runs verify-l2.sh against constructed
# failure scenarios in an isolated git repo.
#
# Cross-refs:
#   verify-l2.sh (the harness this suite validates)
#   <lesson:2026-04-22:verification-applies-at-skill-level>
#   <lesson:2026-04-22:l2-harness-must-be-line-ending-aware>
#   <devlog:2026-04-23:v5-3-ship-regression-suite>
#   <devlog:2026-04-22:powershell-helper-ships-unverified>
#     (the V5.0 counterexample — shipping without a regression
#      suite creates an unverified residual this file avoids)

set -uo pipefail  # intentionally NOT set -e — we inspect exit codes

# ---------------------------------------------------------------------------
# PATH RESOLUTION + PREREQUISITE VALIDATION
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HARNESS_SRC="$SCRIPT_DIR/verify-l2.sh"
GREP_FIRST_SRC="$REPO_ROOT/reference/grep_first.md"
IT_SRC="$REPO_ROOT/reference/integration-tracking.md"

for f in "$HARNESS_SRC" "$GREP_FIRST_SRC" "$IT_SRC"; do
    if [[ ! -f "$f" ]]; then
        echo "[FATAL] Prerequisite missing: $f" >&2
        echo "        This suite expects the skill's deployed layout:" >&2
        echo "          skill_development/authoring-helpers/verify-l2.sh" >&2
        echo "          reference/grep_first.md" >&2
        echo "          reference/integration-tracking.md" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# TEST HARNESS
# ---------------------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
declare -a RESULTS=()

pass() { RESULTS+=("  PASS  $1"); PASS_COUNT=$((PASS_COUNT+1)); }
fail() { RESULTS+=("  FAIL  $1"); FAIL_COUNT=$((FAIL_COUNT+1)); }

check_eq() {
    local test_name="$1" expected="$2" actual="$3" detail="${4:-}"
    if [[ "$expected" == "$actual" ]]; then
        pass "$test_name (got $actual)"
    else
        fail "$test_name (expected=$expected actual=$actual $detail)"
    fi
}

# ---------------------------------------------------------------------------
# ISOLATED TEST ENVIRONMENT
# ---------------------------------------------------------------------------

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

cd "$TEST_ROOT"
git init -q
git config user.email test-verify-l2@local
git config user.name test-verify-l2

mkdir -p reference skill_development/authoring-helpers
cp "$GREP_FIRST_SRC" reference/
cp "$IT_SRC" reference/
cp "$HARNESS_SRC" skill_development/authoring-helpers/
chmod +x skill_development/authoring-helpers/verify-l2.sh

git add -A
git commit -q -m "test baseline"

HARNESS="$TEST_ROOT/skill_development/authoring-helpers/verify-l2.sh"

echo "============================================================"
echo "V5.3 L2 harness regression suite"
echo "Harness under test : $HARNESS_SRC"
echo "Reference sources  : $REPO_ROOT/reference/"
echo "Isolated test root : $TEST_ROOT"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# T1 — Baseline clean pass on CRLF files
# ---------------------------------------------------------------------------
echo "T1: Clean pass on V5.2 CRLF files"
T1_OUT="$("$HARNESS" 2>&1)"
T1_RC=$?
check_eq "T1.exit_code" 0 "$T1_RC"
if [[ "$T1_OUT" == "L2 verification: 21/21 checks passed" ]]; then
    pass "T1.output_format_success (single-line F2 minimal)"
else
    fail "T1.output_format_success (got: '$T1_OUT')"
fi

# ---------------------------------------------------------------------------
# T2 — LF transparency (same content, LF endings)
# ---------------------------------------------------------------------------
echo ""
echo "T2: Clean pass on LF-converted files (CRLF-blindness)"
for f in reference/*.md; do
    tr -d '\r' < "$f" > "$f.lf" && mv "$f.lf" "$f"
done
lf_check="$(file reference/grep_first.md)"
if [[ "$lf_check" == *CRLF* ]]; then
    fail "T2.setup (file still CRLF despite tr normalization)"
else
    pass "T2.setup (file confirmed LF)"
fi
T2_OUT="$("$HARNESS" 2>&1)"
T2_RC=$?
check_eq "T2.exit_code" 0 "$T2_RC"
if [[ "$T2_OUT" == "L2 verification: 21/21 checks passed" ]]; then
    pass "T2.pass_count_unchanged (LF produces same result as CRLF)"
else
    fail "T2.pass_count_unchanged (got: '$T2_OUT')"
fi
# Restore to CRLF for subsequent tests
for f in reference/*.md; do
    sed 's/$/\r/' "$f" > "$f.crlf" && mv "$f.crlf" "$f"
done

# ---------------------------------------------------------------------------
# T3 — Missing reference file (worst-case file-level drift)
# ---------------------------------------------------------------------------
echo ""
echo "T3: Missing grep_first.md → harness fails loudly"
mv reference/grep_first.md /tmp/gf_hidden_$$.md
T3_OUT="$("$HARNESS" 2>&1)"
T3_RC=$?
check_eq "T3.exit_code" 40 "$T3_RC"
T3_FAIL_LINES="$(echo "$T3_OUT" | grep -c 'FILE MISSING' || true)"
if [[ "$T3_FAIL_LINES" == "15" ]]; then
    pass "T3.fail_lines (15 G-checks reported FILE MISSING)"
else
    fail "T3.fail_lines (expected 15, got $T3_FAIL_LINES)"
fi
mv /tmp/gf_hidden_$$.md reference/grep_first.md

# ---------------------------------------------------------------------------
# T4 — Pattern no longer matches identifier in template
# (The single most important test — proves harness catches format drift.)
# ---------------------------------------------------------------------------
echo ""
echo "T4: Remove E_CONN_LOST from template → G1:E_CONN_LOST check fails"
sed -i 's/E_CONN_LOST/REPLACED_OUT/g' reference/grep_first.md
T4_OUT="$("$HARNESS" 2>&1)"
T4_RC=$?
check_eq "T4.exit_code" 40 "$T4_RC"
if echo "$T4_OUT" | grep -q "invariant=G1 | check=E_CONN_LOST"; then
    pass "T4.specific_fail (G1:E_CONN_LOST reported as VERIFY_FAILED)"
else
    fail "T4.specific_fail (did not find G1:E_CONN_LOST in output)"
fi
sed -i 's/REPLACED_OUT/E_CONN_LOST/g' reference/grep_first.md

# ---------------------------------------------------------------------------
# T5 — Not inside a git working tree → exit 99
# ---------------------------------------------------------------------------
echo ""
echo "T5: Run harness outside a git repo → exit 99"
NONGIT_DIR="$(mktemp -d)"
cp "$HARNESS" "$NONGIT_DIR/verify-l2.sh"
pushd "$NONGIT_DIR" >/dev/null
T5_OUT="$(./verify-l2.sh 2>&1)"
T5_RC=$?
popd >/dev/null
check_eq "T5.exit_code" 99 "$T5_RC"
if echo "$T5_OUT" | grep -q "\[FATAL\].*git working tree"; then
    pass "T5.fatal_message (FATAL message mentions git working tree)"
else
    fail "T5.fatal_message (got: '$T5_OUT')"
fi
rm -rf "$NONGIT_DIR"

# ---------------------------------------------------------------------------
# T6 — Idempotence: running twice yields identical result
# ---------------------------------------------------------------------------
echo ""
echo "T6: Idempotence — two runs, same output"
T6A="$("$HARNESS" 2>&1; echo "RC=$?")"
T6B="$("$HARNESS" 2>&1; echo "RC=$?")"
if [[ "$T6A" == "$T6B" ]]; then
    pass "T6.idempotent (two runs byte-identical output + rc)"
else
    fail "T6.idempotent (outputs differ)"
fi

# ---------------------------------------------------------------------------
# T7 — Failure output format: VERIFY_FAILED prefix + summary line
# ---------------------------------------------------------------------------
echo ""
echo "T7: F2 failure-output format validation"
sed -i 's/E_CONN_LOST/GONE/g' reference/grep_first.md
T7_OUT="$("$HARNESS" 2>&1)"
if echo "$T7_OUT" | grep -qE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] \[ERROR\] VERIFY_FAILED:'; then
    pass "T7.per_check_format (VERIFY_FAILED prefix with timestamp + level)"
else
    fail "T7.per_check_format (format mismatch)"
fi
if echo "$T7_OUT" | grep -qE 'VERIFY_FAILED: [0-9]+/21 L2 checks failed'; then
    pass "T7.summary_line (X/Y checks failed summary present)"
else
    fail "T7.summary_line (summary format mismatch)"
fi
sed -i 's/GONE/E_CONN_LOST/g' reference/grep_first.md

# ---------------------------------------------------------------------------
# T8 — Exit codes follow E1 convention (0 / 40 / 99)
# ---------------------------------------------------------------------------
echo ""
echo "T8: Exit code verification across all failure types"
check_eq "T8.exit_0_on_pass" 0 "$T1_RC"
check_eq "T8.exit_40_on_L2_fail" 40 "$T3_RC"
check_eq "T8.exit_99_on_env_error" 99 "$T5_RC"

# ---------------------------------------------------------------------------
# T9 — Tmpfile cleanup (EXIT trap)
# ---------------------------------------------------------------------------
echo ""
echo "T9: Tmpfile cleanup on success"
BEFORE_TMP="$(ls /tmp/tmp.* 2>/dev/null | wc -l)"
"$HARNESS" >/dev/null 2>&1
AFTER_TMP="$(ls /tmp/tmp.* 2>/dev/null | wc -l)"
if [[ "$BEFORE_TMP" == "$AFTER_TMP" ]]; then
    pass "T9.cleanup_success (no leaked /tmp files after successful run)"
else
    fail "T9.cleanup_success (before=$BEFORE_TMP after=$AFTER_TMP)"
fi

# ---------------------------------------------------------------------------
# T10 — Registry parsing iterates all 15 invariants
# ---------------------------------------------------------------------------
echo ""
echo "T10: All 15 invariants present in output under controlled failure"
mv reference/grep_first.md /tmp/gf_hidden_$$.md
mv reference/integration-tracking.md /tmp/it_hidden_$$.md
T10_OUT="$("$HARNESS" 2>&1)"
T10_DISTINCT="$(echo "$T10_OUT" | grep -oE 'invariant=[A-Z][0-9]+' | sort -u | wc -l)"
check_eq "T10.distinct_invariants" 15 "$T10_DISTINCT"
mv /tmp/gf_hidden_$$.md reference/grep_first.md
mv /tmp/it_hidden_$$.md reference/integration-tracking.md

# ---------------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------------

echo ""
echo "============================================================"
echo "RESULTS: $PASS_COUNT PASS  |  $FAIL_COUNT FAIL"
echo "============================================================"
for r in "${RESULTS[@]}"; do
    echo "$r"
done
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
