#!/usr/bin/env bash
# handoff.sh — session-exit helper for the ai-kb vault skill.
#
# Runs the atomic validate → reindex → stats → re-validate sequence the
# _WRITE_PROTOCOL.md §2 requires. Fails loudly on any step so missed retrofits
# (r17) and index/stats drift surface before the session ends.
#
# Usage:
#   bash handoff.sh                    # defaults
#   VAULT=/custom/path bash handoff.sh
#
# Exit codes:
#   0 = all four steps clean, vault is ship-ready
#   1 = pre-write validation failed (fix before anything else)
#   2 = reindex failed
#   3 = stats failed
#   4 = post-write validation failed (almost always r17 — you promoted a rule
#       or added a type but didn't retrofit the tooling)
#   5 = vault not found

set -u

SCRIPT_VERSION=1

if [[ "${1:-}" == "--version" ]]; then
    echo "handoff.sh $SCRIPT_VERSION"
    exit 0
fi

VAULT="${VAULT:-/home/talos/obsidian/ai-kb}"

if [[ ! -d "$VAULT" ]]; then
    echo "HANDOFF_FAILED: vault not found at $VAULT" >&2
    exit 5
fi

echo "=== AI-KB VAULT HANDOFF ==="
echo "Vault: $VAULT"
echo

# Step 1: pre-write validation. If the vault was already broken on entry,
# this catches it before the AI blames handoff for its own writes.
echo "Step 1/4: validate (pre-write)"
if ! python "$VAULT/scripts/validate.py" 2>&1 | tail -5; then
    echo "HANDOFF_FAILED: pre-write validation failed." >&2
    echo "The vault was broken before handoff ran. Check your recent writes." >&2
    exit 1
fi

# Step 2: reindex. Rebuilds _INDEX.md from current state. Non-dry-run
# because we want it committed to disk for step 4's parity check.
echo
echo "Step 2/4: reindex"
if ! python "$VAULT/scripts/reindex.py" 2>&1 | tail -3; then
    echo "HANDOFF_FAILED: reindex failed." >&2
    exit 2
fi

# Step 3: stats. Rebuilds _MANIFEST.md STATS block and _BOOTSTRAP.md
# SCRIPT_VERSIONS table.
echo
echo "Step 3/4: stats"
if ! python "$VAULT/scripts/stats.py" 2>&1 | tail -3; then
    echo "HANDOFF_FAILED: stats failed." >&2
    exit 3
fi

# Step 4: post-write validation. The key r17 check — if you promoted a rule
# or added a type but didn't retrofit scripts/schema, this is where it shows.
echo
echo "Step 4/4: validate (post-write)"
POST_OUT=$(python "$VAULT/scripts/validate.py" 2>&1)
POST_EXIT=$?
echo "$POST_OUT" | tail -5

if [[ $POST_EXIT -ne 0 ]]; then
    echo >&2
    echo "HANDOFF_FAILED: post-write validation failed (exit $POST_EXIT)." >&2
    echo "This usually means one of:" >&2
    echo "  * rule_count frontmatter doesn't match rule headings" >&2
    echo "  * you promoted a rule/type but didn't retrofit tooling (see r17)" >&2
    echo "  * index parity mismatch" >&2
    echo "See references/meta_rules.md and references/failure_modes.md." >&2
    exit 4
fi

# Summary + git hint.
echo
echo "=== HANDOFF CLEAN ==="
if command -v git >/dev/null 2>&1 && [[ -d "$VAULT/.git" ]]; then
    CHANGED=$(cd "$VAULT" && git status --porcelain 2>/dev/null | wc -l)
    echo "Git: $CHANGED modified file(s) (run 'git status' in $VAULT to review)"
fi
echo "Session ready to end. Don't forget to update your agent profile's"
echo "session log row and contributed_rules count before closing."
exit 0