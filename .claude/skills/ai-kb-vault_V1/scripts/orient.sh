#!/usr/bin/env bash
# orient.sh — session-start helper for the ai-kb vault skill.
#
# Purpose: get a fresh AI productive in the vault with ~300 tokens of output
# instead of ~15KB of governance-file reading. Runs the self-healing and
# validation scripts, summarizes the result, and surfaces unread memos
# addressed to the calling model.
#
# Usage:
#   bash orient.sh                    # defaults, shows all memos
#   MODEL_ID=claude-opus-4-6 bash orient.sh  # filter memos to recipient
#   VAULT=/custom/path bash orient.sh        # override vault location
#
# Exit codes:
#   0 = vault clean and ready
#   1 = vault has pre-existing errors (will still print summary)
#   2 = vault not found or scripts missing

set -u

SCRIPT_VERSION=2

if [[ "${1:-}" == "--version" ]]; then
    echo "orient.sh $SCRIPT_VERSION"
    exit 0
fi

VAULT="${VAULT:-/home/talos/obsidian/ai-kb}"
MODEL_ID="${MODEL_ID:-}"

if [[ ! -d "$VAULT" ]]; then
    echo "ORIENT_FAILED: vault not found at $VAULT" >&2
    echo "Set VAULT=/path/to/ai-kb to override." >&2
    exit 2
fi

if [[ ! -f "$VAULT/scripts/validate.py" ]]; then
    echo "ORIENT_FAILED: $VAULT/scripts/validate.py missing — wrong vault path?" >&2
    exit 2
fi

echo "=== AI-KB VAULT ORIENTATION ==="
echo "Vault: $VAULT"
echo

# Step 1: stats.py self-heals bootstrap version table drift. Silent unless error.
if ! python "$VAULT/scripts/stats.py" >/dev/null 2>&1; then
    echo "WARN: stats.py failed — bootstrap version table may be stale"
fi

# Step 2: validate.py — capture output for warning surfacing (r15 discipline).
# We want orphan-dir warnings to reach the AI, not stay buried in logs.
VALIDATE_OUT=$(python "$VAULT/scripts/validate.py" 2>&1)
VALIDATE_EXIT=$?

# Step 3: parse key signals from validate output.
FILES_CHECKED=$(echo "$VALIDATE_OUT" | grep -oE 'files_checked=[0-9]+' | head -1 | cut -d= -f2)
UNKNOWN_DIRS=$(echo "$VALIDATE_OUT" | grep -oE "unknown content directory '[^']+/'" || true)

if [[ $VALIDATE_EXIT -eq 0 ]]; then
    echo "Validation: PASS ($FILES_CHECKED files, 0 errors)"
else
    echo "Validation: FAIL (exit $VALIDATE_EXIT) — fix before contributing"
    echo "$VALIDATE_OUT" | grep -E 'VERIFY_FAILED|ERROR' | head -5
fi

if [[ -n "$UNKNOWN_DIRS" ]]; then
    echo "WARN (r15): $UNKNOWN_DIRS"
fi

# Step 4: manifest snapshot — total rules, files, incidents, memos.
# Format in _MANIFEST.md: "- **Total rules:** 316"
if [[ -f "$VAULT/_MANIFEST.md" ]]; then
    extract() { grep -oE "\*\*Total $1:\*\* [0-9]+" "$VAULT/_MANIFEST.md" | grep -oE '[0-9]+$' | head -1; }
    RULES=$(extract "rules")
    FILES=$(extract "topic files")
    INCID=$(extract "incidents")
    MEMOS=$(extract "memos")
    if [[ -n "$RULES" ]]; then
        echo "Totals: ${RULES} rules, ${FILES} topic files, ${INCID} incidents, ${MEMOS} memos"
    fi
fi

# Step 5: script versions from the bootstrap table (sanity for this AI's view).
SCRIPT_VERSIONS=$(grep -E '^\| `[a-z_]+\.py`' "$VAULT/_BOOTSTRAP.md" 2>/dev/null | \
    awk -F'|' '{gsub(/[` ]/, "", $2); gsub(/ /, "", $3); printf "%s:%s ", $2, $3}')
[[ -n "$SCRIPT_VERSIONS" ]] && echo "Scripts (name:version, self-healed by stats.py): $SCRIPT_VERSIONS"

# Step 6: agent profile detection.
echo
if [[ -n "$MODEL_ID" ]]; then
    PROFILE="$VAULT/agents/${MODEL_ID}.md"
    if [[ -f "$PROFILE" ]]; then
        CHOSEN=$(grep -oE '\*\*Chosen name: [^*]+\*\*' "$PROFILE" | head -1 | sed 's/\*\*Chosen name: //;s/\*\*//')
        LAST=$(grep -oE 'last_session: [0-9-]+' "$PROFILE" | head -1 | cut -d' ' -f2)
        RCOUNT=$(grep -oE 'contributed_rules: [0-9]+' "$PROFILE" | head -1 | cut -d' ' -f2)
        echo "Profile: $MODEL_ID ($CHOSEN) — last_session=$LAST, rules=$RCOUNT"
    else
        echo "Profile: MISSING for $MODEL_ID — first-time contributor."
        echo "         Pick a chosen name and create agents/${MODEL_ID}.md."
        echo "         See references/collaboration.md and references/templates.md."
    fi
else
    echo "Profile: (MODEL_ID not set — pass MODEL_ID=<your-model-id> to check yours)"
fi

# Step 7: unread memos.
# search.py --brief omits status/to/from from its output, so we scan
# comms/*.md frontmatter directly. Python handles the YAML-ish block
# parsing more robustly than awk or sed.
echo
if [[ ! -d "$VAULT/comms" ]]; then
    echo "Memos: comms/ directory missing"
else
    MEMO_OUT=$(MEMO_MODEL_ID="$MODEL_ID" python3 - "$VAULT/comms" <<'PYEOF'
import os, sys, pathlib
comms = pathlib.Path(sys.argv[1])
me = os.environ.get("MEMO_MODEL_ID", "")
files = sorted(comms.glob("*.md"))
if not files:
    print("EMPTY")
    sys.exit(0)
hits_mine, hits_other = [], []
for f in files:
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines or lines[0].strip() != "---":
        continue
    fm = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if ":" in line:
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip()
    if fm.get("status") != "unread":
        continue
    to = fm.get("to", "")
    frm = fm.get("from", "")
    subj = fm.get("subject", "(no subject)")
    row = f"  {f.name}  from:{frm}  subject:{subj}"
    if me and (to == me or to == "all"):
        hits_mine.append(row)
    else:
        hits_other.append(f"  {f.name}  to:{to}  from:{frm}")
if not hits_mine and not hits_other:
    print("NONE")
elif hits_mine:
    print("MINE")
    for r in hits_mine:
        print(r)
    if hits_other:
        print(f"OTHER_COUNT {len(hits_other)}")
else:
    print("OTHER_ONLY")
    for r in hits_other[:5]:
        print(r)
PYEOF
)
    case "$MEMO_OUT" in
        EMPTY)
            echo "Memos: none (comms/ empty)" ;;
        NONE)
            echo "Memos: none unread" ;;
        MINE*)
            echo "Memos unread for you:"
            echo "$MEMO_OUT" | sed -n '2,$p' | grep -v '^OTHER_COUNT' || true
            OTHER=$(echo "$MEMO_OUT" | grep '^OTHER_COUNT' | awk '{print $2}')
            [[ -n "$OTHER" ]] && echo "  (+$OTHER other unread memo(s) not addressed to you)"
            ;;
        OTHER_ONLY*)
            if [[ -n "$MODEL_ID" ]]; then
                echo "Memos unread (none addressed to $MODEL_ID):"
            else
                echo "Memos unread (set MODEL_ID to filter):"
            fi
            echo "$MEMO_OUT" | sed -n '2,$p'
            ;;
    esac
fi

# Step 8: routing hints — what to do next.
echo
echo "=== NEXT ==="
echo "Retrieve  → see SKILL.md §Quick-retrieve or references/retrieval.md"
echo "Contribute → see SKILL.md §Quick-contribute or references/contribution.md"
echo "At session end → bash \$SKILL/scripts/handoff.sh"
echo

exit $VALIDATE_EXIT