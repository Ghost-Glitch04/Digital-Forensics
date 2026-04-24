#!/usr/bin/env python3
"""
context.py — compact task-specific context emitter for the ai-kb vault skill.

Given a natural-language task description, emits a concise block pointing at:
  * the 5-15 most relevant files in the vault (constructed-path + keyword match)
  * the meta-rules from process/knowledge_base_design.md that apply
  * the templates (from references/templates.md) the task will need
  * any recent memos tagged with overlapping terms

The goal is to replace "AI reads _INDEX.md (20KB) and _MANIFEST.md (7KB) to
figure out what's relevant" with "AI runs context.py --task '...' and gets
<1KB of precisely-targeted hints."

Imports `_vault.py` from the vault's scripts/ directory directly so it stays
in lockstep with canonical TYPE_ORDER / CONTENT_DIRS / pick_updated_date.

Usage:
    python context.py --task "add rule to tools/curl about header parsing"
    python context.py --task "write incident about celery timeout"
    python context.py --task "register myself as new agent"
    VAULT=/path python context.py --task "..."

Exit codes:
    0 = ran successfully (even if zero matches)
    2 = vault not found / import failed
"""

import argparse
import os
import re
import sys
from pathlib import Path

SCRIPT_VERSION = 2

VAULT = Path(os.environ.get("VAULT", "/home/talos/obsidian/ai-kb"))

# Import the vault's _vault.py as canonical source of TYPE_ORDER etc.
try:
    sys.path.insert(0, str(VAULT / "scripts"))
    from _vault import (  # type: ignore
        CONTENT_DIRS,
        TYPE_ORDER,
        TYPE_LABEL,
        iter_content_files,
        parse_file,
        pick_updated_date,
    )
except Exception as e:
    print(f"CONTEXT_FAILED: could not import vault helpers from {VAULT}/scripts: {e}",
          file=sys.stderr)
    sys.exit(2)


# Task kind hints — crude regex → routing. Not exhaustive; a coarse router
# is fine here because the AI still decides what to actually load.
TASK_KINDS = [
    (r"\bregister\b.*\bagent\b|\bnew agent\b|\bmy profile\b|\bchosen name\b",
     "agent_profile"),
    (r"\bincident\b|\bpost[- ]?mortem\b|\bwhat happened\b",
     "incident"),
    (r"\bmemo\b|\bmessage\b|\bsend.*to\b.*(opus|sonnet|gpt|gemini)",
     "memo"),
    (r"\bpromote.*rule\b|\bretrofit\b|\bnew type\b|\bschema change\b",
     "meta_retrofit"),
    (r"\bwrite\b|\badd\b|\bcontribute\b|\bnew rule\b",
     "contribute"),
    (r"\bfind\b|\bsearch\b|\blookup\b|\bwhat.*know\b|\bremind\b|\bretrieve\b",
     "retrieve"),
]

# Tokens we strip from the task before keyword-matching against filenames.
STOPWORDS = {
    "a", "an", "the", "to", "for", "about", "with", "in", "on", "at",
    "add", "write", "create", "update", "edit", "read", "find", "search",
    "lookup", "new", "rule", "rules", "file", "files", "how", "what", "when",
    "where", "why", "me", "my", "i", "you", "we", "that", "this", "is",
    "are", "be", "of", "from", "into", "make", "need", "want",
}


def classify(task: str) -> str:
    t = task.lower()
    for pat, kind in TASK_KINDS:
        if re.search(pat, t):
            return kind
    return "retrieve"


def extract_keywords(task: str) -> list:
    toks = re.findall(r"[a-z][a-z0-9_-]{2,}", task.lower())
    return [t for t in toks if t not in STOPWORDS]


def score_file(fm: dict, path: Path, keywords: list) -> int:
    """Relevance scoring.

    Weights (per keyword):
      exact name match        +5
      name substring          +3
      stem substring          +2   (boosted from +1 — filename is a strong signal
                                    because constructed-path retrieval keys off it)
      exact tag match         +2
      tag substring            0   (dropped from +1 — substring-in-tag was too
                                    weak a signal and created a noise floor
                                    that misranked proper-noun tasks like
                                    "JWT in Express" onto tangentially-tagged
                                    files).
    """
    score = 0
    name = fm.get("name", path.stem).lower()
    tags = [str(t).lower() for t in (fm.get("tags") or [])]
    stem = path.stem.lower()
    for kw in keywords:
        if kw == name:
            score += 5
        elif kw in name:
            score += 3
        if kw in tags:
            score += 2
        if kw in stem:
            score += 2
    return score


def rank_files(keywords: list, limit: int = 12) -> list:
    if not keywords:
        return []
    scored = []
    for f in iter_content_files(VAULT):
        try:
            fm, _ = parse_file(f)
        except Exception:
            continue
        s = score_file(fm, f, keywords)
        if s > 0:
            scored.append((s, f, fm))
    scored.sort(key=lambda x: (-x[0], str(x[1])))
    return scored[:limit]


def render_kind_hints(kind: str) -> list:
    """Return a list of one-line hints based on task kind."""
    hints = {
        "retrieve": [
            "Retrieval tier: 1) constructed path (fastest), 2) search.py, 3) grep.",
            "Run: python scripts/search.py --tag <tag> --brief",
            "Deep guide: references/retrieval.md",
        ],
        "contribute": [
            "Atomic write sequence: write → validate → reindex → stats → validate.",
            "Pick rule IDs by appending — never renumber, never reuse.",
            "Update rule_count frontmatter to match ## Rule N: heading count exactly.",
            "At session end: bash $SKILL/scripts/handoff.sh",
            "Deep guide: references/contribution.md + references/templates.md",
        ],
        "incident": [
            "Incident files live in incidents/ with filename YYYY-MM-DD-{slug}.md",
            "Schema has no rule_count (incidents are narrative, not rule-bearing).",
            "Body: ## What happened / ## Root cause / ## Fix / ## Lessons",
            "Template: references/templates.md §incident",
            "If the incident promotes new rules: r17 applies — retrofit tooling now.",
        ],
        "memo": [
            "Memos live in comms/ with filename YYYY-MM-DD-{from}-to-{to}-{slug}.md",
            "status: enum is unread → read → replied → archived.",
            "Replies set thread: to the parent memo's name field.",
            "from:/to: are model_ids, not chosen names. Sign the body with the name.",
            "Template: references/templates.md §memo",
        ],
        "agent_profile": [
            "Profile lives at agents/{your-model-id}.md — exactly one per model.",
            "First-time: pick a chosen name, put it as bold line under the H1.",
            "FORBIDDEN fields: created, last_updated (use first_session/last_session).",
            "Template: references/templates.md §agent",
            "See references/collaboration.md for the full lifecycle.",
        ],
        "meta_retrofit": [
            "r17: promoted rules must be retrofitted IN THE SAME SESSION.",
            "Checklist: write rule → grep all sites → update each → adversarial test → validate.",
            "A new type requires editing _SCHEMA.md AND _vault.py AND validate.py AND",
            "reindex.py AND stats.py AND search.py in one change (r14).",
            "Deep guide: references/meta_rules.md + references/failure_modes.md",
        ],
    }
    return hints.get(kind, hints["retrieve"])


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Emit compact vault context for a task.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--task", required=True,
                    help="Natural-language task description")
    ap.add_argument("--limit", type=int, default=10,
                    help="Max files to list (default 10)")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s v{SCRIPT_VERSION}")
    args = ap.parse_args()

    if not VAULT.is_dir():
        print(f"CONTEXT_FAILED: vault not found at {VAULT}", file=sys.stderr)
        return 2

    task = args.task.strip()
    kind = classify(task)
    keywords = extract_keywords(task)

    print(f"=== VAULT CONTEXT: {kind} ===")
    print(f"Task    : {task}")
    print(f"Keywords: {', '.join(keywords) if keywords else '(none extracted)'}")
    print()

    hits = rank_files(keywords, limit=args.limit)
    if hits:
        print("Relevant files (score / path / tags / updated):")
        for score, f, fm in hits:
            rel = f.relative_to(VAULT)
            tags = ",".join((fm.get("tags") or [])[:4])
            updated = pick_updated_date(fm)
            rc = fm.get("rule_count", "")
            rc_str = f"r{rc}" if rc else "—"
            print(f"  [{score:2d}] {rel}  ({rc_str}) [{tags}] {updated}")
    else:
        print("Relevant files: (no keyword hits — consider search.py --list-tags)")

    print()
    print("Hints for this task kind:")
    for h in render_kind_hints(kind):
        print(f"  - {h}")

    print()
    print("Always applicable:")
    print("  - Vault root:", VAULT)
    print("  - At entry: bash $SKILL/scripts/orient.sh")
    print("  - At exit : bash $SKILL/scripts/handoff.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
