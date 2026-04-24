# scripting-standards — V5.3

Ghost's personal scripting-standards skill, governing how PowerShell, Bash, and Python scripts are authored with emphasis on prove-first development, structured logging, integration tracking, and mechanically-enforced format discipline.

> **Note:** This top-level README was reconstructed during the V5.3 delivery because the V5.2 bundle's canonical version was not recoverable from the working session. Compare against your V5.2 bundle's top-level README before replacing. The file-tree description and installation instructions are V5.3-accurate; the surrounding framing is synthesized.

---

## What's in this bundle

```
scripting-standards-v5.3/
├── README.md                                          ← this file (synthesized)
├── SKILL.md                                           ← top-level skill entry
├── reference/
│   ├── bash.md
│   ├── grep_first.md                                  (V5.2)
│   ├── integration-tracking.md                        (V5.0, V5.0.1)
│   ├── log_vocabulary.md
│   ├── minimal_scripts.md
│   ├── powershell.md
│   ├── prove_first.md
│   ├── python.md
│   ├── testing.md
│   ├── troubleshooting.md
│   └── integration-helpers/
│       ├── verify-integrations.ps1                    (V5.0, static-reviewed)
│       └── verify-integrations.sh                     (V5.0, verified)
└── skill_development/
    ├── authoring-helpers/                             ← NEW in V5.3
    │   ├── README.md
    │   ├── pre-commit                                   git hook wrapper
    │   ├── verify-l2.sh                                 L2 enforcement harness
    │   └── test-verify-l2.sh                            regression suite
    ├── developer_log/
    │   ├── README.md                                  (reconstructed — verify)
    │   └── log.md                                     (V5.3 section appended)
    └── lessons_learned/
        ├── README.md
        └── lessons.md
```

## What changed at V5.3

**Headline:** Automated L2 enforcement. A pre-commit hook now mechanically verifies that the canonical patterns documented in `reference/grep_first.md` (G1–G9) and `reference/integration-tracking.md` (I1–I6) still match their worked templates on every commit — closing the CRLF-drift failure mode captured in `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>`.

**Footprint:**
- 4 new files in `skill_development/authoring-helpers/`
- 1 modified paragraph in SKILL.md (mechanical-enforcement cross-reference at end of "How This Skill Evolves")
- 1 new section in `skill_development/developer_log/log.md` (V5.3 — Automated L2 Enforcement, 13 entries)
- 1 new section in `skill_development/developer_log/README.md` Decision Index (V5.3 — Automated L2 Enforcement, 13 bullets)
- 0 reference file changes (V5.2 IT-untouched lock preserved; cross-references from V5.3 to reference files are one-directional)

**Deferred to V5.4+:**
- Candidates A, B, C from V5.3 Phase 1 Q1 (pre-rename enumerator; case-study capture workflow; map-side drift detection)
- V5.0 PowerShell helper runtime verification (residual from `<devlog:2026-04-22:powershell-helper-ships-unverified>`)
- Registry externalization (when `L2_CHECKS` exceeds ~20 rows)

See `skill_development/developer_log/log.md § V5.3 — Automated L2 Enforcement` for the full decision trail.

## Installation

### As a Claude skill

Place the bundle directory in the appropriate skills location. The skill self-activates when the conversation context triggers `SKILL.md`'s frontmatter description (PowerShell, Bash, or Python scripting work).

### For authoring the skill itself (V5.3 pre-commit hook)

When making edits to this skill's files, install the pre-commit hook so L2 format drift gets caught at commit time:

```bash
cd scripting-standards-v5.3/
git config core.hooksPath skill_development/authoring-helpers/
```

Verify installation:

```bash
# Run the harness directly
./skill_development/authoring-helpers/verify-l2.sh
# Expected: "L2 verification: 21/21 checks passed"

# Run the regression suite
./skill_development/authoring-helpers/test-verify-l2.sh
# Expected: "RESULTS: 19 PASS  |  0 FAIL"
```

See `skill_development/authoring-helpers/README.md` for the L2-covered invariant set, governance rules, and regression testing documentation.

## Versioning

Per `SKILL.md § How This Skill Evolves`, version numbers are tagged in commit messages or session notes, not embedded in file content. Major bumps mark structural reorganizations or new reference files; minor bumps mark content additions.

V5.3 is a **minor bump** from V5.2 — adds `skill_development/authoring-helpers/` subdirectory but no new `reference/` files and no runtime-behavior changes to user-authored scripts. Matches the V5.1 precedent for `skill_development/` tree additions.

## Relationship to Ghost's general `lessons-learned` skill

This skill's `skill_development/lessons_learned/` folder is scoped strictly to the development of **this** skill. Project-level lessons from work that *uses* this skill belong in Ghost's general `lessons-learned` skill. Cross-references are one-directional: this folder may point outward; the general skill does not point inward.
