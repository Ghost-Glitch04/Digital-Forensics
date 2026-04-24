# Lessons Learned V3.5 — Installation Guide

## What's in this package

```
lessons-learned_V3_5/
├── INSTALL.md                                        # This file
├── SKILL.md                                          # V3.5 SKILL.md (replaces V3.4)
├── reference/
│   ├── invariants.md                                 # NEW — retrieval invariants
│   ├── drift_intake.md                               # NEW — drift intake protocol
│   ├── evidence.md                                   # NEW — anchor discipline + evidence block
│   ├── meta_classification.md                        # NEW — meta-note sub-types + Step 6
│   └── lookup.md                                     # NEW — lookup protocol details
├── meta/
│   └── skill_dev_log.md                              # NEW — skill evolution log
└── integration_notes/
    ├── templates_section_phase_file_variants_to_append.md    # APPEND to templates.md
    ├── verify_additions_to_merge.md                          # MERGE into verify.md
    ├── phase4a_skill_audit_report.md                         # Development artifact (optional)
    └── phase4c_validation_report.md                          # Development artifact (optional)
```

## Target directory structure in your project

When installed, your `lessons-learned` skill directory will look like:

```
.claude/skills/lessons-learned_V3_5/
├── SKILL.md
└── reference/
    ├── bootstrap.md            # UNCHANGED from V3.4
    ├── retroactive.md          # UNCHANGED from V3.4
    ├── templates.md            # V3.4 content + new §"Phase File Variants" section appended
    ├── verify.md               # V3.4 Checks 1-13 + new Checks 14, 15, 16 appended
    ├── invariants.md           # NEW in V3.5
    ├── drift_intake.md         # NEW in V3.5
    ├── evidence.md             # NEW in V3.5
    ├── meta_classification.md  # NEW in V3.5
    └── lookup.md               # NEW in V3.5
```

Plus, in each project that uses the skill:

```
lessons_learned/
├── meta/
│   └── skill_dev_log.md        # NEW in V3.5 (bootstrapped with this package)
├── INDEX.md
├── phase*.md
└── ai/
    ├── _overview.md
    └── *.md
```

## Installation steps

### Step 1 — Back up your current V3.4 skill

Before installing anything, make a backup of your current skill
directory:

```bash
cp -r .claude/skills/lessons-learned_V3_4 .claude/skills/lessons-learned_V3_4.backup
```

### Step 2 — Create V3.5 skill directory

```bash
mkdir -p .claude/skills/lessons-learned_V3_5/reference
```

### Step 3 — Copy unchanged V3.4 reference files

These three files are unchanged in V3.5 and should be carried forward:

```bash
cp .claude/skills/lessons-learned_V3_4/reference/bootstrap.md \
   .claude/skills/lessons-learned_V3_5/reference/
cp .claude/skills/lessons-learned_V3_4/reference/retroactive.md \
   .claude/skills/lessons-learned_V3_5/reference/
```

### Step 4 — Install new SKILL.md and reference files

```bash
# Unzip this package, then:
cd lessons-learned_V3_5

cp SKILL.md .claude/skills/lessons-learned_V3_5/
cp reference/invariants.md         .claude/skills/lessons-learned_V3_5/reference/
cp reference/drift_intake.md       .claude/skills/lessons-learned_V3_5/reference/
cp reference/evidence.md           .claude/skills/lessons-learned_V3_5/reference/
cp reference/meta_classification.md .claude/skills/lessons-learned_V3_5/reference/
cp reference/lookup.md             .claude/skills/lessons-learned_V3_5/reference/
```

### Step 5 — Merge templates.md additions

The existing V3.4 `templates.md` stays as-is. The new "Phase File
Variants" section appends to the end of it:

```bash
# Copy the V3.4 templates.md
cp .claude/skills/lessons-learned_V3_4/reference/templates.md \
   .claude/skills/lessons-learned_V3_5/reference/templates.md

# Append the new section
cat integration_notes/templates_section_phase_file_variants_to_append.md \
   >> .claude/skills/lessons-learned_V3_5/reference/templates.md
```

Verify the section landed correctly:
```bash
grep -c "^# Phase File Variants" \
   .claude/skills/lessons-learned_V3_5/reference/templates.md
# Should output: 1
```

### Step 6 — Merge verify.md additions

The existing V3.4 `verify.md` Checks 1-13 stay as-is. New Checks 14,
15, 16 append after Check 13. The Quick Pass section at the bottom
gets updated.

This is the most involved merge. Follow the instructions in
`integration_notes/verify_additions_to_merge.md`:

1. Start with V3.4 `verify.md`
2. Locate the existing `## Quick Pass (abbreviated check)` section
   near the bottom
3. BEFORE that section, paste the three new check sections (Check 14,
   Check 15, Check 16) from `verify_additions_to_merge.md`
4. REPLACE the existing Quick Pass section with the updated version
   from `verify_additions_to_merge.md`

```bash
# Starting point
cp .claude/skills/lessons-learned_V3_4/reference/verify.md \
   .claude/skills/lessons-learned_V3_5/reference/verify.md

# Then manually merge per the steps above.
# The updated file should end with the updated Quick Pass section.
```

Verify the merge:
```bash
grep -c "^## Check 1[4-6]:" \
   .claude/skills/lessons-learned_V3_5/reference/verify.md
# Should output: 3
```

### Step 7 — Install skill_dev_log.md in each project

For each project that uses the lessons-learned skill, create the
meta directory and install the skill_dev_log:

```bash
cd /path/to/project
mkdir -p lessons_learned/meta
cp /path/to/lessons-learned_V3_5/meta/skill_dev_log.md \
   lessons_learned/meta/
```

Note: The skill_dev_log comes pre-populated with V3.3→V3.4 retroactive,
V3.4→V3.5, and 12 seed entries documenting the V3.5 design journey.
These form the starting institutional knowledge for the log.

### Step 8 — Verify installation

Run the authored-skill self-check (Check 12 equivalent):

```bash
# 1. All reference pointers resolve
grep -oE "reference/[a-z_]+\.md" \
   .claude/skills/lessons-learned_V3_5/SKILL.md | sort -u | while read ref; do
  if [ -f ".claude/skills/lessons-learned_V3_5/$ref" ]; then
    echo "OK: $ref"
  else
    echo "MISSING: $ref"
  fi
done

# 2. No duplicate reference files
md5sum .claude/skills/lessons-learned_V3_5/SKILL.md \
       .claude/skills/lessons-learned_V3_5/reference/*.md | sort
# All hashes should be distinct.

# 3. Expected file count
ls .claude/skills/lessons-learned_V3_5/reference/ | wc -l
# Should output: 9 (bootstrap, retroactive, templates, verify, invariants,
#                   drift_intake, evidence, meta_classification, lookup)
```

### Step 9 — Retire V3.4 (optional)

Once V3.5 is confirmed working:

```bash
# Either archive V3.4:
mv .claude/skills/lessons-learned_V3_4 \
   .claude/skills/archive/lessons-learned_V3_4

# Or if you're confident in V3.5 and don't want the backup:
rm -rf .claude/skills/lessons-learned_V3_4
```

Skip this step until V3.5 has passed Phase 7 trial successfully.

## First-use considerations

### Existing phase files without `**Format:**` declarations

V3.5 uses retroactive tolerance — phase files without a `**Format:**`
declaration are implicitly treated as `canonical` if their structure
matches canonical. If it doesn't, Check 16 flags them.

Optional one-time retrofit pass for your existing phase files:

```bash
# For each existing phase file, add the appropriate Format declaration
# to its header. Most will be `canonical`; meta-reflections and
# case-studies need their specific variants.
#
# Example edit to phase77_cf76_1_e2e_fixes.md:
#
# Before:
#   # Phase 77 — CF-76-1: E2E Test Fixes
#   **Scope:** Resolve 4 pre-existing Playwright E2E failures...
#
# After:
#   # Phase 77 — CF-76-1: E2E Test Fixes
#   **Scope:** Resolve 4 pre-existing Playwright E2E failures...
#   **Format:** canonical
```

This is optional — V3.5 won't fail on old files. But adding the
declaration makes Check 16 strict rather than tolerant, which catches
format drift earlier.

### Existing wishlist entries without sub-types

V3.5 Check 15 is warn-only on pre-V3.5 phase files (those without
`**Format:**` declarations). Existing `type: meta` entries remain
valid. When you encounter them during a future reflection, you can
retroactively classify them as `meta-fix` / `meta-question` /
`meta-wish` — but you don't have to.

### First reflection under V3.5

The first reflection authored under V3.5 is the first real test of
the skill. Specifically, these features will be exercised:

- Evidence block execution during GATHER (Step 1)
- `**Format:**` declaration in the phase header (Step 2)
- Completeness check after drafting (Step 2)
- Meta-note sub-type classification on wishlist entries (Step 2)
- Synchronous Step 6 if any `meta-fix` items surfaced
- Check 14, 15, 16 in VERIFY

Treat the first reflection as a trial run. If anything feels wrong or
unclear, note it and propose an adjustment for V3.5.1 or V3.6. The
skill_dev_log is the natural place to record those observations as
`meta-observation` entries.

## Phase 7 trial — what to expect

Per the V3.5 plan, Phase 7 is your empirical validation. Run V3.5 on
real work in the CTF training project and measure:

- **Anchor consistency rate (Check 14):** % of Bugs/DD entries with
  `**Lesson:**` anchor + citation pattern. Target: ≥90%.
- **Meta-fix action rate (Step 6):** % of `meta-fix` proposals
  approved. Target: ≥70%.
- **Meta-fix revert rate:** % of applied Step 6 edits later reverted.
  Target: <20%.
- **Variant conformance:** % of new phase files declaring a documented
  variant OR routing to drift intake. Target: 100%.

Update the V3.5 entry in `skill_dev_log.md` with trial results when
you have them. Add new `meta-observation` entries for anything the
trial surfaces that's worth capturing for future skill evolution.

## Support files included

The `integration_notes/` directory contains development artifacts:

- `phase4a_skill_audit_report.md` — The audit that guided V3.5's
  SKILL.md integration. Useful if you want to understand why specific
  content moved or stayed during V3.4→V3.5.
- `phase4c_validation_report.md` — The cross-reference validation
  performed before V3.5 shipping. Lists every pointer that was
  verified to resolve.

These are optional reading. The production skill (SKILL.md +
reference/*.md + meta/skill_dev_log.md) doesn't depend on them.

## Questions or issues

If anything about V3.5 seems unclear or inconsistent during
installation or first use, that itself is data. Capture it as a
`meta-observation` entry in the skill_dev_log and treat it as input
for V3.5.1 or V3.6.

The skill teaches institutional knowledge capture. Its own
installation experience is institutional knowledge worth capturing.
