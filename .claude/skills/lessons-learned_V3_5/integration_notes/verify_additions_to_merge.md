# V3.5 verify.md Additions — Checks 14, 15, 16

## Integration instructions

These three new checks append to `reference/verify.md` after Check 13,
before the Quick Pass section. The Quick Pass section at the bottom
also needs updating — the replacement text is at the end of this
document.

All three checks are **authored-skill self-checks** when they concern
the skill itself, and **per-reflection checks** when they concern
phase file content. The distinction is documented in each check's
preamble.

---

## Check 14: Anchor consistency (per-reflection + authored-skill)

**New in V3.5.** Validates INV-PHASE-02 — every actionable phase-file
entry has a `**Lesson:**` anchor line containing at least one citation
pattern. This check has two modes.

### Mode A: Per-reflection — current phase file

Run after drafting the phase file, before INDEX update (corresponds to
SKILL.md §3a Step 2 sub-step 20 completeness check, but Check 14 runs
on the authored entries themselves).

```bash
# Extract all Bugs / Pitfalls / Design Decisions entries from the current
# phase file. Adapt section names as needed for the phase file's variant.
PHASE={current_phase_file}

# Find all ### N. or ### N.N entry headings inside these sections
awk '
  /^## (Bugs and Pitfalls|Bugs|Pitfalls|Design Decisions|Decisions|What Went Badly)/ { in_section=1; next }
  /^## / { in_section=0 }
  in_section && /^### [0-9]+(\. |\.[0-9]+ )/ {
    print NR ": " $0
  }
' lessons_learned/${PHASE}

# For each entry number N in the above output, verify a **Lesson:** line
# appears within the next 30 lines:
awk '
  /^## (Bugs and Pitfalls|Bugs|Pitfalls|Design Decisions|Decisions|What Went Badly)/ { in_section=1; next }
  /^## / { in_section=0 }
  in_section && /^### [0-9]+(\. |\.[0-9]+ )/ {
    entry_line = NR
    entry_title = $0
    found_lesson = 0
    for (i = 1; i <= 30 && (getline line) > 0; i++) {
      if (line ~ /^\*\*Lesson:\*\*/) {
        found_lesson = 1
        lesson_line = line
        break
      }
      if (line ~ /^### [0-9]+(\. |\.[0-9]+ )/) break
    }
    if (!found_lesson) {
      print "MISSING ANCHOR: line " entry_line ": " entry_title
    } else {
      # Check for at least one citation pattern in the Lesson line
      if (lesson_line !~ /[a-f0-9]{7,40}|\.(py|ps1|sh|js|ts|go|rs|yaml|yml|md):[0-9]+|[0-9]+ (files|lines|times|errors|rows|tests|entries|seconds|ms|s)\b|_[a-zA-Z]+\(\)|[a-z_]+\(\)|--[a-z-]+|test_[a-zA-Z_]+/) {
        print "WEAK ANCHOR (no citation): line " entry_line ": " entry_title
        print "    Lesson: " lesson_line
      }
    }
  }
' lessons_learned/${PHASE}
```

### Mode B: Authored-skill — cross-phase sweep

Run when editing the skill, or during a skill-development reflection,
to audit anchor discipline across the whole phase file collection.

```bash
# Run Mode A across every phase file; aggregate failures
for f in lessons_learned/phase*.md; do
  [ "$(basename "$f" .md)" = "INDEX" ] && continue
  echo "=== $(basename "$f") ==="
  # (same awk logic as Mode A applied to $f)
done
```

### Citation patterns recognized

The check looks for at least one of these in each Lesson line:

| Pattern | Regex fragment |
|---|---|
| Commit SHA (7-40 hex chars) | `[a-f0-9]{7,40}` |
| File and line | `\.(py\|ps1\|sh\|js\|ts\|go\|rs\|yaml\|yml\|md):[0-9]+` |
| Function name | `_?[a-z_]+\(\)` |
| Specific count | `[0-9]+ (files\|lines\|times\|errors\|rows\|tests\|entries\|seconds\|ms\|s)` |
| Command flag | `--[a-z-]+` |
| Test name | `test_[a-zA-Z_]+` |

The regex is deliberately permissive — true citation detection
requires human judgment; this catches bright-line omissions (Lesson
lines with no specific content).

### Failure modes

- **MISSING ANCHOR:** Entry in Bugs/DD section has no `**Lesson:**`
  line. Add one per `reference/evidence.md` §"The Lesson Anchor".
- **WEAK ANCHOR (no citation):** Entry has a Lesson line but contains
  none of the recognized citation patterns. Possible resolutions:
  (1) rewrite to include specific citation if one exists;
  (2) accept if the entry is a genuine process insight (uncommon in
  Bugs/DD, more common in What Went Well or What Would Help Me Grow);
  (3) reclassify the entry out of Bugs/DD into What Went Well.

### Scope exceptions

Check 14 applies to entries inside `## Bugs`/`## Bugs and Pitfalls`/
`## Pitfalls`/`## Design Decisions`/`## Decisions`/`## What Went Badly`
sections (canonical and common synonyms). It does NOT apply to:

- Purely narrative sections (Overview, Summary Judgment, Scope)
- Case-study variant's descriptive H2 sections
- Meta-reflection's What Went Well / What Went Poorly synthesis
  (anchors are useful but not required)
- Non-numbered prose paragraphs

The invariant INV-PHASE-02 is scoped to actionable entries — entries
that will be indexed as rule/bug/pattern/insight. Non-indexed content
is exempt.

---

## Check 15: Meta-note sub-type coverage (per-reflection + authored-skill)

**New in V3.5.** Validates that every `type: meta` wishlist entry in a
V3.5-authored phase file declares a sub-type classification: `meta-fix`,
`meta-question`, or `meta-wish`.

### Mode A: Per-reflection — current phase file

```bash
PHASE={current_phase_file}

# Find the "What Would Help Me Grow" / "Tooling Wishlist" section and
# extract all entries within it
awk '
  /^## (What Would Help Me Grow|Tooling Wishlist|What I Would Like to Improve)/ { in_section=1; next }
  /^## / { in_section=0 }
  in_section && /^### / {
    entry_line = NR
    entry_title = $0
    entry_has_subtype = 0
    # Check title for inline sub-type tag: `meta-fix` | `meta-question` | `meta-wish`
    if ($0 ~ /`(meta-fix|meta-question|meta-wish)`/) {
      entry_has_subtype = 1
    } else {
      # Check next 10 lines for **Sub-type:** declaration
      for (i = 1; i <= 10 && (getline line) > 0; i++) {
        if (line ~ /^\*\*Sub-type:\*\* `(meta-fix|meta-question|meta-wish)`/) {
          entry_has_subtype = 1
          break
        }
        if (line ~ /^### /) break
      }
    }
    if (!entry_has_subtype) {
      print "MISSING SUB-TYPE: line " entry_line ": " entry_title
    }
  }
' lessons_learned/${PHASE}
```

### Mode B: Authored-skill — grandfathering legacy entries

V3.4 phase files with bare `type: meta` tags are grandfathered. The
check distinguishes "pre-V3.5 authored" (tolerant) from "V3.5-authored
but missing sub-type" (fail).

The signal for V3.5 authorship is the presence of a `**Format:**`
declaration in the phase file header (INV-PHASE-08):

```bash
# V3.5-authored phase files have a Format declaration
if grep -q "^\*\*Format:\*\*" lessons_learned/${PHASE}; then
  echo "V3.5-authored — running Check 15 strictly"
  # (run Mode A)
else
  echo "Pre-V3.5 authored — Check 15 runs in warn-only mode"
  # (run Mode A but report as warnings, not failures)
fi
```

### Failure modes

- **MISSING SUB-TYPE (V3.5 file):** Wishlist entry without sub-type
  declaration. Add `meta-fix`, `meta-question`, or `meta-wish`
  classification per `reference/meta_classification.md` §"Three
  Sub-Types".
- **MALFORMED SUB-TYPE:** Sub-type declaration exists but value is
  not one of the three documented values. Typical cause: typo
  (`meta-fixed`, `meta-wishlist`, etc.). Correct to the canonical
  value.
- **MULTIPLE SUB-TYPES on one entry:** See
  `reference/meta_classification.md` §"Multiple sub-types on one
  entry" — split the entry into two wishlist items each with its own
  sub-type.

### Scope

Check 15 applies only to entries inside the "What Would Help Me Grow"
or "Tooling Wishlist" or "What I Would Like to Improve" sections. It
does NOT apply to:

- Carry-Forward items (those use CF-N IDs, not meta sub-types)
- Bugs or Design Decisions entries
- Phase files without a wishlist section (zero-check, pass)
- Pre-V3.5 phase files without `**Format:**` declaration (warn-only)

### Related checks

- If a wishlist entry classified `meta-fix` has no `**Step 6 outcome:**`
  line, it means Step 6 wasn't run or was skipped. Track but don't fail
  — the entry may legitimately be carried forward.
- If an entry has `**Step 6 outcome:** APPLIED` but also a later
  `RESOLVED` note, ensure they agree (the Step 6 outcome is the
  resolution).

---

## Check 16: Variant conformance + drift intake routing (per-reflection + authored-skill)

**New in V3.5.** Validates that every phase file's structure matches
its declared `**Format:**` variant, and routes undocumented variants
to the Drift Intake Protocol.

### Check routing logic

From `reference/drift_intake.md` §"Check 16 Routing Logic":

```
Read the **Format:** declaration (or infer canonical if absent).

Case 1: Declaration matches a variant documented in templates.md
    → Load that variant's schema
    → Validate the file against the schema
    → Validate all applicable retrieval invariants
    → PASS or FAIL based on schema conformance

Case 2: Declaration does not match any documented variant
    → Check if any other phase file declares the same variant name
      (i.e., is this a recurring undocumented variant?)
    → If no other file declares it:
          → WARN: "Undocumented variant '{name}' declared in {file}."
          → Continue by validating retrieval invariants regardless
    → If 1+ other files declare it:
          → FLAG as variant candidate (recurrence threshold met)
          → Route to Drift Intake Protocol for canonization proposal

Case 3: Declaration is absent AND file structure doesn't match canonical
    → FLAG: "Missing **Format:** declaration and file structure does
      not match canonical."
    → Validate retrieval invariants regardless
```

### Mode A: Per-reflection — current phase file

```bash
PHASE={current_phase_file}

# Extract the Format declaration (if any)
FORMAT=$(grep -m1 "^\*\*Format:\*\*" lessons_learned/${PHASE} \
  | sed 's/\*\*Format:\*\* *//')

if [ -z "$FORMAT" ]; then
  # Case 3: missing declaration
  echo "NO FORMAT DECLARATION: checking if file structure matches canonical..."
  # Run canonical schema validation (see schema below)
  FORMAT="canonical_inferred"
fi

case "$FORMAT" in
  canonical)
    # Validate canonical schema:
    # - Required-when-present sections conform to their formats
    # - INV-PHASE-01..09 all applicable
    echo "Validating as canonical variant..."
    ;;
  meta-reflection)
    # Validate meta-reflection schema:
    # - INV-PHASE-01, 02, 08, 09 required; 03/06/07 exempt
    # - Wishlist entries validated per Check 15 if present
    echo "Validating as meta-reflection variant..."
    ;;
  case-study)
    # Validate case-study schema:
    # - INV-PHASE-08 required; 01/02 conditional; 03/06/07 exempt
    echo "Validating as case-study variant..."
    ;;
  canonical_inferred)
    # Retroactive tolerance — warn only
    echo "WARN: File has no Format declaration. Treating as canonical."
    echo "Add **Format:** canonical to header for V3.5 compliance."
    ;;
  *)
    # Undocumented variant — route to drift intake
    # Check for recurrence
    RECURRENCE=$(grep -l "^\*\*Format:\*\* *${FORMAT}" lessons_learned/phase*.md | wc -l)
    if [ "$RECURRENCE" -ge 2 ]; then
      echo "VARIANT CANDIDATE: '${FORMAT}' now appears in ${RECURRENCE} files."
      echo "Route to Drift Intake Protocol for canonization proposal."
      echo "See reference/drift_intake.md §'Four-Step Promotion Path'."
    else
      echo "WARN: Undocumented variant '${FORMAT}' — observed drift."
      echo "Continuing with invariant validation only."
    fi
    ;;
esac
```

### Mode B: Authored-skill — cross-file variant survey

Run periodically to see the distribution of variants across the repo
and detect any undocumented variants that have reached the recurrence
threshold.

```bash
# Tally declared variants
for f in lessons_learned/phase*.md; do
  [ "$(basename "$f" .md)" = "INDEX" ] && continue
  format=$(grep -m1 "^\*\*Format:\*\*" "$f" | sed 's/\*\*Format:\*\* *//')
  if [ -z "$format" ]; then
    format="[no declaration]"
  fi
  echo "$format    $(basename "$f")"
done | sort | awk '
  { counts[$1]++; files[$1] = files[$1] " " $2 }
  END {
    for (variant in counts) {
      printf "%-25s %d file(s):%s\n", variant, counts[variant], files[variant]
    }
  }
'
```

### Canonical schema requirements

When Check 16 validates as `canonical`, these schema requirements apply:

| Required | Validation |
|---|---|
| If `## Applied Lessons` present | Three-column table per INV-PHASE-03 |
| If `## Missed` or `## Missed Lessons` present | Three-column table per INV-PHASE-06 |
| If Bugs/DD sections present | Numbered entries per INV-PHASE-01 with Lesson anchors per INV-PHASE-02 (Check 14 Mode A) |
| If `## Carry-Forward Items` present | CF-N IDs per INV-PHASE-07 |
| `**Format:**` declaration | INV-PHASE-08 |

**Absent-section tolerance:** canonical files may omit any optional
section (no Bugs section if no bugs occurred, no CF if no debt opened).
Absence is not a failure.

### Meta-reflection schema requirements

| Required | Validation |
|---|---|
| `**Format:**` declaration | INV-PHASE-08 |
| If numbered entries present | INV-PHASE-01/02 apply |
| `## What Went Well` + `## What Went Poorly` + wishlist section | typical but not strictly required |

**Explicit exemptions:** INV-PHASE-03 (Applied Lessons table),
INV-PHASE-06 (Missed table), INV-PHASE-07 (CF Items) do NOT apply.
Meta-reflections synthesize from constituent phases; they don't
re-run the per-phase feedback loop.

**Hybrid tolerance:** A meta-reflection that records new cross-phase
lessons worth indexing may include Applied Lessons / numbered entries.
When present, those conform to canonical schemas. Absence is expected,
presence is valid.

### Case-study schema requirements

| Required | Validation |
|---|---|
| `**Format:**` declaration | INV-PHASE-08 |
| If numbered entries present (conditional) | INV-PHASE-01/02 apply only to entries that will be indexed |

**Explicit exemptions:** Most section name requirements don't apply.
Case studies use descriptive H2 headings that teach specific lessons;
section names vary by content.

### Failure modes

- **Schema mismatch:** File declares variant X but structure doesn't
  match X's schema. Two resolutions:
  (1) Update the declaration to match actual structure.
  (2) Add or remove sections to match declared variant.
- **Unknown variant with single instance:** Warn only. One-off drift
  is not yet a variant candidate.
- **Unknown variant with 2+ instances:** Trigger the Drift Intake
  Protocol. Next skill-development reflection proposes canonization.
- **Missing declaration with non-canonical structure:** Add
  `**Format:**` declaration explicitly; don't leave inference to do
  the wrong thing.

### Interaction with Check 13

Check 13 (format drift) is authoritative on retrieval invariants.
Check 16 (variant conformance) routes variant classification. A file
can fail Check 13 (violating an invariant) even while passing Check 16
(declared variant is documented). The two checks are complementary,
not redundant.

Where Check 13 and Check 16 both could fire on the same issue
(e.g., a file's Applied Lessons table has wrong columns), Check 13
takes precedence — the invariant violation is the actionable failure,
and the variant declaration is secondary.

---

## Updated Quick Pass (abbreviated check)

Replace the existing Quick Pass section at the bottom of verify.md
with this updated version:

```markdown
## Quick Pass (abbreviated check)

When time is limited, run Checks 1, 4, 8, and 14 — they catch the
most common issues (missing INDEX rows, stale _overview counts, stale
_overview keywords that degrade lookup accuracy, and missing Lesson
anchors that degrade grep retrieval quality).

When editing the skill itself, also run Checks 12, 13, and 16. These
are the prove-first discipline from `scripting-standards_V4_6` applied
to this skill: every format the skill documents must be grep-checkable
against real usage before the skill ships.

Check 15 (meta-note sub-type coverage) runs at reflection time for
any phase file with a wishlist section — a quick pass if wishlist is
present, a no-op if absent.

Check 16 (variant conformance) runs on every full reflection — the
Format declaration lookup is cheap (~1 grep), and the variant-specific
schema validation is the same cost as the invariant checks it replaces
in the declared variant's schema.

### Check cost summary

| Check | Runs when | Cost |
|---|---|---|
| 1, 2, 3, 4, 5, 6, 6b, 7, 8, 9, 10 | Per-reflection (Step 5 VERIFY) | ~10-20s |
| 11 | During authorship (each AI rule) | ~5s per rule |
| 12, 13 | Authored-skill self-check | ~15s per skill edit |
| 14 | Per-reflection + authored-skill | ~5s Mode A, ~30s Mode B |
| 15 | Per-reflection (if wishlist present) | ~3s |
| 16 | Per-reflection | ~3s (plus variant schema validation) |
```

---

## Meta-observations surfaced during Phase 5 drafting

Two observations queued for the V3.4→V3.5 skill_dev_log entry:

### Observation 1: Check numbering has its own drift risk

V3.4 added Checks 12 and 13 as the last two entries. V3.5 adds 14, 15,
16 at the end. This "append-only" numbering scheme works while check
counts are small, but over versions it creates an odd artifact — check
numbers reflect historical order of addition, not logical grouping.
Check 11 (isolation-read) is more closely related to Check 14 (anchor
consistency) than to Check 10 (supersession). A reader encountering
Check 11 followed by Check 12 (reference pointer resolution) sees
unrelated adjacency.

**Candidate resolution for a future version:** group checks by scope
(per-reflection vs. authored-skill), use section-level hierarchy
instead of flat numbering, or accept that check numbers are stable
grep anchors (like invariant IDs) and stop caring about logical
ordering.

**For V3.5:** append-only numbering retained for backward
compatibility. Track in skill_dev_log; decide in a future reflection.

### Observation 2: Mode A / Mode B pattern emerged naturally

All three new checks (14, 15, 16) naturally split into per-reflection
and authored-skill modes. V3.4's check set didn't use this pattern
explicitly — most checks are per-reflection by default, and the skill-
authorship checks (12, 13) are called out in preambles. V3.5's three
new checks each have enough complexity that the mode split is load-
bearing.

**Candidate resolution for a future version:** retrofit Checks 1-11
to declare their mode explicitly in a consistent "Mode A / Mode B"
format, or accept that the mode distinction is implicit when the
check's content makes it obvious.

**For V3.5:** mode split used in new checks only. Legacy checks
keep their current preamble-based mode declaration.
