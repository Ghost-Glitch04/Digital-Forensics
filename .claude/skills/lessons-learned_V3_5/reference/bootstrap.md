# Bootstrap — Initialize Lessons Learned on a New Project

Use this workflow when adding the lessons-learned system to a project for
the first time. If the project already has significant history, also read
`retroactive.md` to capture accumulated knowledge from before the system
existed.

---

## When to Bootstrap

- You're starting a new project and want knowledge capture from day one.
- You're on an existing project where `lessons_learned/` doesn't exist yet
  and the team is ready to start recording.
- A CLAUDE.md or equivalent project-instructions file exists and would
  benefit from being fed by a structured knowledge system.

---

## Step 1 — Create the Directory Layout

```bash
mkdir -p lessons_learned/ai
```

That's the full layout. Two directories:

```
lessons_learned/
├── INDEX.md                          # Grep-optimized discovery router
├── phase{N}_{short_name}.md          # Phase files — narrative source of truth
└── ai/
    ├── _overview.md                  # AI file routing table
    └── {topic}.md                    # Structured-recall rule files (one per topic)
```

Optionally, `lessons_learned/export.md` gets created at project completion
for portable Foundation-tier lessons (see SKILL.md §7).

---

## Step 2 — Choose a Phase Naming Convention

Phase files are the narrative source of truth. Each file represents one
coherent unit of work. The file naming convention sets the pattern all
future files will follow — pick it once and keep it.

### Observed conventions in mature projects

| Pattern | Use case | Example |
|---------|----------|---------|
| `phase{N}_{short_name}.md` | Standard phases, numeric sequence | `phase5_terminal_notes.md` |
| `phase{N}{letter}_{short_name}.md` | Sub-phases within a major phase | `phase3a_canvas_shell.md`, `phase3b_interaction.md` |
| `phase{N}_{short_name}.md` (parallel) | Two phases with the same number where one is a retro, extension, or second-round | `phase7_sbom_debugging.md`, `phase7_soft_delete.md` |
| `skill_authorship_{skill_name}_{version}.md` | Reflection on authoring or revising a skill itself (meta-lessons) | `skill_authorship_scripting_standards_V4_6.md` |

### Naming rules

- **Lowercase, underscores, no dashes.** `phase5_terminal_notes` not `Phase5-Terminal-Notes`.
- **Short name is 2–4 words.** The title of the phase, not a sentence.
- **`phase{N}` prefix is mandatory** for work-unit phases. The prefix is the
  sort key — files in the filesystem and INDEX rows are often listed in
  phase order. A file named `websocket_lessons.md` will sort alphabetically,
  disconnected from timeline.
- **Skill-authorship reflections use `skill_authorship_` prefix** instead of
  `phase{N}_`. They form a parallel thread that is not part of the main
  phase sequence but still uses the same entry format.

### Phase numbering conventions

- Start at `phase0_setup.md` for initial bootstrap. Phase 0 captures the
  decisions made while setting up the project itself.
- Sub-phase letters (`phase3a`, `phase3b`) when one major work unit has
  multiple coherent sub-deliverables. Don't use sub-letters prematurely.
- When a phase is extended or a parallel thread opens with the same number,
  a second file with a different short_name is fine: `phase7_sbom_debugging.md`
  and `phase7_soft_delete.md` are both valid.

---

## Step 3 — Seed INDEX.md

Create `lessons_learned/INDEX.md` with this skeleton:

```markdown
# Lessons Learned — Topic Index

> **Usage:** Grep this file by keyword to find relevant lessons from past phases.
> Each row points to a specific section in a source file.
> Read the pointed-to section with: `Read(file_path="lessons_learned/{source_file}.md", offset=LINE, limit=40)`
>
> **For subject-based recall:** Read `ai/<topic>.md` for self-contained When/Rule/Code
> format rules. These are the primary recall mechanism — this INDEX is the discovery layer.
>
> **Maintenance:** When appending new lessons, add `<!-- tags: -->` to source headings
> and append entries to the Active tier. At phase transitions, graduate old entries to
> Foundation or Reference.

## Tag Vocabulary

(Start empty. Add lowercase, comma-separated tags as rules are captured.
Primary tags go first in each rule row.)

## AI Subject Files — Quick Reference

| File | Rules | Primary recall for |
|------|-------|--------------------|
| (populate as files are created — one row per ai/{topic}.md file) |

---

## Active Index

Rules and patterns relevant to current or upcoming work. New entries always
start here.

| tags | description | source | type |
|------|-------------|--------|------|

---

## Foundation Index

Rules that have recurred across 2+ phases or are universal (security,
validation). Graduate from Active when proven durable.

| tags | description | source | type |
|------|-------------|--------|------|

---

## Reference Index

Rules from completed, stable work. Graduate when the tag is inactive for 2+
phases AND the work area is complete.

| tags | description | source | type |
|------|-------------|--------|------|
```

**INDEX.md skeleton rules:**
- Always three tiers: **Active**, **Foundation**, **Reference**. Don't collapse.
- Always the four-column row format: `| tags | description | source | type |`.
- Tag Vocabulary block at the top lists the project's canonical tags.
  Populate it as rules are captured — don't invent tags up front.
- Quick Reference table lists every AI subject file. Update it whenever an
  AI file is added, split, or removed.

---

## Step 4 — Seed ai/_overview.md

Create `lessons_learned/ai/_overview.md` with this skeleton:

```markdown
# AI Lessons — Topic Index

> Derived from `lessons_learned/phase*.md` source files.
> Read the topic file matching your current work for self-contained rules.
> For full narrative context, follow the *Source* pointer in each rule.
> Last updated: {date}

| File | Rules | Covers |
|------|-------|--------|
| (populate as ai/{topic}.md files are created) |

**Unique rules: 0** (deduplicated across files)

## How to use

1. **Starting new work?** Read the 1–2 topic files matching your area.
2. **Hit a bug?** Grep `INDEX.md` by tag to find the specific entry.
3. **Adding a stage/tool/endpoint?** Read the relevant topic file + `process.md`.
4. **Writing tests?** Read `testing.md` first.
5. (Add more entry points as AI files grow — one per major file.)
```

**_overview.md skeleton rules:**
- One row per AI file. No file = no row.
- Rule count excludes superseded rules.
- "Covers" column is a comma-separated keyword list — not sentences. Grep
  hits on this column route the lookup protocol to the right file.
- "How to use" entries are one per major entry point. Keep them literal —
  the lookup protocol routes sessions to files through these entries.

---

## Step 5 — Write the First Phase File

Start with `phase0_setup.md`. This records the bootstrap decisions themselves:
- Why the project was started
- Initial architecture decisions
- Dependencies chosen and why
- Known constraints (timeline, platform, team)

Use the phase file format from `templates.md` → "Phase File Structure".

**What to record in phase0:**
- **Design Decisions:** Every non-obvious choice made during setup. "Why
  Postgres not SQLite" is cheap to record now and expensive to reconstruct later.
- **Constraints:** Anything that will shape future phases but isn't obvious
  from the code. "Can't use X because of licensing" or "Must support Y
  deployment target."
- **Applied Lessons (optional):** If you're bootstrapping on top of lessons
  from a prior project (via `lessons_learned/export.md`), record which of
  those Foundation-tier rules applied to this new project's setup.

phase0 often has sparse **What Went Well** and **Bugs** sections. That's
fine — it's a setup snapshot, not a work log.

---

## Step 6 — Teach the Project to Trigger the Skill

Add a reference to the skill in `CLAUDE.md` (or equivalent project-instructions
file):

```markdown
## Lessons Learned

This project uses the lessons-learned skill for institutional knowledge.
Before starting any non-trivial work, run the lookup protocol:

1. grep INDEX.md for relevant tags
2. Read matching ai/{topic}.md files
3. Apply rules before writing code

After completing a coherent work unit, run the capture workflow:
1. Write a phase file in lessons_learned/
2. Update INDEX.md with one row per lesson
3. Update ai/{topic}.md with When/Rule entries

See the `lessons-learned` skill for full workflow details.
```

This makes the skill discoverable from the project's root instructions
without requiring each session to know the skill exists.

---

## Step 7 — First Lookup Protocol Run

Before doing any work in the newly bootstrapped project, run a lookup:

```bash
grep -i "{keyword1}\|{keyword2}" lessons_learned/INDEX.md
grep -i "{keyword}" lessons_learned/ai/_overview.md
```

On a fresh bootstrap, both grep calls will return nothing — that's expected.
The goal is to establish the muscle memory: *always look up before writing*,
even when there's nothing to find yet. Over phases, the lookups start returning
hits and the feedback loop begins.

---

## Step 8 — First Reflection Run

At the end of the first coherent work unit (not the setup itself — actual
work), run a full reflection following SKILL.md §3a. This will:

1. Populate phase1's entries in the phase file
2. Add the first rows to INDEX.md's Active tier
3. Create the first AI subject file(s) — likely only 1 or 2 at first
4. Update `_overview.md` with the new files

At this point the system is live and future sessions should start with a
lookup against the newly-populated INDEX.

---

## Common Bootstrap Mistakes

- **Creating AI files before they have content.** Don't create an empty
  `security.md` "because we'll need it eventually." AI files are created
  when a phase produces 3+ rules on a topic, not in anticipation.
- **Populating the tag vocabulary up front.** Tags are discovered from real
  rules, not imagined. Start with an empty vocabulary and let it grow.
- **Writing phase0 as a manifesto instead of a snapshot.** Phase0 is a
  record of setup decisions, not a vision document.
- **Committing `lessons_learned/` with `.gitignore` still excluding `*.md`.**
  Check the `.gitignore` before your first reflection — the whole system
  depends on the files being tracked.
- **Duplicating SKILL.md instructions into a project-level README.** The
  skill is loaded per-session; the project just needs a pointer to it, not
  a copy of the workflow.

---

## When to Use Retroactive Reflection Instead

If the project already has 50+ commits, multiple contributors, or known
pitfalls that predate the bootstrap, run the bootstrap steps 1–4 above to
create the directory structure, then follow `retroactive.md` to capture
accumulated knowledge before starting the normal capture workflow.

Retroactive entries differ in one key way: they skip the Active tier and
go straight to Foundation (they are already proven by lived experience).

---

## Checklist

- [ ] `lessons_learned/` and `lessons_learned/ai/` directories created
- [ ] Phase naming convention chosen and documented in phase0 or CLAUDE.md
- [ ] `INDEX.md` created with three tiers and empty tables
- [ ] `ai/_overview.md` created with the skeleton table and How to use block
- [ ] `phase0_setup.md` written capturing bootstrap decisions
- [ ] Project instructions (CLAUDE.md) reference the skill
- [ ] `.gitignore` does not exclude `lessons_learned/`
- [ ] First lookup protocol run done (even if zero hits)
- [ ] First real reflection queued for end of next work unit
