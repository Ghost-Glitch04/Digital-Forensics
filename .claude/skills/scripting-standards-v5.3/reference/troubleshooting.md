# Troubleshooting — Pivot Protocol and Session Resumption

This file expands two rules that SKILL.md only summarizes:

1. **The two-failure rule** and how to pivot when stuck
2. **Development Notes** as the primary session-resumption anchor

**Load this file when:** an approach has failed twice, you are about to start a new strategy, or you are resuming work on an existing script in a new session.

---

## Part 1 — The Two-Failure Rule

Repeating the same approach expecting a different result is not debugging. It is spinning.

### The rule

**If an approach has failed twice, do not try it a third time.** Stop, document what was tried and why it failed, then shift to a genuinely different strategy.

Different means different *at the level of approach*, not parameters. A few examples of what counts and what doesn't:

| Change | Different approach? |
|---|---|
| Timeout 30s → 60s → 120s | No. Same approach, different parameter. |
| Default timeout → chunked requests with configurable timeout | Yes. Different decomposition of the problem. |
| Retry wrapper with 3 attempts → 5 attempts | No. |
| Retry wrapper → switch to a queue with ack/nack | Yes. |
| Mock the DB session → Mock with `spec=Session` → Mock with spec + side effects | The spec change is different; the side_effects change is not. |
| Patch `api.routes.engagements.load_profile` → patch `runbook.loader.load_profile` | Yes. Different target resolution. |

### Why two failures

- **One failure** is data. You learned something about the system.
- **Two failures** is a pattern. The assumption driving both attempts is probably wrong.
- **Three failures** is sunk-cost reasoning. You're committed to the assumption because you've invested in it, not because it's likely to be correct.

The cost of stopping after two failures and genuinely pivoting is almost always lower than the cost of a third failed attempt.

### The pivot sequence

When stuck:

1. **Name the failure clearly.** What did the error say verbatim? What did the logs show? "It didn't work" is not a diagnosis. "`AttributeError: module 'api.routes.engagements' has no attribute 'load_profile'`" is.

2. **Identify the assumption that was wrong.** Every failed attempt rests on at least one false assumption. Find it. If you can't identify it, you don't have enough information to try again — go gather information, don't guess. If you can't pin down the assumption at all, that's often a sign a prove-first step was skipped earlier — see `prove_first.md` "Five Signs You Need a Proof Step" for the categories where unverified assumptions typically hide.

3. **Generate at least two alternatives before choosing one.** Picking the first alternative that comes to mind is a form of the same sunk-cost trap — it's usually a minor variation of what already failed. Force yourself to produce at least two, then pick between them.

4. **Pick the alternative most likely to surface new information.** A partial success that reveals the real root cause is more valuable than another clean failure. Prefer diagnostic attempts over "finally nail it" attempts when you are still uncertain about the cause.

### Alternatives to cycle through when pivoting

When you need a different approach but can't see one, work through these in order:

| Angle | Question to ask |
|---|---|
| **Abstraction level** | Am I at the wrong level of the stack? Would a lower-level call (raw HTTP instead of SDK) or a higher-level one (framework helper instead of hand-rolled) be easier? |
| **Scope of failure** | Is the failing thing too big to debug? Can I decompose it further and isolate exactly which step breaks? |
| **Observability** | Am I guessing because I can't see what's happening? Add diagnostic logging *before* trying another fix. |
| **Environment** | Is the environment what I think it is? Check Python version, shell, container state, network reachability, auth status. |
| **Assumption audit** | Read the error code reference and the documentation for every function in the failing path. Look specifically for the three categories that hide in plain sight on first read: default argument values (what the call does when you *don't* pass something), edge-case behavior (empty input, zero, `None`, unicode, timeouts), and return-value semantics (does it return `None` or raise on not-found? a value or a list of one? a dict or an object with attrs?). A fresh read framed around these three categories catches misreads the first read missed. |
| **Manual reproduction** | Can I reproduce the failure manually outside the script? If not, the script is doing something the manual process isn't — that's the bug. |
| **Borrow from memory** | Is this a class of problem I've solved before? Check project memory, lessons learned, prior incident notes. |

---

## Part 2 — Development Notes as the Resumption Anchor

Every non-trivial script carries a `## Development Notes` block at the top (or in a companion `.notes.md` file). This block has two jobs:

1. **Debugging log while the script is being built.** What was tried, what failed, what the root cause was.
2. **Session-resumption anchor.** What the next session needs to know — whether that's a human, a new agent session after context compaction, or you coming back after a week.

### Why this matters for agent sessions specifically

Claude Code sessions have context limits. Conversations get compacted. A session that was debugging a script for an hour may come back — after a `/compact` or a brand-new session start — with no memory of what was tried. Without Development Notes, the new session will re-try every dead-end approach the previous session already ruled out. The notes block is the durable institutional memory for the script.

**If you only read one part of this file, read this:** when resuming work on an existing script, read the Development Notes block *before* touching the code. Every time. It is the single highest-leverage habit for cross-session continuity.

### The schema

Each entry records:

- **Date and attempt number** — so the sequence is auditable
- **What was tried** — specific enough that someone else could reproduce it
- **Result** — `FAILED` or `SUCCESS`
- **Reason** — the root cause, not just the symptom
- **Next** — for failures only: what the next attempt will change (must be *different*, per the two-failure rule)

### Full example

```text
## Development Notes

### [2026-04-11] Attempt 1 — Direct API call with default timeout
Tried : Single POST to /api/export with default 30s timeout
Result: FAILED — timeout on payloads > 5MB
Reason: Default timeout insufficient; large payloads exceed 30s consistently
Next  : Switch to chunked requests with configurable timeout param

### [2026-04-11] Attempt 2 — Chunked requests, $TimeoutSec = 120
Tried : Split payload into 500-record chunks, POST each with 120s timeout
Result: FAILED — auth token expired mid-batch on large datasets
Reason: Token lifetime (60min) shorter than full batch run time
Next  : Refresh token between chunks — different approach from attempt 1 (parameter → structural)

### [2026-04-11] Attempt 3 — Chunked requests with token refresh per batch
Tried : Refresh auth token before each chunk, 120s timeout retained
Result: SUCCESS — reliable across all tested payload sizes (tested up to 15MB)

### Edge cases discovered during testing
- Empty input file produces 0 chunks — script exits 0 with "no records to export" log line
- 499 records produces 1 chunk of 499; 500 produces 1 chunk of 500; 501 produces 2 chunks (500 + 1)
- Chunk boundaries never split a logical record — input is pre-sorted by parent_id before chunking
```

The "edge cases discovered during testing" section is where the notes earn their keep on resumption. A new session reading this knows to preserve the pre-sort, the chunk size boundary, and the empty-file behavior — without having to re-discover them.

---

## When to Write in Development Notes

**Write an entry when:**

- An attempt failed and you're about to try something different
- An attempt succeeded after previous failures (record the winning approach AND why it worked)
- You discovered an edge case during testing that isn't obvious from the code
- You ruled out an approach based on reading rather than running (record why)
- You chose between two plausible approaches and picked one for a specific reason
- You resumed work and want to note what state you found the script in

**Don't write an entry for:**

- Routine successful execution (the log file is for that)
- Trivial syntax errors and typos you fixed in seconds
- Commentary on the code itself (use code comments)

---

## Resumption Protocol

When you pick up an existing script — whether in a new session, after `/compact`, or just coming back to old work — follow this sequence:

### Step 1 — Read the Development Notes block first

Before touching anything, read the full notes block. Look for:

- **Approaches already tried and rejected.** Don't re-attempt these unless you have genuinely new information.
- **The winning approach and why it worked.** Don't silently change it without understanding the reason it was chosen.
- **Edge cases that aren't obvious from the code.** These are land mines for the unwary.
- **The last recorded state.** If the notes say "Attempt 3 succeeded, now testing with larger payloads" and the code doesn't match the Attempt 3 description, someone has been working since the notes were written — read the commit history next.

### Step 2 — Check git log and the script's last modification

```bash
git log --oneline -20 -- path/to/script
git diff HEAD~5 -- path/to/script
```

The notes may be out of date. The commit log and recent diffs reveal what has actually changed. If the notes say "Attempt 3 succeeded" but the code is now on Attempt 5 with no corresponding notes, the notes are stale — update them as your first act.

### Step 3 — Run the script in dry-run mode if it's operational

If the script is complete enough to run, execute it in `--dry-run` mode before modifying anything. The output tells you whether the current state is consistent with what the notes describe. If they don't match, you have a stale-notes problem or a broken-script problem to solve before proceeding.

### Step 4 — Write a resumption entry

Add an entry to the Development Notes block that records:

- That you resumed (date, session type — "new session", "continuing after compaction", etc.)
- The state you found the script in
- What you plan to do next

Even if you don't end up making changes, the resumption entry proves the protocol was followed and helps the *next* session.

---

## Stale Notes — How to Handle Them

Development Notes can become stale. The code evolves; the notes don't. When you find stale notes, the response depends on severity:

| Severity | Example | Action |
|---|---|---|
| **Minor drift** | A function was renamed, notes still use the old name | Update the notes inline as you work |
| **Moderate drift** | An approach in the notes was abandoned but the entry says "SUCCESS" | Add a new entry correcting the record: "Earlier entry marked this SUCCESS, but the approach was later abandoned in commit abc123 because..." |
| **Severe drift** | Notes describe a completely different strategy than the current code | Stop. Read git history. Reconcile the notes with reality *before* making any changes. Severe drift usually means multiple undocumented session transitions happened. |

**Never delete old entries.** Add new entries that correct them. The debugging history is part of the institutional memory — a later session may need to know that Attempt 3 was thought to succeed but was later revealed to be wrong, not just that Attempt 5 is the current answer.

---

## The Notes Block Is Not Optional for Complex Scripts

For minimal scripts (see `minimal_scripts.md`), a Development Notes block is overkill. Skip it for one-shot utilities.

For any script with two or more of the following, the notes block is required:

- External service calls
- Multi-step data transformations
- Phase gates / full template structure
- Has been debugged or pivoted at least once
- Runs in an unattended context (cron, CI, pipeline)
- Will be handed off to another session / agent / operator

*These criteria overlap with — but are not identical to — the "grow to full template" criteria in SKILL.md's "When to Grow into the Full Script" section. The overlap is intentional (external calls and multi-step transforms are load-bearing for both decisions), and so is the divergence: a script can deserve the full template without needing the notes block (e.g., a short pipeline-composable utility with no debugging history), and a script can need the notes block without deserving the full template (e.g., a minimal script that has already been pivoted once). The two decisions answer different questions — "when does structure help?" vs. "when does memory help?" — and should be evaluated separately.*

When in doubt, add the block. The cost is a few lines of markdown; the benefit is every future session that touches the script.

---

## Summary — The Two Rules of This File

1. **Two failures, stop and pivot.** Don't try a third minor variation of an approach that has failed twice. Generate real alternatives, pick the one most likely to reveal the root cause, and proceed.

2. **Read Development Notes before touching existing code.** It is the primary cross-session memory mechanism for scripts. Skipping this step is how rejected approaches get re-tried and hard-won edge cases get re-discovered.

Both rules exist to protect the most limited resource in agent work: the time and context budget required to get a script from broken to working. Everything else is optimization on top of these two.
