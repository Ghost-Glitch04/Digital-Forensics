# Skill Development Lessons Learned

Real patterns recognized during the development of the `scripting-standards` skill. Each entry follows the six-field schema documented in `README.md`.

**Entries are strictly gatekept.** Real incidents only. Retroactive entries require existing-file evidence. Success story lessons require a generalizable rule that extends beyond the specific incident.

Entries are ordered by capture date, newest at the bottom. Cross-reference by grep-stable slug.

---

### <lesson:2026-04-22:empty-assoc-array-under-set-u>

**Situation.** Phase 4d verification of `verify-integrations.sh`. The helper uses `declare -A` for associative arrays (MAP_CONTRACTS, CODE_CONTRACT_VERSION, CODE_CONTRACT_LOC) and `set -euo pipefail` for strict error handling — both idioms explicitly recommended by the skill. Test 8 of a 10-test regression suite introduced an empty project (no CONTRACT or USES markers, no map entries) to verify clean-exit behavior on the zero-content edge case.

**What went wrong.** The helper aborted mid-run in `read_map_file` with exit code 1 and stderr message `MAP_CONTRACTS: unbound variable`. Seven tests (baseline clean, three drift directions, DRIFT-EXPECTED downgrade, phase gate, missing map) had passed. The eighth surfaced the bug: the line `log INFO UNIT_END "... contracts=${#MAP_CONTRACTS[@]} ..."` triggered the strict-mode error.

**Root cause.** Bash 5.2 under `set -u` treats `${#ASSOC[@]}` as "unbound variable" when the associative array has been declared (`declare -A FOO`) but never assigned to. This is asymmetric with indexed arrays — `declare -a FOO=()` followed by `${#FOO[@]}` returns 0 without error. The asymmetry is undocumented in the bash manpage for this specific interaction; it's discoverable only through runtime exposure.

**What would have caught it.** The empty-project test itself — Test 8 ran specifically because `reference/prove_first.md`'s Five Signs include "asserting on a framework's internal behavior you've never inspected." Bash's strict-mode behavior qualifies. The fix was applied in-phase (Phase 4d) before V5.0 shipped; the test surfaced it before any production user hit it.

**Lesson encoded.** Verification History section appended to the bottom of `reference/integration-helpers/verify-integrations.sh`, documenting the bug, the fix (`declare -A ARR=([x]=1); unset 'ARR[x]'` idiom), and the rule. Any future editor of this script sees the bug history before modifying the declaration block.

**Generalizable rule.** Any Bash script using `set -u` together with `declare -A` must touch each associative array before reading its size or iterating its keys. The idiom `declare -A ARR=([x]=1); unset 'ARR[x]'` is the minimal fix — initialize with a dummy key, immediately remove it, leaving the array "touched" but empty. Indexed arrays declared with `=()` are unaffected; this asymmetry is specific to associative arrays.

**See also:** `reference/prove_first.md § Case Study 1 — Celery task.apply() vs push_request` (same failure pattern: asserting on framework-internal behavior without inspection); `<lesson:2026-04-22:verification-applies-at-skill-level>` (the protocol run that caught this).

---

### <lesson:2026-04-22:format-drift-in-self-authored-patches>

**Situation.** V5.0 Phase 4d setup for runtime verification. I was building a test project to exercise `verify-integrations.sh` and needed a sample `.integration-map.md` matching invariant I5 (`^- CONSUMER: path:line`, CONSUMER entries at column 0). Simultaneously, I had already drafted Patch 1c (SKILL.md Worked Example — Adding a New Contract) in the V5.0 patch document, which included an example `.integration-map.md` fragment demonstrating the same format.

**What went wrong.** The Patch 1c example had CONSUMER entries **nested** under a `- **Consumers:**` parent bullet, indented two spaces:

```
- **Consumers:**
  - CONSUMER: src/api/client.ps1:87 ...
```

This violated invariant I5's grep pattern `^- CONSUMER:`, which anchors to column 0. The nested form wouldn't be detected by the helpers. The bug was caught only because I used the correct flat format in the test project (sourced from Invariant I5 directly) and noticed the mismatch during Phase 4d setup. By that point, the patch document had been reviewed, approved, and included in the V5.0 complete bundle with the format violation intact — I had to go back and fix it.

**Root cause.** I copied the visual hierarchy of a nested-list example without re-checking it against the Format Contract I had authored myself in the same document. The nested form *looked* more informational (grouping consumers under a Consumers header) but it broke the grep-anchoring that makes the whole system mechanical. The author of the invariant and the author of the example were the same person and still produced drift — proving that authorial identity is not a drift defense.

**What would have caught it.** Running the Integration Grep Protocol's Q6 verification against every example in the authored content, before shipping the patch document. The V5.0 patch document had five examples involving CONSUMER entries; none were checked against the grep pattern that would detect them in a real codebase.

**Lesson encoded.** This lesson, and a process note for future format-contract changes: the authoring workflow now includes a "run the invariant's grep pattern against every example in the authored content" step before shipping a patch document that references the invariant.

**Generalizable rule.** Format contracts must be tested against the examples you write, not just trusted. An author introducing a format and an author writing examples against it are the same drift risk even when they are the same person — especially then. Before shipping a document that contains examples of a grep-anchored format, grep the invariant's pattern against your own examples; if the pattern doesn't match, the examples are wrong.

**See also:** `<devlog:2026-04-22:illustrative-templates-launch>` (the launch decision that established the templates-before-case-studies pattern); `reference/integration-tracking.md § Format Contract § Invariant I5` (the violated invariant).

---

### <lesson:2026-04-22:grep-first-assumed-but-unspecified>

**Situation.** V5.0 Phase 2 (architecture design) for integration tracking. Ghost's memory notes described "Grep-First protocol" as an established mitigation for Claude Code's context-locality problem. I designed the V5.0 Integration Grep Protocol to tie into Grep-First as its foundational layer, assuming the broader protocol already existed in the skill's source files and I would reference it.

**What went wrong.** Phase 3 structural diff against V4.7 revealed that Grep-First existed only in Ghost's memory notes and in informal practice — not formalized anywhere in the scripting-standards skill. A grep across all nine V4.7 files for `grep-first|grep_first|grep\.first` returned zero matches. The Phase 2 architecture had been built on a dependency that didn't exist in the skill's codified form.

**Root cause.** I trusted the memory notes as evidence of the protocol's existence without verifying against source files. The memory notes accurately reflected Ghost's development practice; they did not distinguish practices that had been codified from practices that remained informal. The memory-practice gap was the hidden assumption.

**What would have caught it.** A grep across the V4.7 skill files for the named protocol, done once during Phase 1 or early Phase 2. The cost would have been seconds; the rework was a Phase 3 design revision to make the Integration Grep Protocol self-contained (Path 1 of three options considered). The revised architecture shipped; the scope creep (retrofitting Grep-First formalization into V5.0) was avoided.

**Lesson encoded.** `<devlog:2026-04-22:integration-grep-protocol-self-contained>` captures the decision that resulted from catching this. The generalizable rule below is added here to warn future design cycles that depend on named-but-possibly-informal practices.

**Generalizable rule.** Verify named dependencies exist in the source-of-truth before building architecture on them. Memory notes, conversation references, and informal practice are evidence that *something* exists — but not that it has been codified in the form the current work assumes. A grep of the target skill's files for the named concept, done once during planning, costs seconds and prevents architectural rework later. This applies to protocols, patterns, conventions, and any named artifact that a new design proposes to extend or reference.

**See also:** `reference/prove_first.md § Case Study 1 — Celery task.apply() vs push_request` (same failure pattern at the framework level: asserting on something's existence without inspection); `<devlog:2026-04-22:integration-grep-protocol-self-contained>` (the resulting architectural decision).

---

### <lesson:2026-04-22:verification-applies-at-skill-level>

**Situation.** V5.0 Phase 4d end-to-end verification of `verify-integrations.sh`. The bash helper had been static-reviewed for syntax, logic, and scripting-standards compliance. `bash -n` passed cleanly. The algorithm had been walked through on paper and matched the Integration Grep Protocol's specification. By the standard of "I've read the code and it looks right," the helper was ready to ship. The Phase 4c review gate offered an explicit option to skip Phase 4d ("V5.0 ships as-is; I'll verify locally later").

**What the protocol almost missed.** Had Phase 4d been skipped, the helper would have shipped with the bug captured in `<lesson:2026-04-22:empty-assoc-array-under-set-u>` — aborting on every empty project it was run against, with a cryptic bash error message and no clear path to resolution. Users with small or greenfield projects would have hit a hard failure on first run. The skill's credibility on first use would have been damaged before integration tracking had a chance to demonstrate value; the first real incident would have been "this helper doesn't work" rather than "this helper caught a bug I wouldn't have caught otherwise."

**Root cause.** Static review and `bash -n` verify syntax and visible control flow. They do not verify runtime behavior on edge cases. The empty-input case is exactly the kind of path that static review passes over — there's no visible branch for "no content found"; the code looks like it handles it correctly because the loop simply doesn't execute. Runtime exposure is the only reliable way to surface this category of bug.

**What did catch it.** The Phase 4d regression suite, specifically Test 8 (empty project). The test was included because prove-first reasoning applied to the helper: the helper asserts on bash behavior under `set -u`, which is framework-internal behavior I had never personally inspected in that exact combination. The test was a direct application of the skill's own Prove-First rule to the skill's own tooling.

**Lesson encoded.** Phase 4d is now part of the skill's drafting protocol for any new helper script shipped with the skill. The `scripting-standards` skill already required end-to-end verification for full-template scripts (documented in `reference/minimal_scripts.md` and each language reference's Verification History section); this lesson extends the requirement from scripts users write *using* the skill to scripts that ship *as part of* the skill.

**Generalizable rule.** Verification discipline applies at the skill level, not only at the script level. A skill's own tooling is held to the same runtime-verification bar as the scripts it teaches users to write — static review and syntax checks are necessary but not sufficient. End-to-end runs against edge cases, especially empty inputs and malformed inputs, catch a class of bugs that review cannot see. When the temptation surfaces to ship helper scripts as "reviewed but not run," the correct response is to invest the time for a 10-test regression before shipping, not to defer.

**See also:** `<lesson:2026-04-22:empty-assoc-array-under-set-u>` (the specific bug this protocol caught); `<devlog:2026-04-22:powershell-helper-ships-unverified>` (the counterexample — the helper that did ship without runtime verification, with the residual risk explicitly acknowledged); `reference/prove_first.md` (the general principle this lesson extends).

---

### <lesson:2026-04-22:voice-drift-across-session-boundaries>

**Situation.** Retroactive capture. `SKILL.md` carries a section titled "A Note on Voice" under "How This Skill Evolves," explicitly acknowledging that the skill was authored session-by-session by different instances of the same assistant and providing guidance on preserving voice across session boundaries. The section includes a Testable Criterion subsection specifying when a rewrite for voice is warranted. Sources: `SKILL.md § How This Skill Evolves § A Note on Voice`, full text.

**What went wrong.** In earlier revisions of the skill (exact timing not documented in the current sources, but implied by the existence of the corrective section), content was rewritten by different Claude instances in voices that diverged from the established register — "direct, occasionally blunt, structured around the rule-and-why pattern." The result degraded navigability: a reader building a mental model of the skill had to re-calibrate register on each section. Voice drift was non-obvious in single-session review (each section read fine in isolation) but was visible cumulatively to a reader processing the whole skill.

**Root cause.** Each authoring session had fresh context with no native recall of the skill's register. Without an explicit voice guide and a testable criterion for rewrites, "this section reads oddly" was a sufficient trigger to rewrite it — which replaced the unfamiliar register with the session's native register, compounding drift over time. A single-session author has natural voice consistency; cross-session authorship does not, and requires explicit scaffolding.

**What did catch it.** The addition of the "A Note on Voice" section, which supplies both the register description ("direct, occasionally blunt, rule-and-why") and a testable criterion: "Before rewriting any section for voice, read it and restate the rule it conveys in one sentence. If you can restate the rule unchanged, the prose works — the unfamiliarity is stylistic, not comprehension-blocking, and the rewrite isn't needed." The criterion distinguishes stylistic unfamiliarity from prose that actually blocks comprehension.

**Lesson encoded.** `SKILL.md § How This Skill Evolves § A Note on Voice`, specifically the Testable Criterion subsection.

**Generalizable rule.** Cross-session authoring of a single artifact requires an explicit voice guide and a testable criterion for when rewrites are warranted. "It reads oddly to me" is not a testable criterion; "I cannot restate the rule without rereading the section" is. This rule applies to any skill or document with multi-session authorship, not only to this one — the failure mode is structural to how LLM-assisted authoring works across session boundaries, not specific to any single skill.

---

### <lesson:2026-04-22:safety-critical-duplication-pattern>

**Situation.** Retroactive capture. `SKILL.md`'s "Worked Example — Adding a New Rule" demonstrates the Idempotency Rule pattern: the rule is stated in `SKILL.md` where the design decision is made ("should I use retry?") and is also stated in each language reference's helper comment where the implementation happens ("am I using retry correctly?"). The Worked Example closes with an explicit statement of the pattern: "Safety-critical rules are the one place where duplication is correct. For non-safety rules, pick one location — duplicate rules drift." Sources: `SKILL.md § How This Skill Evolves § Worked Example — Adding a New Rule`, final paragraph.

**What went wrong.** Before this pattern was codified, safety-critical rules that existed in only one location were vulnerable to a specific failure mode: a session reviewing the helper without reviewing the top-level skill (or vice versa) would miss the rule. The Idempotency Rule in particular addresses a safety concern — a retry wrapper that doubles payments or sends duplicate emails — where a missed check is not a documentation gap but a production incident. A single-location rule placed the burden of "know to look in `SKILL.md` before using the retry helper" on every future session, which is not a reliable burden to place.

**Root cause.** The general editorial principle "duplicate rules drift" (stated in the same Worked Example's closing paragraph) argues against duplication. But "duplicate rules drift" addresses a correctness-of-documentation concern; safety-critical rules address a correctness-of-action concern. The two concerns have opposite correct responses for a narrow class of rules, which the general principle does not accommodate alone.

**What did catch it.** The Worked Example explicitly carves out the safety-critical case and establishes the dual-placement pattern as the correct structural response. The carve-out is narrow, justified by the failure mode, and does not dilute the general "duplicate rules drift" principle for non-safety cases.

**Lesson encoded.** `SKILL.md § How This Skill Evolves § Worked Example — Adding a New Rule`, specifically the final paragraph establishing the dual-placement convention with the Idempotency Rule as the template.

**Generalizable rule.** Safety-critical rules must appear both at the decision point (where the choice is made) and at the implementation site (where the rule is applied). For non-safety rules, single-location is correct — duplication introduces drift and the drift is worse than the single-location gap. The discriminator is failure cost: if missing the rule at the implementation site produces a production incident rather than a documentation gap, duplicate; otherwise, single-source it.

---

### <lesson:2026-04-22:l2-harness-must-be-line-ending-aware>

**Situation.** V5.2 Phase 4c verification of `grep_first.md`. Per-category L2 grep-tests (worked template identifiers vs canonical pattern) passed cleanly during 4b-1, 4b-2, and 4b-3 individual sub-phase reviews, when the file was LF. At the end of 4c, `grep_first.md` was converted to CRLF to match the V5.1 bundle convention, and a full-suite L2 re-run was performed against the now-CRLF file.

**What went wrong.** The full-suite harness reported L2 FAIL on G4 (API endpoints) and G9 (file paths). G4's new path `/api/accounts` and G9's old path `logs/run.log` were reported as not matching their canonical patterns, despite those same patterns having passed cleanly against the same identifiers just phases earlier. Investigation time was contained to a single tool-call round, but the experience produced false-negative alarm on authoring that was actually correct — the content had not drifted; only the harness was now returning misleading results.

**Root cause.** GNU grep's `\b` word-boundary semantics against patterns like `/api/users\b` or `logs/run\.log\b` behave differently at line-end under LF vs CRLF. Under LF, `\b` anchors cleanly between the last path character and the line terminator. Under CRLF, the `\r` that precedes `\n` is not a word character, so `\b` matches between the path and `\r` — but the surrounding regex construction (grep in extended mode with trailing `\b`) can fail to match when the content immediately before `\r` is a word character followed by no other word character, depending on the specific boundary being asserted. The net effect is false-negative L2 failures on CRLF content that passed under LF. The harness did not strip CR before running grep, and did not use patterns tolerant of `\r\n` at end of line.

**What did catch it.** Cross-checking the individual 4b sub-phase passes against the full-suite failure. The worked templates had not changed between the two runs — only the line-ending convention had. The failures were therefore impossible as content drift, which isolated the harness as the root cause. A CRLF-aware harness (strip `\r` via `tr -d '\r'` into a tempfile, grep the tempfile) produced 9/9 PASS on the identical content.

**Lesson encoded.** V5.2 Phase 4c verification procedure now uses a CRLF-aware L2 harness (`/tmp/l2_verify.sh` pattern, reusable for any future V5.2-and-later edit). The harness strips CR before grep, or equivalently uses patterns that tolerate `\r\n` at line-end. Any L2 harness run against a file in the V5.0+ bundle (all markdown CRLF by convention) must follow this discipline or produce silent false negatives.

**Generalizable rule.** L2 verification harnesses must be line-ending-aware or pre-normalize input to LF. A harness that passes under LF can silently FAIL on CRLF content, producing false negatives that waste investigation time and — worse — can mask real drift if the FAIL rate becomes background noise. Strip `\r` before regex with word-boundary anchors, or use patterns that tolerate `\r\n` (e.g., `(\b|\r)`). This rule is the dual of `<lesson:2026-04-22:format-drift-in-self-authored-patches>`'s Pattern B warning — Pattern B warns that text-replacement tools can silently convert CRLF→LF; this lesson warns that verification tools can silently misbehave on the reverse direction.

**See also:** `<lesson:2026-04-22:format-drift-in-self-authored-patches>` (V5.1 Pattern B — CRLF→LF drift is the dual of this lesson); `<devlog:2026-04-22:v5-2-formal-invariants-over-workflow-guidance>` (the V5.2 decision that made L2 harness discipline central to Grep-First authoring).
