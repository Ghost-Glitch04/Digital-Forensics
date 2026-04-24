# Skill Development Log

Design decisions made during the evolution of the `scripting-standards` skill. Each entry follows the four-required-field schema documented in `README.md`.

**Entries are strictly gatekept.** Decisions with named alternatives only. Retroactive entries require existing-file evidence. Calibration observations, narratives, and general principles are rejected.

Entries are organized by version grouping, matching the Decision Index in `README.md`. Within each grouping, approximate chronological order top-to-bottom. All entries share the capture date 2026-04-22 — the day V5.1 was drafted. Retroactive entries state the original version context in the Context field.

---

## V5.0 — Integration Tracking (design phase)

### <devlog:2026-04-22:contract-block-separate-vs-wrap>

**Context:** V5.0 Phase 2 architecture design for integration tracking. The Unit header format already in use across all three language references (PowerShell, Bash, Python) carries Purpose, Inputs/Args/Params, Outputs/Returns, Depends. A new `<CONTRACT>` block was being designed to declare the formal integration contract — typed parameters, return shape, throws, side effects — in a grep-stable form. The question was whether the CONTRACT block should wrap the existing Unit header (reusing its fields) or sit as a separate block above it.

**Decision:** Separate block above the Unit header, with no blank line between them so they read as a single logical region while remaining grep-separate. The CONTRACT block contains the machine-readable contract; the Unit header retains its existing narrative form.

**Alternatives considered:** Wrap the existing Unit header with `<CONTRACT>` tags (Option W). Would add fewer lines and avoid duplication between Unit header fields and CONTRACT fields.

**Rationale:** Long-term reliability, effectiveness, and efficiency all favor separation. Reliability: a future editor modifying the Unit header's narrative content cannot accidentally damage the CONTRACT's machine-readable fields because they occupy separate blocks. Effectiveness: CONTRACT fields have visual dedication — the return-shape declaration is prominent rather than buried among narrative fields. Efficiency: the 2-line cost is negligible. The apparent duplication between Unit header ("Args: ...") and CONTRACT ("PARAMS: ...") serves different readers — the Unit header is narrative for humans; the CONTRACT is machine-consumable for grep. The skill already establishes precedent that narrative and machine-readable concerns coexist (the log format contract's `key=value` and `Label: value` styles).

**See also:** `reference/integration-tracking.md § Language-Specific Marker Syntax`.

---

### <devlog:2026-04-22:integration-grep-protocol-self-contained>

**Context:** V5.0 Phase 3 structural diff against V4.7. Ghost's memory notes referenced "Grep-First protocol" as an established mitigation for Claude Code's context-locality problem. Phase 2 architecture had assumed Grep-First was formalized somewhere in the V4.7 skill and that V5.0's Integration Grep Protocol would reference it as its foundational layer. A grep across all V4.7 files for `grep.first|grep-first|grep_first` returned zero matches.

**Decision:** Define V5.0's Integration Grep Protocol as self-contained — a named protocol scoped specifically to integration tracking, with its own Q1-Q6 query library, independent of any broader Grep-First concept.

**Alternatives considered:** (1) Formalize Grep-First as part of V5.0 alongside integration tracking — both protocols land in the same release. (2) Defer integration tracking entirely until Grep-First is formalized as its prerequisite.

**Rationale:** Grep-First deserves its own design cycle. It addresses a broader problem than integration tracking — context-locality applies to error codes, log prefixes, config keys, any shared textual element. Retrofitting it into V5.0 as scaffolding for integration tracking would have shaped it by integration tracking's concerns rather than from first principles. The specificity of the Integration Grep Protocol is also valuable on its own — its queries are optimized for `<CONTRACT>`/`<USES>` markers and would not generalize cleanly if broadened. Scoping V5.0 narrowly kept the release focused on one headline and preserved Grep-First for a dedicated future version (now committed to V5.2).

**See also:** `<lesson:2026-04-22:grep-first-assumed-but-unspecified>` (the pattern of trusting named-but-unspecified dependencies).

---

### <devlog:2026-04-22:illustrative-templates-launch>

**Context:** V5.0 Phase 3 design decision. `reference/integration-tracking.md` needed worked examples demonstrating the Change Impact Protocol on each failure mode (signature change, return-shape change, variable rename). The skill's gatekeeping rule for case studies (inherited from `prove_first.md`) forbids hypothetical examples — but V5.0 shipping at launch meant zero real integration-tracking incidents had occurred yet.

**Decision:** Launch V5.0 with a "Worked Templates" section containing illustrative synthetic examples (clearly labeled as such) and an intentionally-empty "Case Studies" section. Real case studies accumulate as incidents occur, following the six-field schema and gatekeeping rule.

**Alternatives considered:** (1) Recall 2-3 real integration-tracking incidents from past Ghost project work to seed Case Studies with real content at launch (strict gatekeeping conformance, requires archaeological work). (2) Label worked examples as Case Studies and ignore the hypotheticals-banned rule for launch.

**Rationale:** Option 1 would have required finding sourceable incidents, but no real incidents existed yet for integration-tracking specifically — the whole point of the discipline is prevention. Option 2 would have violated the gatekeeping rule from the start, establishing precedent that the rule can be waived. The chosen path preserves gatekeeping purity: templates teach mechanics without claiming to be institutional memory; the empty Case Studies section signals "this is reserved for real incidents." Users read template content knowing it's not case-study-grade evidence.

---

### <devlog:2026-04-22:helpers-as-separate-runnable-files>

**Context:** V5.0 Phase 4b drafting decision for the drift-detection helpers. Two questions: (1) Should helper scripts live inline in `reference/integration-tracking.md` as fenced code blocks, or as runnable files in a subdirectory? (2) If files, where do they go in the skill structure?

**Decision:** Helper scripts as separate runnable files at `reference/integration-helpers/verify-integrations.ps1` and `.sh`, not inline in the reference file.

**Alternatives considered:** Inline in the reference file as fenced code blocks — simpler grep target, one-file mental model.

**Rationale:** Runnable-by-default beats copy-paste-then-run. A user encountering drift would need to extract the helper from markdown before running it — that friction guarantees underuse. Real script files can be invoked directly, edited as scripts (not as fenced markdown), and maintained with normal tooling. The context-budget argument also applies: loading `integration-tracking.md` should pay for the protocol and invariants, not for ~250 lines of bash/powershell a reader doesn't need in-context to reason about integration tracking. The precedent matches the V4_4 → V4_5 log-vocabulary hoist — load-on-demand content stays out of the per-session context tax.

**See also:** `<devlog:2026-04-22:log-vocabulary-hoist>` (the earlier precedent for hoisting load-on-demand content).

---

### <devlog:2026-04-22:v5-major-version-bump>

**Context:** V5.0 Phase 3 finding. The skill's own versioning convention in `SKILL.md § How This Skill Evolves` states: "Major number increments for structural reorganizations or new reference files; minor number increments for content additions." The integration-tracking addition had initially been planned as V4.8, treating it as a content addition.

**Decision:** V4.7 → V5.0, not V4.8. The addition of `reference/integration-tracking.md` plus the `reference/integration-helpers/` directory is a structural addition crossing the major-version threshold per the skill's own rule.

**Alternatives considered:** V4.8 — treat the addition as content-only under the interpretation that a new reference file is a content addition.

**Rationale:** Conformance to the skill's own versioning rule is load-bearing for the versioning system's integrity. The rule exists to make version numbers legible — a major bump signals structural change worth re-reading; a minor bump signals content addition. Calling a new reference file "content" would erode the distinction and make future version numbers less informative. The rule is the discriminator; applying it correctly to V5.0 is what keeps the rule useful for V6.0 and beyond.

---

### <devlog:2026-04-22:three-drift-directions>

**Context:** V5.0 Phase 4b drafting. The initial `integration-tracking.md` design called out two drift directions in its Drift Defenses section — code-ahead-of-map and map-ahead-of-code. While implementing `verify-integrations.sh`, a third category emerged organically: consumers referencing a contract by an outdated `version=` number.

**Decision:** Recognize and document three drift directions: code-ahead-of-map, map-ahead-of-code, and version-mismatch. Update `integration-tracking.md`'s Drift Defenses and Integration Grep Protocol sections to cover all three.

**Alternatives considered:** (1) Remove version-mismatch from the helpers (treat as out-of-scope for V5.0). (2) Leave the reference at two directions and document the third only in the helpers.

**Rationale:** The three-direction structure captures distinct failure modes that require different resolutions. Code-ahead-of-map means the map needs updating; map-ahead-of-code means the map needs cleanup; version-mismatch means a consumer needs updating to the new contract version. Reducing to two would lose that clarity. Leaving documentation at two while implementing three would create exactly the documentation drift the skill works to prevent — the same failure mode Lesson L2 teaches applied to my own drafting. Reconciliation was a small update (~20 lines) and made the helpers' behavior match their stated protocol.

**See also:** `reference/integration-tracking.md § Drift Defenses § The Three Drift Directions`; `<lesson:2026-04-22:format-drift-in-self-authored-patches>`.

---

### <devlog:2026-04-22:drift-expected-global-scope>

**Context:** V5.0 Phase 4b drafting of the DRIFT-EXPECTED escape hatch. During a multi-commit refactor, contracts and map may intentionally be out of sync until the final commit reconciles them. A mechanism was needed to downgrade drift findings from ERROR to WARN during the refactor window.

**Decision:** `# DRIFT-EXPECTED: reason` as the first line of `.integration-map.md` downgrades all drift findings in the run. Global per-run scope, not per-contract.

**Alternatives considered:** Per-contract scoping — each drift-expected contract gets its own annotation, allowing strict checks to continue on other contracts while a specific one is being refactored.

**Rationale:** Global scope is simpler and fits the most common refactor pattern — a single coordinated change touching multiple contracts at once. Per-contract scoping would require more ceremony (one annotation per in-progress contract) and introduce more surface for drift within the drift-management mechanism itself. Global scope is the right V5.0 default; per-contract can be added in a future version if operational experience reveals the need. The decision explicitly accepts that global DRIFT-EXPECTED means strict checks are disabled for *all* contracts during the window — the reason-text in the annotation is the discipline that makes users own the trade-off.

---

## V5.0 — Integration Tracking (delivery)

### <devlog:2026-04-22:powershell-helper-ships-unverified>

**Context:** V5.0 Phase 4d end-to-end verification. `verify-integrations.sh` was runtime-verified against a 10-test regression suite (and caught one real bug — the empty-associative-array issue). `verify-integrations.ps1` could not be runtime-verified because no PowerShell runtime was available in the drafting environment.

**Decision:** Ship `verify-integrations.ps1` with V5.0 in "static-reviewed, not runtime-verified" state. Document the verification gap explicitly in the V5.0 bundle README as a residual task, with a suggested 10-test regression plan mirroring the Bash verification.

**Alternatives considered:** (1) Skip Phase 4d entirely and ship both helpers unverified. (2) Delay V5.0 until a PowerShell runtime could be obtained for verification. (3) Ship only the Bash helper and defer PowerShell to V5.0.1.

**Rationale:** Option 1 would have shipped the empty-associative-array bug that Phase 4d caught on Bash. Option 2 would have blocked V5.0 indefinitely on environmental circumstance rather than on content readiness. Option 3 would have deprived PowerShell users of the helper until V5.0.1. The chosen path ships value while being honest about the verification gap — the README names exactly what wasn't verified, what residual risk that carries, and provides the test plan. The PowerShell helper's structure mirrors the Bash helper's closely, so runtime verification is expected to pass; the decision is transparent that "expected" here means "unverified."

**See also:** `<lesson:2026-04-22:verification-applies-at-skill-level>` (the bar this decision fell short of).

---

## V5.0 → V5.1 transition

### <devlog:2026-04-22:dev-log-deferred-to-v5-1>

**Context:** During V5.0 Phase 4 drafting, Ghost proposed adding a `skill_development/` directory to capture dev logs and lessons learned from the V5.0 design cycle. The proposal was solid — architectural precedent existed, the need for cross-session institutional memory was real, the shape of the content was well-defined.

**Decision:** Defer `skill_development/` from V5.0 to V5.1 as its own release. V5.0 ships focused on integration tracking; V5.1 ships focused on institutional memory.

**Alternatives considered:** Include `skill_development/` in V5.0 — one release, two related-but-distinct additions.

**Rationale:** Conceptual coherence. V5.0's coherent story is "scripting-standards now tracks integration contracts." Adding a dev log is a different kind of addition — about how the skill develops itself, not about what the skill does for users. A version with two headlines dilutes both. Quality of seed content also favored deferral: producing high-quality retroactive dev log entries requires real archaeological work through existing references, which would have rushed the dev log's launch while V5.0 was trying to ship. Deferring let V5.0 itself become genuinely useful primary source material for V5.1 (the V5.0 design conversation became real seed content for this log).

**See also:** `<devlog:2026-04-22:v5-0-1-scope-split>` (the later sibling decision applying the same principle).

---

### <devlog:2026-04-22:v5-0-1-scope-split>

**Context:** During V5.1 Phase 1 content inventory, Ghost raised the question of whether grep performance improvements should be part of V5.1. Investigation distinguished two levels of "grep-first improvements": tactical (ripgrep, `-F`, `--exclude-dir` — ~30-50 line additions to existing content) and strategic (full Grep-First formalization as a general cross-cutting protocol — a major design cycle with its own reference file and helper extensions).

**Decision:** Three-version split. V5.0.1 ships the tactical wins now as a patch to V5.0 (closing the V5.0 story). V5.1 ships the dev log and lessons as originally planned (unchanged scope). V5.2 ships the full Grep-First formalization as its own major release with an independent design cycle.

**Alternatives considered:** (1) Combine tactical and strategic into V5.1. (2) Defer both tactical and strategic to V5.2 and ship V5.1 unchanged. (3) V5.1 gets the tactical wins plus the dev log; V5.2 is Grep-First only.

**Rationale:** Same one-headline-per-version discipline that justified deferring the dev log from V5.0. Each version gets a single coherent story. V5.0.1 as a patch-level release keeps V5.0's integration-tracking story clean; V5.1 as a documentation release keeps the institutional-memory story clean; V5.2 as a major release gives Grep-First its own design cycle rather than shaping it by whatever other release it was bolted onto. The sequencing also matters operationally — V5.1's dev log provides somewhere for V5.2's decision trail to land in real time. Without V5.1 first, V5.2's dev log entries would need retroactive capture afterward.

**See also:** `<devlog:2026-04-22:dev-log-deferred-to-v5-1>` (the earlier sibling decision).

---

## Retroactive entries (pre-V5.0 history)

### <devlog:2026-04-22:log-vocabulary-hoist>

**Context:** During V4_4, the full 25-row log prefix table lived inside `SKILL.md`, loading on every session regardless of whether log auditing was the session's task. Captured retroactively from `reference/log_vocabulary.md` closing section titled "Why This File Exists Separately from SKILL.md," which documents the state and the reason for the change in its own closing paragraph.

**Decision:** Hoist the full log prefix table out of `SKILL.md` into a dedicated `reference/log_vocabulary.md` file. Keep ~8 core prefixes in `SKILL.md`; move the full table plus grep patterns, format contract, and extension rules to the reference file. Load on demand.

**Alternatives considered:** Retain the full table in `SKILL.md` on the grounds of single-source referenceability.

**Rationale:** Context-budget discipline. A session that loads every reference up front has wasted significant context before writing a line of code. Most of the 25 prefixes are emitted automatically by log helpers — the full table is reference material for auditors, not a rule every session needs to internalize. Keeping only the core lifecycle prefixes (`SCRIPT_START`, `UNIT_START`, etc.) in `SKILL.md` communicates the vocabulary's shape without paying the per-session tax for the full table. This decision established the pattern: structural orchestration in `SKILL.md`; detailed reference content in `reference/` files loaded on demand.

**See also:** `<devlog:2026-04-22:helpers-as-separate-runnable-files>` (the V5.0 decision that applied this precedent).

---

### <devlog:2026-04-22:end-to-end-verification-discipline>

**Context:** V4_5 development phase. Sources: `reference/minimal_scripts.md` opening note ("All three scaffolds in this file were run end-to-end during V4_5 authorship — dry-run, normal, debug, and missing-input paths"); Verification History sections at the bottom of `reference/powershell.md` and `reference/python.md` documenting specific bugs caught during this verification pass. Before V4_5, the skill had been authored via static review — content reviewed for correctness, but scripts not necessarily executed end-to-end.

**Decision:** Adopt end-to-end execution of scaffolds and templates as part of the authoring protocol. Document bugs caught during verification in each language reference's Verification History section, so future editors see the specific failures that motivated each fix.

**Alternatives considered:** Continue with static review only, relying on authorial correctness and reader-reported issues.

**Rationale:** Bugs that pass static review but fail at runtime are common in scripts — cross-platform environment variable differences, error-handling edge cases, log-ordering issues. Without runtime exposure, these ship. The Verification History sections created by V4_5 document three concrete examples in the PowerShell reference alone (Windows-only env vars, `Initialize-Script` ordering, `$_` stringification in catch blocks) — all caught by executing the scaffold, none visible from reading it. The discipline is expensive (actual runs, actual test data) but the catch rate justifies the cost. This decision established the pattern that V5.0's Phase 4d later applied to helper scripts shipping as part of the skill.

**See also:** `<lesson:2026-04-22:verification-applies-at-skill-level>` (the V5.0-era extension of this discipline to skill-own tooling).

---

### <devlog:2026-04-22:stack-trace-cross-language-substitution>

**Context:** During vocabulary definition for the log prefix system (likely V4_4 or earlier — the exact phase is not documented in the current sources). Sources: `reference/log_vocabulary.md` full prefix table (see the `STACK_TRACE` row and its substitution note); `reference/log_vocabulary.md § Extending the Vocabulary § rule 6` ("Document cross-language substitutions"); `reference/bash.md § Verification History § Extension rule — STACK_TRACE has no Bash equivalent." The question arose because `STACK_TRACE` captures a call-stack trace — Python and PowerShell have native mechanisms (`traceback.format_exc()`, `$_.ScriptStackTrace`); Bash does not.

**Decision:** Document the cross-language asymmetry explicitly rather than pretending all three languages implement the prefix identically. Bash substitutes `$LINENO` + `$BASH_COMMAND` from the ERR trap; the `log_vocabulary.md` prefix table carries the substitution note inline; the extension-rules section formalizes the pattern as a general policy for any future prefix that cannot be implemented uniformly.

**Alternatives considered:** (1) Force Bash to approximate stack traces with shell-function gymnastics (walking `BASH_LINENO` and `FUNCNAME` arrays). (2) Remove `STACK_TRACE` from the vocabulary entirely since it can't be uniform.

**Rationale:** Option 1 produces fragile, complex code that approximates a feature Bash legitimately lacks. Option 2 loses a valuable diagnostic prefix for Python and PowerShell, where it works naturally. The chosen path acknowledges the language difference honestly, documents the substitution, and preserves a triage-greppable prefix that works in its native languages with a documented variant for Bash. The precedent generalizes: any future prefix that cannot be implemented uniformly follows the same pattern — document the substitution, don't pretend uniformity.

---

### <devlog:2026-04-22:idempotency-rule-dual-placement>

**Context:** When the `Invoke-WithRetry` / `invoke_with_retry` helpers were added to the language references, the Idempotency Rule needed a home. The helper documentation needed to warn against retry-unsafe operations (POST /charges, POST /send-email, POST /webhook); the top-level skill needed to establish the retry discipline. The question was whether the rule should live in both places or one. Sources: `SKILL.md § Retry Logic for Transient Failures § Idempotency Rule`; language reference helper comment blocks for `Invoke-WithRetry` / `invoke_with_retry`; `SKILL.md § How This Skill Evolves § Worked Example — Adding a New Rule` (the closing paragraph that formalized the dual-placement pattern).

**Decision:** Safety-critical rules appear in two places — at the decision point (SKILL.md, where "should I use retry?" gets asked) and at the implementation site (language reference helper comments, where "am I using retry correctly?" gets asked). Establish this as a named pattern for any future safety-critical rule.

**Alternatives considered:** (1) Single-location in `SKILL.md` only, relying on developers to cross-reference when implementing. (2) Single-location in the language reference helper comment, relying on "read the helper before calling it."

**Rationale:** For safety-critical rules, missing the check at the implementation site produces a production incident, not a documentation gap. A retry wrapper that doubles payments or sends duplicate emails is worse than no retry at all. Single-location placement would require every session using the helper to have also read the top-level skill — a burden that silently fails for new sessions and re-entry sessions. Dual placement ensures the rule is visible at the moment of use. The decision also explicitly names the exception: dual placement is correct *only* for safety-critical rules. Non-safety rules follow the general "duplicate rules drift" principle and stay single-location. The discriminator is failure cost.

**See also:** `<lesson:2026-04-22:safety-critical-duplication-pattern>` (the general rule this decision codified).

---

## V5.2 — Grep-First

### <devlog:2026-04-22:v5-2-coverage-breadth>

**Context:** V5.2 Phase 1 Round 1, Q1. Handoff surfaced coverage breadth as open — all 9 shared-textual-element categories at launch, or a subset with remainder deferred to V5.3+.

**Decision:** Full 9-category coverage at V5.2 launch.

**Alternatives considered:** Narrower subset (error codes + log prefixes + config keys at V5.2; others V5.3+).

**Rationale:** Grep-First's value is uniformity of discipline across categories. A subset launch creates a two-tier protocol — some categories disciplined, others not — undermining the conceptual completeness that justifies the protocol's existence. Scale cost is bounded (line-count ballpark ≥IT's 743); the alternative is deferred value plus an awkward "partial Grep-First" state bridging V5.2 and V5.3.

---

### <devlog:2026-04-22:v5-2-rg-preferred-posture>

**Context:** V5.2 Phase 1 Round 1, Q2 + Q2 sub-question. V5.0.1 had established grep-portable with rg as documented alternative. V5.2 needed to choose tool posture — retain, flip, or go agnostic — and if flipped, V5.2-scoped or skill-wide.

**Decision:** rg preferred + grep as portable fallback, V5.2-scoped. `grep_first.md` and its examples lead with rg. V5.0.1 helpers and any future V5.2 helpers retain grep-portability as locked invariant.

**Alternatives considered:** (1) Continue V5.0.1 posture unchanged. (2) Tool-agnostic with per-tool performance guidance. (3) Skill-wide flip to rg-first (would re-open V5.0.1 portability invariant).

**Rationale:** rg is materially better for Grep-First's workflow — 2–10x faster, .gitignore-aware, type filters align with the protocol's category framing. Authoring V5.2 examples rg-first centers reader attention on the right tool. V5.2-scoping the flip preserves V5.0.1's portability invariant for helpers — portability matters most for shipped tooling; docs can lead with the better tool without breaking cross-environment compatibility. Split is explicit to prevent silent propagation skill-wide.

---

### <devlog:2026-04-22:v5-2-light-umbrella-framing>

**Context:** V5.2 Phase 1 Round 1, Q3. `<devlog:2026-04-22:integration-grep-protocol-self-contained>` locked IT's protocol body against absorption or rewrite. V5.2 needed to choose how Grep-First relates to IT.

**Decision:** Light umbrella (Position B). Grep-First framed as general protocol in a new SKILL.md section peer to "Integration Tracking." The new section names IT as "the most-developed specialization of this protocol." `integration-tracking.md` is literally untouched. Cross-reference asymmetry (Grep-First names IT; IT does not name Grep-First in V5.2) accepted as honest cost of honoring both letter and spirit of the locked IT-self-contained decision.

**Alternatives considered:** (A) Strong umbrella — SKILL.md restructures; IT gains a new opening paragraph positioning itself as a specialization. (C) Pure peer — no umbrella framing; bidirectional see-also only.

**Rationale:** Position A preserves the letter but bends the spirit — IT would be retroactively reframed as a specialization it was explicitly not designed to be. L3's warning about assumed-but-unspecified dependencies has a symmetric form: don't retroactively reshape content that shipped self-contained to conform to a parent that didn't exist when it shipped. Position C forgoes unifying conceptual framing across future specializations. Position B honors both letter and spirit while still giving future specializations a named parent. Cross-reference asymmetry is recoverable at any future natural edit cycle of IT — likely when IT's empty Case Studies receives its first real incident.

**See also:** `<devlog:2026-04-22:integration-grep-protocol-self-contained>` (the locked decision this choice honors); `<lesson:2026-04-22:grep-first-assumed-but-unspecified>` (the symmetric-form argument applied here).

---

### <devlog:2026-04-22:v5-2-no-helper-at-launch>

**Context:** V5.2 Phase 1 Round 2, Q4. V5.0 precedent and V5.0.1's tactical wins had made "some helper at V5.2" seem the default option. Ghost surfaced a constraint not in the original framing: V5.2's protocol is new and will iterate — a helper at ship pays coupling cost continuously through iteration, not once.

**Decision:** No runnable helper ships with V5.2 (Position α). `grep_first.md` designed as copy-paste-friendly reference. Helpers defer to V5.3+ driven by real usage patterns.

**Alternatives considered:** (β) Light pre-rename enumerator — rg-first, ~100-150 lines, covers step 1 of workflow. (γ) Canonical pattern runner — helper implementation is the pattern library's executable form, continuous consistency check against `grep_first.md` patterns. (δ) Rich multi-mode tool — subcommands for enumerate, verify-rename, list-patterns.

**Rationale:** Helpers encode stable spec, not iterating spec. V5.0's helpers verified a spec that had stabilized by end of Phase 4b; V5.2's spec will be at the start of iteration at ship. Under iteration, γ's apparent L2 alignment (helper-as-consistency-check) inverts — the helper-pattern coupling becomes a drift surface that every iteration exercises, which is the same failure mode L2 warns against on the example axis. α minimizes coupling, preserves iteration signal (copy-paste friction across 9 categories surfaces which queries need tooling), and is asymmetrically reversible — α → β/γ at V5.3+ is natural extension; reverse would be regression. Honest prior-framing correction: initial analysis framed γ as "most L2-aligned" which was correct under stability assumptions and wrong under iteration assumptions.

**See also:** `<lesson:2026-04-22:format-drift-in-self-authored-patches>` (the L2 failure mode whose helper-axis variant justifies α); `<devlog:2026-04-22:illustrative-templates-launch>` (V5.0 precedent for shipping light-at-first and letting usage shape additions).

---

### <devlog:2026-04-22:v5-2-templates-only-launch-applies-precedent>

**Context:** V5.2 Phase 1 Round 2, Q5. `<devlog:2026-04-22:illustrative-templates-launch>` established V5.0 precedent of synthetic templates + empty Case Studies, accumulating real incidents over time. V5.2's 9-category breadth made "seed case studies for a subset" a genuine option.

**Decision:** Apply the V5.0 precedent to V5.2 unchanged. Templates-only launch; empty Case Studies per category; real incidents accumulate.

**Alternatives considered:** Partial real incidents — Ghost has informal Grep-First application history in prior project work and could seed case studies for some categories while templates cover the rest.

**Rationale:** Declining to source retroactive case studies preserves the gatekeeping purity V5.0 established. Same reasoning as `<devlog:2026-04-22:illustrative-templates-launch>` applies here unchanged.

---

### <devlog:2026-04-22:v5-2-formal-invariants-over-workflow-guidance>

**Context:** V5.2 Phase 2 Round 1, A1. Whether V5.2's new reference file introduces formal grep-stable invariants (analogous to IT's I1-I6) or stays workflow-focused with pattern examples as guidance.

**Decision:** Formal invariants G1-Gn per category, applying IT-style rigor to Grep-First. Each category has a versioned invariant with canonical grep pattern, attributes, and format contract discipline.

**Alternatives considered:** (1) Workflow-focused guidance — query patterns as non-versioned examples that iterate freely. (2) Mixed — invariants for high-risk categories (function names, constants), guidance for softer ones (config keys, paths).

**Rationale:** Formal invariants give V5.2 vocabulary integrity matching V5.0's I1-I6 precedent, and provide a stable spec that V5.3+ helpers can target when usage patterns justify tooling. L2 discipline (grep-test examples against their pattern before shipping) applies naturally to versioned invariants. Initial Phase 2 Round 1 framing pushed toward workflow-focused on iteration-cost grounds; on reflection, Q4's coupling argument targeted runtime tooling specifically, not documented invariants. Formal invariants without runtime tooling iterate via deliberate version bumps (authoring-time discipline) — a different risk profile from runtime-coupled helpers. Honest prior-framing correction: Round 1 opening throughline slightly overreached by implying invariants carry the same iteration cost as helpers. They don't.

**See also:** `<devlog:2026-04-22:v5-2-no-helper-at-launch>` (the runtime-coupling concern the prior framing conflated with authoring-time discipline); `<lesson:2026-04-22:format-drift-in-self-authored-patches>` (the L2 discipline formal invariants invoke).

---

### <devlog:2026-04-22:v5-2-five-step-numbered-protocol>

**Context:** V5.2 Phase 2 Round 1, A2. Under A1 formal invariants, the Grep-First protocol's shape: mirror IT's 11-step Change Impact Protocol, or adopt a lighter rule + workflow description?

**Decision:** Numbered protocol with approximately 5 steps: grep → classify → resolve UNCLEAR → change → grep-verify. Parallel to IT's Change Impact Protocol but lighter by design.

**Alternatives considered:** Rule + workflow description without numbered steps.

**Rationale:** IT's 11 steps exist because IT has stateful artifacts (`.integration-map.md`, versioned contracts, tiered enforcement gates) that require explicit maintenance operations. Grep-First has no such artifacts — no map, no versioned contracts at the protocol level — so several of IT's steps don't apply. A 5-step form gives readers the same cognitive scaffolding IT provides without inventing ceremony for artifacts that don't exist. Unnumbered alternative loses the scaffolding readers use to orient across the skill's two protocols; readers navigating from IT's 11-step protocol to Grep-First's unnumbered protocol would face inconsistent conceptual shape for the same class of discipline.

**Outcome:** During V5.2 Phase 4a drafting, step 3 was specified as not supporting advisory-tier enforcement (unlike IT's `scope="public"`/`"internal"` distinction). This was a legitimate extension of the locked decision — Grep-First operates at raw textual elements with no scope attribute to key a tier off — but it is an implementation-level elaboration rather than a reversal. Captured here rather than as a separate dev log entry because it is a consequence of the 5-step protocol's existence below IT's contract layer, not a new architectural decision.

---

### <devlog:2026-04-22:v5-2-tiered-uniformity-per-category>

**Context:** V5.2 Phase 2 Round 1, A3. Under A1 formal invariants, the 9 category invariants needed a structural uniformity decision.

**Decision:** Tiered uniformity. Uniform base per category (canonical pattern, collision-risk note, worked template, empty Case Studies). Optional extensions applied per-category as real variance warrants (per-language notes, cross-language substitution notes, false-positive guidance).

**Alternatives considered:** (1) Full uniformity — identical sub-structure across all 9 categories, extensions required even where awkward. (2) Per-category variance — each invariant defines its own shape.

**Rationale:** Matches V5.0 I1-I6 precedent. IT's invariants are not structurally identical — I1 is a multi-line block opening, I2 a closing tag, I3 a single-line marker, I4-I6 are different markdown/list forms. They share "grep-stable textual format" but differ per the artifact they define. Tiered uniformity within a formal vocabulary IS the V5.0 pattern. Full uniformity overstates categories' similarity (file paths don't need per-language notes the way function names do); per-category variance undermines the vocabulary's closure.

**See also:** `reference/integration-tracking.md § Format Contract § Invariants I1-I6` (V5.0 precedent); `<devlog:2026-04-22:stack-trace-cross-language-substitution>` (cross-language substitution pattern invoked by optional extensions).

---

### <devlog:2026-04-22:v5-2-section-structure-grouped-by-grep-friendliness>

**Context:** V5.2 Phase 2 Round 2, A4. `grep_first.md` needed a top-level section structure under A1-A3 locked. Three related sub-decisions: section count and order; whether worked templates fold into per-category sections or live as a separate top-level section (IT precedent); per-category organization alphabetical vs. grouped by grep-friendliness.

**Decision:** 8-section structure (Opening → Problem → Invariant Shape → Protocol → Per-Category Invariants → Relationship to IT → Extending Vocabulary → How to Add Case Study). Worked templates folded into each per-category sub-section as part of the tiered-uniformity base (not a separate top-level section). Per-category organization by grep-friendliness groups (high: error codes + log prefixes; medium: config keys + API endpoints + env vars; low: constants + function/class names + type definitions + file paths).

**Alternatives considered:** (1) Separate "Worked Templates" top-level section mirroring IT's precedent — preserves parallel structure with IT at the cost of breaking per-category coherence. (2) Alphabetical per-category ordering — familiar scanning pattern, hides the structural asymmetry tiered uniformity makes explicit.

**Rationale:** Templates folded per-category preserves category coherence — invariant + collision note + template + empty Case Studies form one scannable unit per category. IT's precedent doesn't apply cleanly because IT's three templates demonstrate protocol application across distinct failure modes, not per-invariant application. Grouping by grep-friendliness mirrors the tiered-uniformity structure — high-group categories share minimal extensions; medium-group share moderate extensions; low-group share heavy extensions. Alphabetical interleaves categories with different extension profiles, hiding the pattern that justifies tiered uniformity.

---

### <devlog:2026-04-22:v5-2-skill-md-section-before-integration-tracking>

**Context:** V5.2 Phase 2 Round 2, A5. Under Q3 Position B (light umbrella), the new "Grep-First Protocol" section in SKILL.md is peer to the existing "Integration Tracking" section. Placement question.

**Decision:** Place new "Grep-First Protocol" section immediately before "Integration Tracking." Size ~25 lines mirroring IT's SKILL.md structure. New row in "How This Skill Is Organized" table for `grep_first.md`.

**Alternatives considered:** Place new section immediately after "Integration Tracking" — frames V5.2 as a new addition to an existing skill rather than as the general protocol IT specializes.

**Rationale:** Placing Grep-First before IT gives a top-to-bottom reader the correct mental model — general protocol first, specialization second. A reader encountering Grep-First first builds the umbrella framing naturally. The "after IT" alternative is more honest about V5.2 being new content added to a skill where IT already existed, but produces weaker pedagogical order for new readers. Under Q3 Position B, the light umbrella is named one-directionally; placing before IT makes the naming read as structural rather than retroactive.

---

### <devlog:2026-04-22:v5-2-cross-reference-language-no-meta-commentary>

**Context:** V5.2 Phase 2 Round 2, A6. Q3 Position B's cross-reference asymmetry raised a wording question: does `grep_first.md` explain *why* the asymmetry exists, or implement it silently?

**Decision:** `grep_first.md` implements the umbrella framing in its opening paragraph (brief mention) and section 6 (full framing). Neither location explains the V5.2 design rationale for why IT doesn't back-reference — that explanation lives in the dev log entry for Q3, not the reference file.

**Alternatives considered:** Add a paragraph in section 6 explaining the design choice and pointing to the future natural IT edit as the place a back-reference would be added.

**Rationale:** Meta-commentary about design choices in a reference file breaks the skill's rule-and-why voice. `<lesson:2026-04-22:voice-drift-across-session-boundaries>` warns about register degradation across sessions; design-rationale prose in a reference file is a register shift that erodes voice consistency. Reference files ship the architecture; dev log entries carry the design rationale. Readers who notice the asymmetry and want to know why can consult the dev log — the skill's architecture intentionally separates these concerns.

---

### <devlog:2026-04-22:v5-2-decision-index-placement-and-flat-structure>

**Context:** V5.2 Phase 2 Round 3, A7. Adding V5.2 entries to `developer_log/README.md` Decision Index raised two related questions: where does the new section go (A7a), and does it use phased sub-sections from the start (A7b)?

**Decision:** Place "V5.2 — Grep-First" section between "V5.0 → V5.1 transition" and "Retroactive entries" in the Decision Index. Flat chronological entry listing initially — restructure to phased sub-sections at Phase 4f if entry volume warrants (rough threshold: > 12 entries).

**Alternatives considered:** (A7a alt) Place V5.2 section after "Retroactive entries" — simpler append now, produces a forward-extension problem for V5.3+. (A7b alt) Phased sub-sections from the start (design / delivery split mirroring V5.0) — pays structural cost from entry #1 before knowing if volume warrants it; requires per-entry phase categorization as a judgment-call drift surface.

**Rationale:** Placement — between transition and retroactive establishes a pattern that composes forward (V5.3 inserts after V5.2 and before retroactive, preserving retroactive-at-tail invariant). Placing V5.2 after retroactive defers the forward-extension problem without solving it. Structure — V5.0's design/delivery split worked retrospectively because phase membership was clear in hindsight; V5.2 captures in real-time and per-entry phase categorization is a judgment call that drifts. Flat structure has one authoring target and low drift surface; flat composes forward to phased losslessly, but phased doesn't compose backward cleanly if the initial split is wrong. Defer the restructure cost until volume justifies it.

---

## V5.3 — Automated L2 Enforcement

### <devlog:2026-04-23:v5-3-headline-automated-l2-enforcement>

**Context:** V5.3 Phase 1 Q1. V5.2 handoff presented V5.3 as scope-open with four named candidates (A: pre-rename enumerator; B: case-study capture workflow; C: map-side drift detection; D: automated L2 enforcement) plus combination or reframe options.

**Decision:** D — Automated L2 enforcement — as V5.3's single coherent story.

**Alternatives considered:** A (Grep-First rename helper, deferred from V5.2 at launch), B (process workflow for case-study authoring, no mechanical enforcement), C (map-side version-drift gap closure in integration-tracking), V5.3+V5.4 split pairing D with a lighter second candidate, a direction not among A–D.

**Rationale:** V5.2 Phase 4c hit a CRLF variant of the L2 grep-test failure mode while authoring its own content; the incident produced `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>`. The run-when-remembered discipline guarantees recurrence across future authoring cycles. D is the only candidate that directly closes a known-active failure mode rather than deferring a future possibility (A, C) or adding optional process structure (B). Selecting D also preserves the single-headline-per-version discipline — A/B/C are orthogonal concerns queued as V5.4 seeds.

---

### <devlog:2026-04-23:v5-3-coverage-both-protocols>

**Context:** V5.3 Phase 1 Round 1. With D as headline, the harness's formal input set required scoping across the skill's grep-anchored format contracts.

**Decision:** G1–G9 + I1–I6. 12 worked templates checked against 15 invariant definitions at V5.3 launch. The formal "L2-covered invariant set" is defined and versioned per the V5.2 Section 3 Governance Rule precedent.

**Alternatives considered:** (a) G1–G9 only (narrow, V5.2 additions exclusively); (c) G1–G9 + I1–I6 + `<devlog:>`/`<lesson:>` anchors in `skill_development/` (wide, implicit L2-covered content).

**Rationale:** Uniformity of discipline across both currently-documented grep-anchored protocol families. "Some grep-anchored contracts enforced, others not" is the exact gap D exists to prevent — a two-tier enforcement posture replicates the run-when-remembered problem at the vocabulary layer. Parallels V5.2's full-9-category uniformity argument. (a) leaves a known gap D is named to close; (c) folds in anchors that weren't authored against explicit L2-visible format contracts and risks shipping D with coverage that implicitly requires rewriting parts of `skill_development/` first — a V5.4+ extension once (b) stabilizes.

---

### <devlog:2026-04-23:v5-3-execution-model-pre-commit>

**Context:** V5.3 Phase 1 Round 2. D's mechanical enforcement required an execution surface.

**Decision:** Pre-commit hook. Local git hook invokes the bash harness on `git commit`. `--no-verify` bypass is the explicit author-opt-out boundary per V5.0's opt-in pattern.

**Alternatives considered:** (ii) CI integration (block-on-merge, slower feedback, requires repo-hosted skill); (iii) both pre-commit + CI (defense in depth, doubles implementation surface); (iv) standalone harness + documented integration pattern (ships the tool, author wires; redefines D from enforcement to check).

**Rationale:** Pre-commit is the locus closest to authoring — failures surface at `git commit`, aligned with the established git-commit-before-sessions habit. (iii) doubles V5.3 surface and introduces a test-matrix cost (verifying both paths behave identically on the same failure modes). (ii) is a legitimate V5.4+ extension once (i) proves stable. (iv) reclassifies D back to authorial discipline, which undermines the candidate's stated intent and would be a Q1-level re-scoping rather than a Round 2 decision.

---

### <devlog:2026-04-23:v5-3-harness-language-bash-only>

**Context:** V5.3 Phase 1 Round 3. D's harness language scope question under the pre-commit execution model.

**Decision:** Bash only. Pre-commit hook wrapper and L2 harness both implemented in bash. Runtime-verifiable in the drafting environment via V5.0's Bash verification pattern.

**Alternatives considered:** (b) Bash hook + Python harness via `pre-commit.com` framework — Python regex handles CRLF word-boundaries natively by construction, cross-platform dependency management, adds framework surface. (c) Bash + PowerShell dual-language mirroring V5.0's helper pattern — cross-language parity, compounds the V5.0 PowerShell unverified residual.

**Rationale:** (a) matches `verify-integrations.sh` precedent, remains grep-portable per V5.0.1/V5.2 locked invariants, is runtime-verifiable in the drafting environment, and carries zero new dependencies. (b) is compelling on the CRLF-by-construction argument but adds framework surface disproportionate to V5.3's small headline — Python's word-boundary advantage is addressable via bash `tr -d '\r'` pre-normalization per `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>`. (c) is locked out by the handoff's explicit guidance against compounding the V5.0 PowerShell residual — the same environmental constraint that blocks PS verification at V5.2 remains active; Q5 default (residual stays deferred) would be reversed by (c).

---

### <devlog:2026-04-23:v5-3-topology-two-files>

**Context:** V5.3 Phase 2 Round 1, A1. Enforcement infrastructure needed a file-count decision — single combined, two-file hook + harness, or three-file split extracting registry.

**Decision:** Two files. Minimal pre-commit hook wrapper invokes a standalone L2 harness.

**Alternatives considered:** (T1) Single bash file with inline hook + harness — loses testability; (T3) Three files separating hook, harness, and registry — premature registry split at 15 entries.

**Rationale:** Matches `<devlog:2026-04-22:helpers-as-separate-runnable-files>` precedent. Runnable-by-default beats copy-paste-then-run; a standalone harness enables regression verification without duplicating hook state. (T3) is an honest V5.4+ direction once registry exceeds ~20 entries, but pays the split cost prematurely at 15.

---

### <devlog:2026-04-23:v5-3-location-authoring-helpers-subdirectory>

**Context:** V5.3 Phase 2 Round 1, A2. D as skill-development infrastructure needed a location respecting the V5.1-established boundary between `reference/` (user-facing) and `skill_development/` (skill-evolution memory).

**Decision:** New subdirectory `skill_development/authoring-helpers/`, parallel to `developer_log/` and `lessons_learned/`.

**Alternatives considered:** (L2) `.githooks/` at skill root — splits V5.3 across two trees; (L3) `tools/` at skill root — less specific, invites future scope creep; (L4) `reference/integration-helpers/` — architecturally incorrect because it conflates user-facing references with skill-authoring infrastructure.

**Rationale:** The `skill_development/` tree exists precisely for skill-evolution content. Authoring infrastructure lives alongside authoring memory (developer log, lessons learned). This preserves the V5.1 architectural boundary and establishes a canonical home for future authoring helpers (V5.4+ rename helper, case-study capture scaffolding, etc.).

---

### <devlog:2026-04-23:v5-3-registry-inline-bash-array>

**Context:** V5.3 Phase 2 Round 1, A3. The 15-entry L2-covered invariant set needed a representation.

**Decision:** Inline bash associative array in the harness, keyed by invariant ID, mapping to (canonical pattern, worked-template file).

**Alternatives considered:** (R2) Separate manifest file (e.g., `l2-registry.tsv`) parsed by the harness — explicit governance surface, parsing cost; (R3) Extend G1–G9 / I1–I6 invariant definitions in the reference files with L2-enforcement metadata — reverses V5.2's IT-untouched lock.

**Rationale:** Simplest surface at 15 entries. (R2) is a natural V5.4+ direction if registry grows past ~20 or external tooling needs to consume it. (R3) rejected on lock-preservation grounds — any unification touching `integration-tracking.md` belongs in IT's natural edit cycle per `<devlog:2026-04-22:v5-2-light-umbrella-framing>`, not a tooling-driven edit. The empty-associative-array lesson (`<lesson:2026-04-22:empty-assoc-array-under-set-u>`) does not apply — the array is always populated at init.

**Outcome:** During V5.3 Phase 4b implementation, the multi-check-per-invariant reality surfaced — several G-invariants' worked templates include multiple representative identifiers (e.g., G1's rename example uses both `E_CONN_LOST` and `E_UPSTREAM_UNAVAILABLE`; G9 has three log-prefix identifiers). The approved associative-array structure keyed by invariant ID could not represent this cleanly without either compound keys (`L2_REGISTRY["G1:E_CONN_LOST"]`) or delimited multi-value strings. Implementation shifted to an indexed bash array named `L2_CHECKS`, one row per check, with each row a pipe-delimited tuple of (invariant_id, check_name, canonical_pattern, worked_template_file). Not a reversal of A3's intent (inline, bash, simple, keyed by invariant) — a refinement of the data structure to accommodate multi-check coverage. The README documents `L2_CHECKS` as the variable name and the pipe-delimited row structure as the registry's actual shape.

---

### <devlog:2026-04-23:v5-3-skill-md-brief-cross-reference>

**Context:** V5.3 Phase 2 Round 2, A4. D as new infrastructure needed representation in SKILL.md so authors encounter it in the "How This Skill Evolves" context.

**Decision:** Brief cross-reference paragraph appended to the "How This Skill Evolves" section, after the last Worked Example subsection and before the section's closing `---`. Bold-lead paragraph, not its own subsection — keeps structural weight proportional to the authoring-only concern.

**Alternatives considered:** (S1) Own H3 subsection alongside the Worked Examples — structural peer to "Adding a New Case Study" etc., elevated in SKILL.md's visual hierarchy; (S3) No SKILL.md mention at all — document V5.3 only in the skill_development tree, rely on authors discovering the pre-commit hook mechanically.

**Rationale:** D is authoring infrastructure, not skill substance. (S1) overweights it by making it a peer to the Worked Examples, which ARE skill substance. (S3) under-weights it by burying the announcement — authors may not install the hook if they don't know it exists. (S2) lands in the middle: announced once, in the right architectural section, without elevation. Mirrors V5.2's Section 6 cross-reference pattern — light touch for cross-section pointers.

---

### <devlog:2026-04-23:v5-3-cross-reference-one-directional>

**Context:** V5.3 Phase 2 Round 2, A5. V5.2's IT-untouched lock remains active. Cross-references between V5.3 infrastructure and the existing reference files required directionality.

**Decision:** One-directional cross-references. V5.3 infrastructure (authoring-helpers README, harness comments, dev log entries) may cite `reference/grep_first.md` and `reference/integration-tracking.md` freely. The reference files themselves do NOT cite V5.3 infrastructure.

**Alternatives considered:** (X2) Bidirectional — reference files add a brief "see also: skill_development/authoring-helpers/" mention; (X3) Asymmetric-but-active — reference files updated to cite V5.3 only at their next natural edit cycle (V5.4+ or later).

**Rationale:** The IT-untouched lock from V5.2 was motivated by `<devlog:2026-04-22:v5-2-light-umbrella-framing>` — author discipline that IT changes cost IT's natural edit cycle. V5.3 is not that cycle. (X2) reverses the lock. (X3) is the compromise option but invites scope drift — "minimal cite addition" is the kind of soft edit that compounds. Preserving the lock literally means one-directional for V5.3. The asymmetry is captured in V5.3 dev log entries; readers who notice it and want to know why can consult them, matching the V5.2 `<devlog:2026-04-22:v5-2-cross-reference-language-no-meta-commentary>` precedent.

---

### <devlog:2026-04-23:v5-3-helpers-independent-zero-shared-code>

**Context:** V5.3 Phase 2 Round 2, A6. V5.0 shipped `verify-integrations.sh` (+ its unverified PowerShell counterpart) as the existing authoring helper. V5.3's L2 harness is a second helper in a similar surface area — integration-layer verification tooling.

**Decision:** V5.3 helpers are fully independent from V5.0's `verify-integrations.{sh,ps1}`. Zero shared code, zero shared library. Each helper is a self-contained unit.

**Alternatives considered:** (I2) Extract shared bash utilities (logging, exit-code handling, timestamping) into a common `lib.sh` sourced by both; (I3) Have V5.3's harness call `verify-integrations.sh` as a sub-step to produce a single "all verifications" runner.

**Rationale:** At two helpers totaling ~450 lines, shared-library extraction is premature — the shared surface is thin (log prefix format, exit-code constants) and both are already short enough to inline. (I2) pays structural cost (dependency resolution, sourcing discipline, shared-library governance) for minimal code reduction. (I3) couples V5.3's correctness to V5.0's, including V5.0's unverified PowerShell residual — a regression on `<devlog:2026-04-22:powershell-helper-ships-unverified>`'s isolation. Independence preserves the option to extract `lib.sh` at V5.5+ when a third helper appears and the pattern is clearer.

---

### <devlog:2026-04-23:v5-3-output-format-minimal-on-success-full-on-failure>

**Context:** V5.3 Phase 2 Round 3, A8. The harness's console output format affects author experience at every commit — the dominant path is success, the informative path is failure.

**Decision:** Minimal single-line success output (`L2 verification: N/N checks passed`). Full skill log format on failure — per-check `[timestamp] [ERROR] VERIFY_FAILED: invariant=X | check=Y | file=Z` lines plus a summary line.

**Alternatives considered:** (F1) Verbose on both paths — every check's PASS/FAIL emitted, matching structured-log discipline uniformly; (F3) Minimal on both paths — success and failure both emit one line, details via `--verbose` flag.

**Rationale:** Success is the dominant case; verbose success output is noise that trains authors to ignore the hook's output entirely — a worse failure mode than "too terse." (F1) pays verbosity cost at every commit for information only useful at failure time. (F3) saves the failure-output cost but loses diagnostic immediacy — a failing commit should surface what failed without a second invocation. The asymmetry is intentional: success is confirmation, failure is diagnosis, each gets the format it needs. Matches the `<lesson:2026-04-22:safety-critical-duplication-pattern>`-adjacent principle of calibrating output to consequence.

---

### <devlog:2026-04-23:v5-3-crlf-pre-normalize>

**Context:** V5.3 Phase 2 Round 3, A10. `<lesson:2026-04-22:l2-harness-must-be-line-ending-aware>` is the lesson that motivated V5.3's headline. The harness's CRLF handling strategy had to be chosen explicitly, not inherited by accident.

**Decision:** Pre-normalize every file read: `tr -d '\r' < "$file"` before applying any grep pattern. Registry patterns remain byte-identical to the canonical patterns documented in the reference files (no `(\b|\r)` tolerance baked in); normalization happens at the input boundary.

**Alternatives considered:** (C2) Tolerance-in-patterns — every registry pattern wraps word-boundaries with `(\b|\r\n|$)` or similar; (C3) Require reference files be stored LF — shift the burden from the harness to authoring discipline.

**Rationale:** Pre-normalization is the approach explicitly recommended in the lesson. Patterns stay canonical — "canonical pattern" means literally the string from the reference file, with no harness-specific transformation. (C2) couples every registry entry to CRLF-tolerance syntax and creates a drift surface — someone copying a canonical pattern from `grep_first.md` into the registry might forget the tolerance wrapping. (C3) pushes the problem to authors and would conflict with V5.0.1's grep-portability invariant (which assumes files may arrive in either line-ending convention depending on Windows/Linux authoring). Pre-normalization localizes the line-ending concern to a single line of the harness.

---

### <devlog:2026-04-23:v5-3-ship-regression-suite>

**Context:** V5.3 Phase 4d. During critical-review testing of `verify-l2.sh`, a 10-scenario / 19-assertion regression suite was written as throwaway scaffolding to validate the xargs-bug fix. The suite exercised reliability, effectiveness, CRLF-blindness, failure paths, output format, exit codes, idempotence, tmpfile cleanup, and registry iteration.

**Decision:** Ship the regression suite as `skill_development/authoring-helpers/test-verify-l2.sh` — a permanent V5.3 artifact, not throwaway scaffolding. Paths parameterized for the deployed layout; isolated via `mktemp -d` with EXIT-trap cleanup.

**Alternatives considered:** (1) Discard after Phase 4d — no ongoing maintenance surface; (2) Document the 10-test plan in the authoring-helpers README without shipping executable — matches V5.0's documented-but-unshipped PowerShell regression plan (`<devlog:2026-04-22:powershell-helper-ships-unverified>`).

**Rationale:** V5.4+ maintainers need a mechanical way to validate the harness after changes. (2) means the next person who touches the harness has to reimplement the test suite or skip regression — either way erodes the verification discipline `<lesson:2026-04-22:verification-applies-at-skill-level>` establishes. Shipping the executable preserves the discipline as tooling, not convention. The xargs bug found during this very test suite's development is the empirical argument: without the suite, that bug ships. The ~180 added lines of maintenance surface buy ~40 lines of high-leverage test assertions acting as the harness's own contract.
