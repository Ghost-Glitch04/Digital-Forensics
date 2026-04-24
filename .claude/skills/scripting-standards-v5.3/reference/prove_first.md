# Prove-First Development — Case Studies and Triggers

This file exists because the prove-first rule in SKILL.md is abstract. Rules without concrete examples lose their edge over time, especially across session boundaries. The case studies below are real debugging incidents from the Ghost Assessment Platform build, each annotated with what the prove-first step would have looked like.

**Use this file:** when you are about to write a test or unit against behavior you've never verified in isolation, read the matching case study first. It will either confirm the situation is worth a proof step, or tell you the pattern is already proven and you can proceed.

---

## The Trigger — "Recognizing the Moment"

Prove-first is not "always test everything in isolation first." That would add ceremony to every task. The rule fires only when a specific cognitive pattern appears:

> **"I'm about to write a test (or build a unit) that imports N modules and sets up M fixtures to assert something I've never verified in isolation."**

The key words are *assert something I've never verified*. If you've run the operation before — even in a different project — it is proven and you proceed. If you've only read the documentation, it is not proven. Documentation is not verification.

### Five Signs You Need a Proof Step

1. **You are about to assert on a framework's internal behavior.** Examples: Celery's request context, SQLAlchemy's autoflush timing, Jinja2's autoescape behavior, FastAPI's dependency resolution order, React's useEffect cleanup timing.

2. **You are about to call an external API whose response shape you know only from docs.** Docs lie. Docs go stale. Docs omit edge cases. The only way to know what a response looks like is to see one.

3. **You are about to parse a data file whose exact format, encoding, or delimiter you've assumed.** "It's a CSV" is not a specification. "It's UTF-8" is a guess unless you checked.

4. **You are writing a wrapper around a CLI tool whose output you've never captured directly.** CLI tool output varies by version, flags, locale, and terminal width. Don't write a regex against output you haven't seen. **Measure its runtime too** — assuming a CLI will finish inside a timeout without timing it once is the same mistake.

5. **You are building on top of a teammate's or AI's earlier work that you haven't run.** "They said it works" is not verification. Run it once yourself before you start extending it.

### Three Signs You Do Not Need a Proof Step

1. **You've done this exact operation successfully before in this project or a similar one.** Institutional memory counts. Don't re-prove what's already proven.

2. **The operation has a deterministic, well-known behavior in the language standard library.** `open("file.txt").read()` does not need a proof step. `pandas.read_csv("unknown_encoding.csv")` does.

3. **The rework cost is smaller than the proof cost.** If you can discover the wrong assumption by just writing the code and running it, and the code is 10 lines, just write it. Prove-first is a cost/benefit calculation, not an absolute rule.

---

## A Note on Phase References

Several case studies below cite `Phase 4.1`, `Phase 4.2`, `Phase 4.4`, etc. These are build-phase tags specific to the Ghost Assessment Platform project — they anchor cross-references to that project's `lessons_learned/` directory so a reader inside the project can trace a case study back to the original debugging session. Readers outside that project can safely treat the phase numbers as opaque identifiers; the case study's situation, failure, and lesson stand on their own without needing to know what Phase 4.1 refers to.

---

## Case Study 1 — Celery `task.apply()` vs `push_request`

**Situation.** Phase 4.1 of the Ghost Assessment Platform needed to test a Celery task that sets `run.celery_task_id` from `self.request.id` during execution. The session had read Celery's source and concluded: "I'll call `task.push_request(id='celery-123')` before invoking the task, and the task will read `self.request.id == 'celery-123'` internally."

**What the session wrote first.** A full test harness:

```python
# Test — as originally written, BEFORE proving the assumption
def test_celery_task_id_is_set(db, monkeypatch):
    run = make_run(db)
    run_tool.push_request(id="celery-123")
    try:
        run_tool(str(run.id))
    finally:
        run_tool.pop_request()

    db.refresh(run)
    assert run.celery_task_id == "celery-123"   # This assertion failed.
```

**What the session then did.** Over an hour of investigation. The initial diagnosis was SQLAlchemy autoflush (plausible, wrong). Then session/transaction scope (plausible, wrong). Then a suspected bug in the task body itself (wrong).

**Root cause.** `Task.__call__` in Celery 5.4.0 pushes its own empty request context internally, shadowing anything pushed by `push_request` from outside. The assertion could never pass because the assumption — "push_request from outside the task is visible to `self.request` inside the task" — was simply false.

**The prove-first step that would have cost 90 seconds.**

```python
# In a scratch REPL or a one-off Bash-tool invocation:
python -c "
from celery import Celery
app = Celery('x')
@app.task(bind=True)
def t(self): return self.request.id

import inspect
print(inspect.getsource(type(t).__call__))
"
```

The output shows `Task.__call__` calling `self.push_request(args=args, kwargs=kwargs)` — a new empty context — before executing the task body. The session would have seen this in under two minutes and immediately switched to `task.apply(task_id='celery-123', throw=True)`, which is the documented pattern that threads the task_id through correctly.

**Lesson encoded in Ghost's memory system** *(see the `Celery bind=True testing pattern` memory)*: use `push_request/pop_request` with the caveat that it is shadowed by `Task.__call__`; `task.apply(task_id=..., throw=True)` is the only pattern that works for full task invocation.

**Generalizable rule.** Before writing a test that asserts on a framework's internal context-propagation behavior, run `inspect.getsource` on the method that propagates it. It takes less time than one failed assertion.

---

## Case Study 2 — Python Empty-String Substring Gotcha

**Situation.** Phase 4.2's rule engine needed to match findings against `service_in: [http, https]` lists. The engine used `any(s.lower() in finding.service.lower() for s in service_in)` for case-insensitive substring matching.

**What went wrong.** When `finding.service` was `None`, the code coerced it to `""`. Then `any("" in svc for svc in service_in)` became `any("" in "http", "" in "https")`, which is `True` for every item — because **an empty string is a substring of every string in Python**, including another empty string.

Result: findings with no service field matched every service rule.

**The prove-first step that would have cost 10 seconds.**

```python
python -c "print('' in 'http')"
# True
```

Ten seconds. The assumption that "empty-string substring matching returns no matches" is wrong in Python (and Bash, and most other languages). A single REPL check would have surfaced it before any tests were written.

**Lesson encoded** *(phase4 lessons_learned)*: when normalizing a field to empty string for substring matching, always add an explicit early-return guard: `if not svc: return False`.

**Generalizable rule.** Any time you normalize a possibly-null value to a falsy default before a containment or comparison check, test the null case explicitly — preferably in a REPL before writing the test fixture.

---

## Case Study 3 — Lazy Import Patch Target

**Situation.** Phase 4.4 needed to test that seed-tool creation failure does not break the scope-creation API route. The test needed to make `load_profile` raise an exception.

**What the session wrote first.**

```python
with patch("api.routes.engagements.load_profile", side_effect=Exception("boom")):
    resp = client.post(f"/api/engagements/{eng.id}/scopes", json={...})
```

**What happened.** `AttributeError: module 'api.routes.engagements' has no attribute 'load_profile'`.

**Root cause.** `load_profile` was imported lazily inside the route handler's `try` block:

```python
# Inside the route
try:
    from runbook.loader import load_profile
    profile = load_profile(engagement.profile_name)
    ...
```

A function-body import never creates a module-level attribute on the importing module. `unittest.mock.patch` has nothing to replace because `api.routes.engagements.load_profile` literally doesn't exist until after the route runs.

**The prove-first step that would have cost 15 seconds.**

```python
python -c "
import api.routes.engagements as m
print('load_profile' in dir(m))
"
# False
```

One command. The session would have seen `False` and known immediately that the patch target needed to be `runbook.loader.load_profile` (where the function is *defined*), not the call-site alias.

**Lesson encoded** *(memory: "Always verify calling conventions")*: patch where the function is defined, not where it's used via lazy import. Lazy (function-body) imports are transparent to `patch()`.

**Generalizable rule.** Before patching any name, verify it actually exists as an attribute on the module you're patching. `dir(module)` or `hasattr(module, 'name')` is a one-line check.

**See also:** `testing.md` Rule 1 ("Patch Where the Function Is Defined") covers the same incident from the test-writing angle — once you've verified where the name actually lives, that rule tells you how to pick the right patch target.

---

## Case Study 4 — Jinja2 Autoescape Default

**Situation.** A report generator was using Jinja2 to render HTML. The session assumed `Environment(loader=FileSystemLoader(...))` would produce HTML-escaped output by default. The test passed because the test data had no special characters.

**What would have gone wrong in production.** Jinja2's `Environment()` defaults to `autoescape=False`. Any user-controlled field (engagement name, client name, finding description) would have been injected raw into the HTML, creating an XSS vulnerability.

**The prove-first step that would have cost 30 seconds.**

```python
python -c "
from jinja2 import Environment, BaseLoader
e = Environment(loader=BaseLoader())
t = e.from_string('{{ x }}')
print(repr(t.render(x='<script>alert(1)</script>')))
"
# '<script>alert(1)</script>'  ← not escaped
```

Output proves autoescape is off by default. The fix is `Environment(loader=..., autoescape=select_autoescape(['html']))`.

**This case study is about an assumption that never failed a test but would have failed production.** Prove-first is not just about catching bugs faster — it's about catching silent assumptions that tests won't notice.

**Generalizable rule.** For any security-sensitive default (autoescape, CSRF protection, cookie attributes, CORS policy), verify the default by reading or running — never by reading documentation.

---

## Case Study 5 — Shell Word-Splitting Under zsh

**Situation.** A test harness script used a helper function like `probe "display name" "pattern" command arg1 arg2`. Inside the helper: `timeout 60 bash -c 'run_cmd "$@"' _ "$@"`.

**What went wrong.** When run through the Bash tool in an agent session (which on this system executes under zsh), the `$@` expansion inside the nested `bash -c` did not preserve quoting the way the author expected. Multi-word arguments got split into separate tokens.

**The prove-first step that would have cost 45 seconds.**

```bash
# Scratch file in /tmp:
cat > /tmp/probe_test.sh <<'EOF'
#!/usr/bin/env bash
helper() {
  timeout 60 bash -c 'echo "received: $@"' _ "$@"
}
helper "display name" "arg with spaces"
EOF
chmod +x /tmp/probe_test.sh
/tmp/probe_test.sh
```

Output would have revealed the splitting behavior before the helper was used in 40 tests.

**Lesson encoded** *(memory: "Shell/bash testing traps")*: `timeout` cannot invoke shell functions directly; when passing args through a nested `bash -c`, use explicit array handling or here-docs, not raw `$@` in quoted strings.

**Generalizable rule.** Any shell helper that uses `"$@"` inside a nested `bash -c` or `sh -c` invocation must be proven in isolation with multi-word arguments before it is used anywhere else. Word-splitting bugs are invisible in tests that only pass single-word args.

---

## Case Study 6 — wpscan Default Mode vs the 60s Probe Timeout

**Situation.** Phase 22's WordPress simulation target needed an integration probe that confirmed wpscan could recover a planted credential from the stub `wp-login.php`. The probe function in the test harness has a hardcoded 60-second timeout. The author wrote the probe like this:

```bash
probe "wpscan credential recovery" "Valid Combinations Found" \
    wpscan --url http://localhost:9081/ \
           --usernames admin \
           --passwords /tmp/wordlist.txt \
           --password-attack wp-login
```

**What went wrong.** The probe failed with no credential line in the captured output. At first the failure looked like a stub-target bug (maybe the `wordpress_logged_in_` cookie wasn't being set correctly?), or a wpscan version issue. The session spent time re-reading the PHP stub, re-checking the 302 + cookie pair, and verifying `--password-attack` flag semantics. None of that was wrong. The problem was that wpscan's default `mixed` detection mode runs a `wp_version/unique_fingerprinting.rb` phase that probes **571 JS/CSS files** for version checksums. On this target, that phase took ~57 seconds. `timeout 60` sent SIGTERM with roughly three seconds left on the clock — nowhere near enough time to reach the password attack stage. The in-memory stdout buffer was lost on SIGTERM, so the captured log showed the early HTTP-header lines and then nothing. Classic "silent timeout" symptom masquerading as a stub bug.

**Root cause.** Assuming a CLI tool will finish inside a timeout based on documentation or intuition, without having run it once against the real target and timed it.

**The prove-first step that would have cost 60 seconds.**

```bash
# Run wpscan exactly once, manually, with time, before writing the probe:
time wpscan --url http://localhost:9081/ --usernames admin \
            --passwords /tmp/wordlist.txt --password-attack wp-login 2>&1 | tail -20
```

That single run would have produced one of two outcomes, both actionable:

1. `real  1m02.something` — immediately tells you the default mode blows past 60s. Fix: add `--detection-mode passive`, which drops the full scan to ~9s by reading only the index page HTML.
2. `real  0m09.something` — confirms the scan fits inside the timeout and the probe can proceed.

Either way, you know before writing the probe which mode you need. Instead the session guessed based on the docs, wrote a probe that silently timed out, and then spent debugging time looking for a bug in the wrong component.

**Lesson encoded** *(see `lessons_learned/ai/wpscan.md` Rules 1–2, and `CLAUDE.md` § wpscan)*: use `--detection-mode passive` in any wpscan probe with a ≤60s timeout; omit `--enumerate u` when `--usernames` is already supplied; measure CLI runtime once before writing a timeout-bounded probe around it.

**Generalizable rule.** Any time you are about to write a probe, test, or wrapper that imposes a timeout on an external CLI, **run the CLI once manually with `time` against the real target first**. If the measured runtime is more than half the timeout, either raise the timeout, reduce the tool's work (passive mode, narrower scope, lighter flags), or both. CLI runtimes are rarely what documentation implies — measurement is the only reliable signal. And because CLI output is buffered, a tool killed mid-run emits no output at all, so the failure mode looks like "the tool is broken" rather than "the timeout is too short." Prevent the misdiagnosis by measuring first.

---

## Common Proof Methods

Matched to typical situations. All should take under a minute.

| Situation | Proof method | Time budget |
|---|---|---|
| Framework internal behavior | `inspect.getsource(type(obj).method)` via `python -c` | 30–60 seconds |
| Module attribute existence | `python -c "import m; print(dir(m))"` | 5–15 seconds |
| API response shape | `curl -s URL \| jq .` (or `\| head`) | 10–30 seconds |
| CLI tool output format | `tool --help` and one sample invocation, captured to file | 30–60 seconds |
| CLI tool runtime under real load | `time tool <real-args>` against the real target, once — **do this even if you've run the tool before** | 30–60 seconds |
| Data file format / encoding | `file path`, `head -c 200 path \| xxd`, `iconv -f UTF-8 path` | 20–40 seconds |
| Python runtime behavior | `python -c "..."` one-liner | 5–20 seconds |
| Shell quoting / word-splitting | Scratch file in `/tmp` with the exact nested invocation | 30–60 seconds |
| Database query result shape | Run the query directly in a DB shell and print the first row | 30–60 seconds |
| Regex behavior on real input | `python -c "import re; print(re.search(PATTERN, 'real_sample'))"` | 10–20 seconds |

---

## Anti-Patterns — What Prove-First Is Not

**Prove-first is not "always write a test script first."** Proof is about verifying a single narrow assumption, not about full test coverage. A test script is usually too much for a proof step.

**Prove-first is not "re-test what you've already tested."** If you ran the operation successfully in the current session or project, it is proven. Don't re-prove out of caution — that's ceremony.

**Prove-first is not an excuse for delaying implementation.** The time budget is under a minute. If the proof step is turning into a research project, either the assumption was much deeper than you thought (legitimate) or you are procrastinating (not legitimate). Be honest about which.

**Prove-first does not replace tests.** Proof confirms the assumption is workable; tests confirm the code respects the proven assumption in all the cases you care about. Both are necessary.

---

## How to Add a Case Study to This File

When a future session burns an hour debugging something that could have been prevented by a 90-second proof step, add the incident as a new case study at the bottom of this file.

**Gatekeeping rule — real incidents only.** A case study must document a real debugging incident from this project's build or a prior session's documented work. Hypothetical scenarios, invented examples, and "this could happen" patterns are not allowed — they dilute the signal that makes this file institutional memory rather than decoration. If a teaching pattern is worth capturing but has no real incident behind it, add it to the "Five Signs You Need a Proof Step" or "Common Proof Methods" sections at the top of this file instead, where general-principle content belongs.

The schema:

1. **Situation** — what was being built, what assumption was held
2. **What went wrong** — the failure, including time lost
3. **Root cause** — the false assumption, stated plainly
4. **The prove-first step** — the exact one-liner or scratch file that would have caught it, with a time estimate
5. **Lesson encoded** — cross-reference to the memory entry or lessons-learned file where the rule now lives
6. **Generalizable rule** — the pattern other sessions should recognize

Case studies are the institutional memory this skill runs on. Every added case study makes the next session faster.
