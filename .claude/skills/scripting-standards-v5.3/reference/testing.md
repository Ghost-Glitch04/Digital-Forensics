# Testing Standards

Tests are code, and follow the scripting standards in SKILL.md. This file adds rules specific to test code — the ones that don't apply to production scripts but are essential to tests that stay useful over time.

**Load this file when:** writing new tests, debugging failing tests, or reviewing test suites for maintainability.

**Current scope.** This file currently documents **Python-specific** testing rules — every rule, decision table, case study, and grep pattern below assumes Python + `pytest` + `unittest.mock`. The underlying *principles* generalize across languages (patch-target correctness, mock fidelity, canary tests, fixture discipline, prove-first for framework assertions, forward-stability), but the examples are Python. Equivalent rules for Bash testing (BATS/shellspec) and PowerShell testing (Pester) are not yet documented — when those incidents accumulate, they belong as additional rules or as a parallel testing-bash.md / testing-powershell.md. Until then, a reader writing tests in Bash or PowerShell should read this file for the principles and adapt the patterns to their test framework's idioms.

---

## Philosophy

A test suite has two jobs:

1. **Prove the code behaves correctly today.**
2. **Make the consequences of future changes visible.**

Job 1 is what most people write tests for. Job 2 is why test quality matters over time. A test that passes without exercising the real contract (a mock that accepts anything), or a test that pretends to test code that has been silently bypassed (a patched call that never runs), does neither job — but it *looks* like it does both. That is the most expensive failure mode in testing.

The standards below are designed to catch the silent-failure class of tests.

---

## Decision Checklist — Before You Write the Test

Work through these before you open the test file. Most rules below exist because one of these questions was skipped and a wasted debugging session followed.

1. **Does the function you're testing exist as an attribute on the module you're about to patch?** If no — or if you're not sure — `dir(module)` first. (Rule 1, prove-first Case Study 3)
2. **Does the mock you're about to write actually exercise the contract the real object has?** If the real object has methods that return specific shapes, the mock needs `spec=` or an explicit class. (Rule 2)
3. **Does the test harness itself work?** If no canary test exists for the fixtures this test depends on, you won't be able to distinguish "code broken" from "harness broken" when it fails. (Rule 4)
4. **Does the test assert on framework internals or cross-module behavior?** If yes, verify the framework actually does what you think before writing the assertion. (Rule 6)
5. **Will this test still pass if someone changes the implementation but preserves the contract?** If no, the test is coupled to implementation, not behavior. (Rule 8)

If you answer "I'm not sure" to any of these, the rule for that question is the one to read first. If you answer "yes" to all five, the file below is backup material for the less common cases.

---

## Rule 1 — Patch Where the Function Is Defined

**Patch target selection is the #1 source of tests that silently pass.**

The rule: **patch where the function is defined, not where it's used** — unless the using module imports the name at the top level, in which case the using-module alias is fine too.

### Why

`unittest.mock.patch` replaces an attribute on a specific module. If the target module has no such attribute (e.g., because the function is imported inside a function body, not at module scope), the patch either fails with `AttributeError` or silently patches a name that the real code never reads.

### Quick decision table

| Import style in the target module | Correct patch target |
|---|---|
| `from foo.bar import thing` (top of file) | `target_module.thing` OR `foo.bar.thing` (both work) |
| `import foo.bar` + call `foo.bar.thing()` | `foo.bar.thing` (only) |
| Inside a function body: `from foo.bar import thing` | `foo.bar.thing` (only — the target module has no `thing` attribute) |

### Verification snippet

Before writing `patch("x.y.z", ...)`, verify the target exists:

```python
python -c "import x.y; print('z' in dir(x.y))"
```

If `False`, the patch will either error or silently no-op. Switch to the canonical module path.

### Case study — Phase 4.4

`api.routes.engagements` called `load_profile` via a lazy import inside the route handler:

```python
def add_scope(...):
    try:
        from runbook.loader import load_profile   # lazy import
        profile = load_profile(...)
```

The test wanted to make `load_profile` raise an exception to verify the `try/except` path. First attempt:

```python
with patch("api.routes.engagements.load_profile", side_effect=Exception("boom")):
    ...
```

→ `AttributeError: module 'api.routes.engagements' has no attribute 'load_profile'`.

Correct patch target: `patch("runbook.loader.load_profile", ...)` — the module where `load_profile` is defined. The test passed after the one-line change.

**Generalized:** when patching fails with `AttributeError: module ... has no attribute ...`, the function is almost certainly a lazy import. Patch the source module.

**See also:** `prove_first.md` Case Study 3 covers the 15-second `dir(module)` verification that would have caught this before `patch()` was ever written — the prove-first form of the same lesson.

---

## Rule 2 — Mocks Must Exercise the Contract

A mock that accepts any input and returns a fixed value is worse than no mock — it hides contract violations.

### The contract exists even if you're not testing it

When you replace a real object with a `MagicMock()`, you are implicitly asserting: "the code under test interacts with this object in a way the real object would also accept." If the mock is permissive (accepts any call, any args, any attribute access), that assertion is never checked. A change in the calling code that would break against the real object passes silently against the mock.

The contract that a test mock must match is the same contract tracked by `<CONTRACT>` blocks in production code. When a function carries a `<CONTRACT>` block, its shape is already documented formally — a test using `MagicMock(spec=RealClass)` derives its safety from that same shape. When the CONTRACT block's version bumps, spec-bound mocks break automatically, which is the desired behavior. See `reference/integration-tracking.md` for the production-code side of contract tracking.

### Three levels of mock fidelity

| Level | Example | When appropriate |
|---|---|---|
| **Permissive** | `obj = MagicMock()` — accepts any method, any args | Almost never. Only when the object's entire role in the test is "something exists." |
| **Spec-bound** | `obj = MagicMock(spec=RealClass)` — raises on unknown attrs/methods | Default for most tests. Catches typos and signature drift. |
| **Interface replica** | A small custom class that implements the exact interface the code under test relies on | When the code reads specific fields or calls specific methods in a specific order — especially with mixed sync/async attributes where `MagicMock` behaves unexpectedly. |

### Anti-patterns

**Anti-pattern: the yes-man mock.**

```python
# BAD
session = MagicMock()
session.query.return_value.filter.return_value.first.return_value = fake_user
# This passes no matter what path code takes, including paths that don't
# actually touch session.query at all.
```

**Anti-pattern: the mock that hides async/sync boundaries.**

```python
# BAD
redis = MagicMock()
await redis.publish("channel", "msg")   # MagicMock returns a non-awaitable
                                         # — test passes only because the await
                                         # operator doesn't raise on MagicMock.
```

Use `AsyncMock` for async methods specifically, or a plain class with explicit sync/async methods. A `MagicMock` whose methods are sometimes awaited and sometimes not is a bug waiting to ship.

### Lesson encoded

From the Ghost Assessment Platform memory system (*feedback_mock_fidelity*):
> Mocks must exercise the contract. Use plain classes with explicit interfaces for mixed sync/async objects. `MagicMock(spec=...)` is the default; `MagicMock()` bare is an anti-pattern unless the object's role is trivial.

---

## Rule 3 — Tests Are Not Immutable

When the behavior a test checks changes by design, update the test to reflect the new correct behavior. A failing test after a planned change is **not a regression** — it is a documentation gap. The test was correct when written; the behavior it tested changed.

### How to tell "regression" from "planned change"

| Signal | Interpretation |
|---|---|
| Test fails after a change you didn't intend to make | Regression — fix the code |
| Test fails after a change that was explicitly part of the plan | Planned change — update the test |
| Test fails after a change that *seemed* unrelated but shouldn't have affected this test | Investigate first — might be either |

### What not to do

- **Don't weaken the assertion.** Changing `assert x == 5` to `assert x > 0` to make the test pass is giving up accuracy to avoid work. The new behavior either has a specific correct output or it doesn't.
- **Don't skip the test.** `@pytest.mark.skip("TODO")` is debt with no due date. It will be skipped forever.
- **Don't revert the production change to appease the test.** The test is a tool, not an oracle. If the production change is correct, the test is wrong.

### Case study — Phase 4.4 broke 13 Phase 4.3 tests

Phase 4.3 tests asserted `status == RunStatus.SUGGESTED` for gobuster and nikto. Phase 4.4 introduced auto-queue behavior: tools marked `auto_queue: true` in the profile now create `QUEUED` runs instead of `SUGGESTED`. Thirteen tests failed.

The right fix was to update the assertions to `RunStatus.QUEUED` and add a dispatch patch (`_dispatch_tool_run`) to prevent Celery connection attempts. The tests became more accurate, not less. The alternative — weakening assertions or reverting auto-queue — would have hidden the new behavior from the suite.

**Lesson encoded** (*phase4_orchestration.md — Phase 4.4*): phase-boundary behavioral changes are exactly where test fragility shows up. Audit the suite for tests that were correct for the old behavior, and update them.

---

## Rule 4 — Canary Tests

Write at least one test whose only job is to verify the test harness itself. Without this, "all tests pass" has no meaningful floor.

### What a canary test looks like

```python
def test_canary_fixture_loads():
    """If this test fails, the test database fixture is broken."""
    from tests.conftest import db_factory
    assert db_factory is not None

def test_canary_engagement_creation(db):
    """If this test fails, the test DB cannot create engagements.

    Why this exists: without an explicit canary, a broken db fixture causes
    every engagement-dependent test to fail with the same AttributeError,
    and the real signal ("the DB fixture itself is the problem") is buried
    in 40 unrelated test failures. This test isolates the fixture so harness
    breakage produces one clear failure instead of a wall of red.
    """
    eng = make_engagement(db)
    assert eng.id is not None
    assert db.query(Engagement).filter(Engagement.id == eng.id).first() is not None
```

Canary tests are small, fast, and explicitly labeled `test_canary_*`. They catch the class of failures where "all tests pass" because the harness itself is silently broken (a fixture returns `None`, a database session doesn't commit, a mock is never reset between tests).

### When to add a canary

- Whenever you build a new fixture that other tests depend on
- Whenever you notice a test passing because the thing it was testing never ran
- At the start of any refactor that touches `conftest.py`

---

## Rule 5 — Fixture Discipline

Each fixture should have a single, obvious scope. Don't stack fixtures into hierarchies that require archaeology to understand.

### Good fixture shape

```python
@pytest.fixture
def db():
    """Fresh test database session per test. Rolled back at teardown."""
    session = TestSession()
    yield session
    session.rollback()
    session.close()

@pytest.fixture
def engagement(db):
    """A PCI-DSS test engagement. Use when the test needs a ready engagement."""
    return make_engagement(db, mode=EngagementMode.PCI_DSS, profile_name="pci_dss")
```

Each fixture does one thing. Each docstring explains the scope and purpose. Tests compose the fixtures they need.

### Bad fixture shape

```python
@pytest.fixture
def full_environment(db, redis_mock, celery_mock, engagement, runs, findings, ...):
    # 40 lines of setup covering every possible test need
```

A single "mega-fixture" that sets up everything saves a few lines in each test but makes every test dependent on a structure that is hard to change. When the mega-fixture breaks, every test breaks. When it works but misrepresents production (forgets a commit, skips a flush, reuses state), every test passes for the wrong reason.

### The rule

**Prefer many small fixtures over one large one.** A test that composes `db + engagement + run + finding` individually is clearer about what it depends on than a test that accepts `full_environment`.

---

## Rule 6 — Prove-First Applied to Testing

Before writing a test that asserts on a framework's behavior, *verify the framework behaves the way you think it does.* This is prove-first from SKILL.md, applied specifically to the test-writing situation.

### The framework-internals case (Celery)

The canonical example (see `prove_first.md` Case Study 1): Phase 4.1 wrote a full test harness around `push_request/pop_request` without ever confirming that `push_request` is visible to `self.request.id` inside `Task.__call__`. It isn't. The assertion could never have passed. A 90-second `inspect.getsource(type(task).__call__)` would have shown this before any test code was written.

### The rule

**If you are writing a test whose only role is to call into a framework's internals with a specific context, first prove in isolation that the context actually propagates the way you expect.** Do this with `inspect.getsource`, a REPL experiment, or a minimal scratch invocation. Time budget: under one minute.

---

## Rule 7 — Test Naming

Test names should read like specifications. A test called `test_foo` tells the reader nothing; a test called `test_suggested_run_becomes_queued_after_approve` tells the reader exactly what the system promises.

### Format

`test_<subject>_<condition>_<expected_result>`

Examples:
- `test_empty_service_does_not_match_non_empty_service_in`
- `test_auto_queue_creates_queued_run_not_suggested`
- `test_requires_confirmation_forces_suggested_even_when_auto_queue_true`
- `test_lazy_import_patch_target_uses_source_module`

The name is a sentence. When it fails, the failure message already tells the reader what broke.

### Anti-pattern

`test_suggestion_1`, `test_suggestion_2`, `test_suggestion_3` — names that require reading the body to understand. These are fine when drafting; rename before committing.

---

## Rule 8 — Test Forward-Stability

A test is *forward-stable* when it breaks only for reasons worth breaking for. Forward-stability is a design property, not an accident.

### Forward-stable test qualities

- **Asserts on the behavior the caller cares about, not the internal structure.** `assert user.is_admin is True` is forward-stable. `assert user._admin_flag_column_value == 1` is not.
- **Uses real values, not magic numbers, where the real value is cheap.** `assert len(results) == 3` is fine if the fixture provides exactly 3 inputs; `assert len(results) == 847` suggests a fixture that will drift.
- **Fails loudly on unexpected output shape.** `assert "host" in result` is not enough; `assert result.keys() == {"host", "port", "service"}` catches added or missing fields.
- **Documents why, not what.** A comment explaining *why* the test exists ("regression barrier for empty-string substring gotcha") is worth more than a comment explaining *what* ("checks that service matching works").

### Forward-fragile test qualities to avoid

- **Asserts on ordering that isn't guaranteed.** Dict ordering, set iteration, list-from-query — assume the order is undefined unless the code under test sorts the output.
- **Depends on the wall clock.** `datetime.now()` in a test is a flaky test waiting to happen. Freeze time with `freezegun` or inject a clock.
- **Depends on external network or local daemons without explicit opt-in.** Tests that pass on your machine and fail in CI are a signal that a dependency is implicit.

---

## Useful Grep Patterns

```bash
# Find tests that use permissive MagicMock (potential mock fidelity issues):
grep -rn "MagicMock()" tests/ | grep -v "spec="

# Find tests skipped with @pytest.mark.skip (debt):
grep -rn "pytest.mark.skip" tests/

# Find tests that patch a specific symbol (audit patch targets):
grep -rn 'patch("api\.routes' tests/

# Find tests with time-dependent assertions:
grep -rn "datetime.now\|time.time\|time.perf_counter" tests/

# Find tests without docstrings (potential naming fragility):
grep -rnB1 "def test_" tests/ | grep -v '"""'
```

---

## When a Test Fails — Diagnostic Checklist

Before "fixing the test," walk through this list:

1. **Did the behavior change by design?** (Planned change → update the test.)
2. **Is the test patching a lazy import?** (→ `AttributeError` on `patch()` is the tell.)
3. **Is the mock hiding a contract change?** (→ look for `MagicMock()` without `spec=`.)
4. **Is the assertion on something undefined (order, timestamp, locale)?** (→ forward-fragility, rewrite.)
5. **Is the test depending on a fixture that recently changed?** (→ the fixture is the regression, not the test.)
6. **Did you verify the framework behavior in isolation?** (→ if not, run the prove-first step now before going deeper.)

Only after all six checks say "no" should you assume the test is wrong and needs to be rewritten.
