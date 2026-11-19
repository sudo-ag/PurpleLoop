# Blue persistence defense — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the persistence scenario two-sided: once a foothold has landed, steer blue to hunt the planted SSH key with `investigate_persistence`, then evict it with `remove_persistence` — so a planted backdoor can produce a *blue* win instead of an uncontested red one.

**Architecture:** Two signal-driven guidance branches in `BlueAgent.tool_guidance` plus two helpers. EVICT (key detected + not removed → `remove_persistence user=X`) is placed before HARDEN and fires in both modes. Persistence-HUNT (foothold landed + sensor not run → `investigate_persistence`) is placed after HARDEN and is observe-gated. No objective plumbing: the trigger is the foothold and the detected key, not `--objective`.

**Tech Stack:** Python 3.13, pytest (run as `uv run python -m pytest`).

**Spec:** `docs/superpowers/specs/2026-11-18-blue-persistence-defense-design.md`

## Global Constraints

- Signal-driven, not objective-gated: no `objective` arg on `BlueAgent`; branches fire under any `--objective`.
- No auto-running of sensors; blue stays the decider (guidance only).
- No change to red, arena/orchestrator, the persistence win-eval, or scoring (all landed with slice #1).
- Tests run with `uv run python -m pytest` (plain `pytest`/`uv run pytest` fail to import `src`).

## Review Focus

- EVICT must fire in **both** modes (a key survives an IP ban), and name the account the key was planted on. (Task 1, covered.)
- EVICT must not re-fire once `remove_persistence` has run. (Task 1, covered.)
- Persistence-HUNT must require an actual foothold (`_has_foothold()`); no hunt without one. (Task 1, covered.)
- HARDEN still owns the surface-close turn before the hunt (EVICT only fires once a key is actually detected, which is after the hunt). (Task 1, covered by ordering.)

---

### Task 1: Hunt + evict guidance for a planted SSH-key backdoor

**Files:**
- Modify: `src/agents.py` — add `_removed_persistence()` and `_planted_key_account()` near `_closed_surface()` (~1846); add the EVICT branch immediately before the HARDEN block (~1918); add the persistence-HUNT branch immediately before the RESPOND block (~1975).
- Test: `tests/test_persistence_defense.py` (create)

**Interfaces:**
- Consumes: `_has_foothold()`, `_tools_used()`, `self.history` (all existing on `BlueAgent`); the history-scan idiom from `_escape_detected`.
- Produces: `BlueAgent._removed_persistence(self) -> bool`, `BlueAgent._planted_key_account(self) -> Optional[str]`.

- [x] **Step 1: Write the failing tests** — `tests/test_persistence_defense.py`: hunt-on-foothold, no-hunt-without-foothold, evict-on-right-account, evict-in-non-observe, no-re-evict-after-removal, and `_planted_key_account` parsing. Fixtures mirror `test_foothold_hunt.py` (`MockExecutor`, `Turn`), plus `_persistence_breach(account)` building an `investigate_persistence` BREACH turn.

- [x] **Step 2: Run tests to verify they fail** — `uv run python -m pytest tests/test_persistence_defense.py -v`. Expected: FAIL (branches/helpers absent).

- [x] **Step 3: Add `_removed_persistence(self) -> bool`** — `"remove_persistence" in self._tools_used()`.

- [x] **Step 4: Add `_planted_key_account(self) -> Optional[str]`** — scan `self.history` for an `investigate_persistence` result, return the account from the last `new_keys` entry (`entry.split(":", 1)[0]`), else `None`.

- [x] **Step 5: Add the EVICT branch** — before the HARDEN block. Fire when `_planted_key_account()` and `not _removed_persistence()`; return `remove_persistence user="<account>"` guidance. Fires in both modes.

- [x] **Step 6: Add the persistence-HUNT branch** — before the RESPOND block. Fire when `observe and _has_foothold() and "investigate_persistence" not in _tools_used()`; return `investigate_persistence` guidance.

- [x] **Step 7: Run the new tests** — `uv run python -m pytest tests/test_persistence_defense.py -v`. Expected: PASS (all 6).

- [x] **Step 8: Run the full suite (regression)** — `uv run python -m pytest -q`. Result: 574 passed (568 + 6), no fallout in foothold-hunt / blue-triage.

- [x] **Step 9: Live validation.** In-loop episode left blue's branches unexercised (red never planted; blue never registered the foothold — the deferred sensing gap). Closed deterministically with a direct probe on `.12`: planted key → `investigate_persistence` BREACH → EVICT steer named the account → `remove_persistence` stripped the key off the box → baseline restored.

- [ ] **Step 10: Commit** (user commits per their git rules)

```bash
git add src/agents.py tests/test_persistence_defense.py \
  docs/superpowers/specs/2026-11-18-blue-persistence-defense-design.md \
  docs/superpowers/plans/2026-11-18-blue-persistence-defense.md
git commit -m "feat(blue): hunt and evict a planted SSH-key backdoor"
```

---

## Self-Review

1. **Spec coverage:** `_removed_persistence` (Step 3) ✓; `_planted_key_account` (Step 4) ✓; EVICT branch + both-modes + account (Step 5) ✓; persistence-HUNT branch + observe-gate + foothold-gate (Step 6) ✓; verification (Steps 7–9) ✓.
2. **Step scan:** each step writes one thing; branch placement and conditions are pinned, wording left to the builder.
3. **Type consistency:** `_planted_key_account(self) -> Optional[str]` (Step 4) feeds EVICT's condition (Step 5); `_removed_persistence(self) -> bool` (Step 3) gates re-firing.
4. **Review Focus:** both-modes eviction, no-re-evict, foothold-required hunt, and HARDEN-before-hunt ordering each have a named test or ordering guarantee.
5. **Proportion:** plan ≈ spec length; the design was settled in-chat (signal-driven vs objective-gated fork), so the branch bodies are the builder's.
