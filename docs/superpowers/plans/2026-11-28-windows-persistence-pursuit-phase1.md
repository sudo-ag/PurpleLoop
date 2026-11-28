# Windows Persistence Pursuit — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the single-shot Windows persistence engagement into a multi-round pursuit: red re-plants through a second technique (Startup folder) after blue evicts, the episode runs to the horizon, and the winner is decided by whether any plant still stands.

**Architecture:** A plant *registry* on `SimulationState` records every verified plant and its eviction. Blue's existing `_list_win_persistence` baseline-diff gains a Startup-folder class, so one change gives blue both detection and eviction of it. The referee's persistence branch stops ending on first eviction and instead runs to `max_turns`, where a final live persistence diff decides the verdict (any standing entry → red). Red's plant-steering gate switches from "ever planted" to "nothing currently stands" so it rotates techniques after each eviction. An unconditional between-episode sweep guarantees the box is clean regardless of outcome.

**Tech Stack:** Python 3.13, pytest, WinRM-over-SSH-jump executor (`src/executor.py`), existing orchestrator/referee/agents.

**Spec:** `docs/superpowers/specs/2026-11-28-windows-persistence-pursuit-design.md`

## Global Constraints

- Windows/WinRM path only; the Linux SSH-key persistence path is untouched (every new branch is gated on `transport == "winrm"` or the `windows` flag).
- Verified signals only: a plant is recorded only when `_check_red_persistence_planted` already returns True; an eviction marks the registry only from `remove_persistence_windows`'s actual `removed_entries`.
- Every technique reversible and leaves the box clean: Startup-folder entries must be removable by `_remove_win_persist_entry` AND swept by the unconditional cleanup.
- Tests run with `uv run python -m pytest -q -p no:cacheprovider` (bare `pytest` fails on the `src` import). Live checks run on `.17` via the jump `.11`, box re-provisioned clean between runs.
- Registry identities live in the `_list_win_persistence` namespace (e.g. `task|\Name`, `startup|<path>`), never raw red command args.

## Review Focus

- **Plant signal with no new baseline entry** (red's output matches `_WIN_PERSIST_PLANTED` but the diff shows nothing new — a denied/duplicate create): the registry must not record a phantom plant. → pinned in Task 3.
- **Blue evicts some-but-not-all of several standing plants**: only the removed identities get `evicted_turn`; the rest stay standing and the horizon verdict is red. → pinned in Task 4.
- **Blue never landed a readable persistence sweep all episode** (every `investigate_persistence_windows` came back UNAVAILABLE): the horizon must not hand blue a win just because the in-memory registry is empty — an unproven board is a draw, not a blue clean. → pinned in Task 4.
- **Startup entry with a space/quote in the filename**: enumeration and removal must round-trip it (quoting-safe), else blue can see but not evict it. → pinned in Task 2.
- **A persistence episode with an explicit `--max-turns`**: the user's value must win over the new 32 default. → pinned in Task 7.

---

### Task 1: Plant registry on SimulationState

**Files:**
- Modify: `src/orchestrator.py` (the `SimulationState` dataclass, ~line 81–103)
- Test: `tests/test_persistence_registry.py` (create)

**Interfaces:**
- Produces:
  - `SimulationState.persistence_plants: List[Dict[str, Any]]` — each `{"identity": str, "planted_turn": int, "evicted_turn": Optional[int]}`, default `field(default_factory=list)`.
  - `SimulationState.record_plant(identities: Iterable[str], turn: int) -> None` — append one record per identity not already present as a *standing* plant (an identity already standing is not duplicated; a previously-evicted identity that reappears is a new record).
  - `SimulationState.mark_evicted(identities: Iterable[str], turn: int) -> None` — set `evicted_turn=turn` on every standing record whose identity is in `identities`.
  - `SimulationState.standing_plants() -> List[Dict[str, Any]]` — records with `evicted_turn is None`.
  - `SimulationState.persistence_baseline_ever_read: bool = False` — set True once blue lands any readable persistence sweep (used by the horizon verdict to avoid a false-clean blue win when blue never saw the board).

- [ ] **Step 1: Write failing tests** in `tests/test_persistence_registry.py`:
  - `test_record_plant_appends_standing` — record two identities at turn 2; `standing_plants()` has both.
  - `test_record_plant_dedupes_standing` — record `task|\A` twice; only one standing record.
  - `test_mark_evicted_sets_turn_on_matching` — record `A`,`B` at 2; `mark_evicted(["A"],5)`; `standing_plants()` == `[B]`, and the `A` record has `evicted_turn==5`.
  - `test_replant_after_eviction_is_new_record` — record `A`@2, evict `A`@3, record `A`@4; two records for `A`, one standing.

- [ ] **Step 2: Run to verify fail** — `uv run python -m pytest -q -p no:cacheprovider tests/test_persistence_registry.py` → FAIL (AttributeError).

- [ ] **Step 3: Implement** the field + three methods on `SimulationState`. `record_plant` skips an identity that is already in `standing_plants()`; otherwise appends.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat(persistence): plant registry on SimulationState`.

---

### Task 2: Startup-folder class in the persistence enumerate/remove helpers

**Files:**
- Modify: `src/executor.py` — `_list_win_persistence` (~1370) and `_remove_win_persist_entry` (~2478)
- Test: `tests/test_startup_persistence.py` (create)

**Interfaces:**
- Consumes: existing `_list_win_persistence() -> Optional[set]`, `_remove_win_persist_entry(entry) -> Tuple[bool,str]`, `_ps(script) -> str`.
- Produces: `_list_win_persistence` now also emits `startup|<full path>` for each file in the current user's and the common Startup folders; `_remove_win_persist_entry` handles `kind == "startup"` by deleting that file (quoting-safe).

- [ ] **Step 1: Write failing tests** (monkeypatch `ex._ps` to canned output):
  - `test_list_includes_startup_entry` — `_ps` returns JSON array containing `startup|C:\\Users\\x\\...\\Startup\\eysvc.lnk`; assert that string is in the returned set.
  - `test_remove_startup_entry_routes_to_file_delete` — stub `_ps`; call `_remove_win_persist_entry("startup|C:\\path\\with space\\x.bat")`; assert the `_ps` script received contains `Remove-Item` and the `LiteralPath` is the entry's path (round-trips the space), and the method returns `(True, ...)` on `PL_OK`.
  - `test_remove_startup_unknown_still_handled` — a malformed `startup|` with no path returns `(False, ...)`, not an exception.

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.**
  - In `_list_win_persistence`, after the task block, enumerate `[Environment]::GetFolderPath('Startup')` and the common startup folder (`$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`), emitting `startup|<fullname>` per file. Fault-tolerant (`try/catch`), same as the other categories.
  - In `_remove_win_persist_entry`, add `elif kind == "startup" and len(parts) >= 2:` that `Remove-Item -LiteralPath '<path>' -Force` (join `parts[1:]` in case a path contained `|`; it won't, but be safe), `'PL_OK'` on success.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat(executor): sweep + evict Startup-folder persistence`.

---

### Task 3: Orchestrator records plants (with identity) and evictions into the registry

**Files:**
- Modify: `src/orchestrator.py` — `step()` plant/evict recording (~678–692)
- Test: `tests/test_persistence_registry_wiring.py` (create)

**Interfaces:**
- Consumes: Task 1 (`record_plant`, `mark_evicted`), `_check_red_persistence_planted`, `_check_blue_persistence_removed`, executor `_list_win_persistence`/`_win_persist_baseline`/`_diff_baseline`, `remove_persistence_windows` output shape (`removed_entries`).
- Produces: on a verified Windows plant, the new canonical entries are captured and `record_plant`ed; on a blue removal, `removed_entries` are `mark_evicted`. The legacy scalars `red_persistence_planted_turn`/`blue_persistence_removed_turn` keep being set (back-compat) alongside the registry.

- [ ] **Step 1: Write failing tests** (construct an Orchestrator with a fake executor whose `_list_win_persistence` returns a controllable set; drive `step`-level helpers):
  - `test_windows_plant_records_new_canonical_identity` — baseline `{task|\Old}`; after red's verified plant the live set is `{task|\Old, startup|...\x.lnk}`; assert the registry has one standing plant with identity `startup|...\x.lnk` (the diff entry), not red's raw command.
  - `test_plant_signal_without_new_entry_records_nothing` (Review Focus) — red output matches the signal but live diff == baseline; assert no registry record added.
  - `test_blue_removal_marks_evicted` — registry has standing `startup|...`; feed a `remove_persistence_windows` output with `removed_entries:["startup|..."]`; assert that record's `evicted_turn` set and `standing_plants()` empty.

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** At the existing plant-detect site, when the plant check passes on a Windows engagement, compute `new = _diff_baseline(baseline, _list_win_persistence())[1]` and `state.record_plant(new, turn)` only if `new` is non-empty. At the removal site, parse the `remove_persistence_windows` output's `removed_entries` and `state.mark_evicted(removed_entries, turn)`. Also, wherever blue's `investigate_persistence_windows` output is seen, set `state.persistence_baseline_ever_read = True` when its `assessment != "UNAVAILABLE"`. Guard all on `transport == "winrm"`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat(orchestrator): populate plant registry from verified plant/evict`.

---

### Task 4: Referee runs persistence to the horizon; verdict by standing persistence

**Files:**
- Modify: `src/referee.py` — `resolve_outcome` persistence branch (~92–96); `src/orchestrator.py` — `run_simulation` end-of-loop verdict (~959–964)
- Test: `tests/test_referee.py` (extend), `tests/test_persistence_horizon.py` (create)

**Interfaces:**
- Consumes: `state.standing_plants()`, `state.persistence_plants`, `state.persistence_baseline_ever_read` (new bool, Task 3), prevention fields (`blue_contain_turn`, `blue_remediate_turn`).
- Produces: persistence `resolve_outcome` no longer returns a blue win on `blue_persistence_removed_turn` alone; it returns `"blue"` only for prevention-before-plant (unchanged), else `None` (keep pursuing). `Referee.persistence_horizon_winner() -> Optional[str]` decides a persistence episode from the **in-memory registry** (no live read — executors are already disconnected by the time `run_simulation` reaches its end-of-loop verdict).

- [ ] **Step 1: Write failing tests:**
  - `test_persistence_eviction_does_not_end_episode` — state with `blue_persistence_removed_turn=6` and a standing plant; `resolve_outcome()` is `None` (was `"blue"`).
  - `test_persistence_prevention_before_plant_still_blue` — (keep existing) prevention path still returns `"blue"`.
  - `test_horizon_verdict_standing_plant_is_red` — one standing plant, `persistence_baseline_ever_read=True`; `persistence_horizon_winner()` == `"red"`.
  - `test_horizon_verdict_all_evicted_is_blue` — a recorded plant, all evicted, `persistence_baseline_ever_read=True` → `"blue"`.
  - `test_horizon_unproven_board_is_not_blue` (Review Focus) — no standing plants but `persistence_baseline_ever_read=False` (blue never got a readable sweep) → `None` (draw), not `"blue"`.
  - `test_horizon_partial_eviction_leaves_red` (Review Focus) — two plants recorded, one evicted, one standing → `"red"`.

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.**
  - In `resolve_outcome` persistence branch: drop the `blue_persistence_removed_turn` early win; keep the prevention clause; otherwise return `None`.
  - Add `persistence_horizon_winner(self)`: if `state.standing_plants()` non-empty → `"red"`; elif a plant was recorded OR `state.persistence_baseline_ever_read` → `"blue"` (board proven clean); else `None` (unproven board → draw). In `run_simulation`'s end-of-loop, when `objective == "persistence"` and no in-loop winner, return it (before nothing-stands falls through to the existing None).

- [ ] **Step 4: Run to verify pass** (incl. full `tests/test_referee.py`).

- [ ] **Step 5: Commit** — `feat(referee): persistence runs to horizon, verdict by standing plant`.

---

### Task 5: Red repertoire — Startup-folder technique + rotate-after-eviction steering

**Files:**
- Modify: `src/agents.py` — `RED_WINDOWS_ADDENDUM` (~552–585), `RedAgent.phase_guidance` Windows branch (~1948+), and the steering gate; `src/orchestrator.py` — set the standing flag before red's turn (~in `step` turn setup)
- Test: `tests/test_agents.py` (extend)

**Interfaces:**
- Consumes: `state.standing_plants()`.
- Produces: `RedAgent.persistence_standing: bool` (default False), set by the orchestrator before each red turn to `bool(state.standing_plants())`; the Windows persistence steer in `phase_guidance` fires while `not self.persistence_standing` (replacing the `not self.objective_met()` gate for the Windows persistence case), and names a *rotation* repertoire including the Startup-folder drop.

- [ ] **Step 1: Write failing tests:**
  - `test_windows_red_repertoire_lists_startup_folder` — a winrm persistence `RedAgent` with `persistence_standing=False`: `phase_guidance()` mentions the Startup-folder technique (`Startup` + `.lnk`/`.bat`) alongside schtasks/sc.
  - `test_windows_red_steer_rotates_after_eviction` — `persistence_standing=False` after a prior plant → guidance tells red to re-establish through a DIFFERENT technique; `persistence_standing=True` → no re-plant nag.
  - `test_windows_red_steer_gate_is_standing_not_everplanted` — red has a plant signal in history (`objective_met()` True) but `persistence_standing=False`; the steer still fires (gate is standing, not ever-planted).

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** Add `persistence_standing: bool = False` on `RedAgent`; in `phase_guidance`, for the Windows persistence case gate the plant steer on `not self.persistence_standing`; expand the technique list and add a one-line "if a plant was evicted, rotate to a technique you have not used yet (e.g. a Startup-folder drop)". In the orchestrator, set `self.red_agent.persistence_standing = bool(self.state.standing_plants())` at the start of red's turn.

- [ ] **Step 4: Run to verify pass** (incl. full `tests/test_agents.py`).

- [ ] **Step 5: Commit** — `feat(agents): red Startup-folder technique + rotate-after-eviction steer`.

---

### Task 6: Unconditional between-episode persistence cleanup

**Files:**
- Modify: `src/executor.py` (add `clean_all_persistence`), `src/windows_dojo.py` (`teardown_windows_case` calls it)
- Test: `tests/test_windows_dojo.py` (extend) or `tests/test_startup_persistence.py`

**Interfaces:**
- Consumes: `_list_win_persistence`, `_win_persist_baseline`, `_diff_baseline`, `_remove_win_persist_entry`.
- Produces: `ToolExecutor.clean_all_persistence() -> Dict[str, Any]` — removes every post-baseline persistence entry across all classes, regardless of episode outcome; returns `{removed, failed}`. Called unconditionally from `teardown_windows_case`.

- [ ] **Step 1: Write failing tests:**
  - `test_clean_all_persistence_removes_every_new_entry` — fake executor, baseline `{task|\Old}`, live `{task|\Old, task|\Red, startup|...\r.lnk}`; `clean_all_persistence()` calls remove on `task|\Red` and `startup|...\r.lnk`, not on `task|\Old`.
  - `test_clean_all_persistence_no_baseline_is_noop` — `_win_persist_baseline None` → returns without removing (no blanket wipe).
  - `test_teardown_invokes_clean_all_persistence` — monkeypatch; assert `teardown_windows_case` calls it.

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement** `clean_all_persistence` (diff baseline→live, remove each new entry, collect results; refuse on no baseline), and call it first in `teardown_windows_case`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat(persistence): unconditional between-episode cleanup sweep`.

---

### Task 7: Horizon defaults to 32 turns for the persistence objective

**Files:**
- Modify: `src/arena.py` — `run_episodes`/`main` max-turns default selection
- Test: `tests/test_arena.py` (extend)

**Interfaces:**
- Consumes: `objective`, the CLI `--max-turns` (default sentinel).
- Produces: when `objective == "persistence"` and the user did not pass `--max-turns`, the per-episode `max_turns` is 32; an explicit `--max-turns` always wins.

- [ ] **Step 1: Write failing tests:**
  - `test_persistence_defaults_to_32_turns` — run_episodes path with `objective="persistence"` and no explicit max-turns resolves 32 (assert via the value passed to `run_simulation`, e.g. a spy/patch).
  - `test_explicit_max_turns_overrides_persistence_default` (Review Focus) — `objective="persistence"`, `max_turns=10` explicit → 10 wins.
  - `test_non_persistence_keeps_20_default` — `objective="root"` → 20.

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement.** Change the `--max-turns` CLI default to `None`; in `run_episodes`, resolve `max_turns = explicit if explicit is not None else (32 if objective == "persistence" else 20)`.

- [ ] **Step 4: Run to verify pass.**

- [ ] **Step 5: Commit** — `feat(arena): 32-turn horizon default for persistence`.

---

### Task 8: Live acceptance check on `.17` (not a unit test)

**Files:** none (operational). Depends on Tasks 1–7 merged.

- [ ] **Step 1:** Re-provision `.17` clean (`python -m src.windows_dojo provision …`).
- [ ] **Step 2:** Run a persistence episode `glm` v `glm` (`--objective persistence --transport winrm --red-user contractor …`, no `--max-turns`).
- [ ] **Step 3:** From `ep_001.md`, verify: red planted a first technique, blue evicted, red **re-planted a DIFFERENT technique** (Startup folder appears), the episode ran past the first eviction, and the verdict matches standing persistence at the horizon.
- [ ] **Step 4:** Inspect `.17`: confirm `clean_all_persistence` + teardown left zero post-baseline entries. Re-provision.
- [ ] **Step 5:** Record the result in `TODO.md` / `HANDOFF.md`.

---

## Self-review notes

- **Spec coverage:** registry (Task 1,3), red repertoire + rotate (Task 5), evasive technique end-to-end — Startup folder detect+evict (Task 2) — , partial blue vision (deferred to Phase 2, per spec phasing), eviction parity (Task 2), loop-to-horizon + standing verdict (Task 4), unconditional cleanup (Task 6), horizon length (Task 7), live proof (Task 8). Phase-2/3 items (split vision, WMI, anticipation scoring) are intentionally out of this plan.
- **Back-compat:** legacy scalar turn fields are kept set (Task 3) so existing scorecard/report code keeps working; `persistence_winner`/`build_scorecard` reconciliation beyond the horizon verdict is Phase-2 cleanup if needed.
- **Review Focus** items are each pinned to a task's tests above.
