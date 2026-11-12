# Per-Agent Episode Debrief Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Append a per-agent, first-person pentest-style debrief (exec summary → actions → learned → next) to each episode's `ep_NNN.md`, built deterministically from episode data with an optional `--narrate` LLM polish.

**Architecture:** A new pure module `src/debrief.py` assembles the four-part skeleton from the finished `SimulationState` + the episode `card` (which already holds `verdict`/`tiers`). Each agent's per-episode `reflect()` lesson is captured onto `SimulationState` so the skeleton can read it. The deterministic skeleton stands alone; a toggled polish callable rewrites it into prose, fail-safe to the skeleton on any error. Arena appends both agents' debriefs to the report.

**Tech Stack:** Python 3.13, pytest, uv. Touches `src/orchestrator.py` (lesson capture), `src/debrief.py` (new), `src/arena.py` (wiring + `--narrate` flag).

**Spec:** `docs/superpowers/specs/2026-11-12-purpleloop-episode-debrief-design.md`

## Global Constraints

- Test command: `uv run python -m pytest` (the `-m` form puts cwd on `sys.path`; bare `uv run pytest` can't import `src`).
- The deterministic skeleton stands alone: with `--narrate` OFF the report is complete, readable, and makes **no model call**.
- `--narrate` defaults **OFF** (reproducible by default). It is the only non-deterministic step.
- Polish fails safe: any error or empty return from the polish callable ⇒ emit the deterministic skeleton unchanged. Never crash, never a blank section.
- First-person ("I scanned…"), same four-part skeleton for red and blue.
- Exec-summary headline uses the **graded** verdict (`card["verdict"]`/`card["tiers"]`), never the legacy binary winner.
- No new scoring, no new sensors, no change to the simulation or to the ② case engine.

## Review Focus

- **Thin episode** (agent made no foothold, empty `blue_case`, `lesson` is `None`/`""`): every section still renders coherently and short — no crash, no blank. → Task 2.
- **Lesson with no "so next time" clause**: "What's next" falls back to a tier-derived step, then to a fixed string. → Task 2.
- **Polish raises or returns `""`**: `build_debrief` emits the deterministic skeleton unchanged. → Task 2 (wrapper) + Task 4.
- **Blue with an empty case**: "Actions" still renders from blue's tool calls (or "no leads recorded"), never assumes leads exist. → Task 2.
- **`--narrate` default OFF**: no model call happens on a normal run. → Task 4.

---

### Task 1: Capture per-episode lessons onto state

**Files:**
- Modify: `src/orchestrator.py` (SimulationState ~`:80-101`; `run_simulation` ~`:877-878`)
- Test: `tests/test_debrief_capture.py`

**Interfaces:**
- Produces: `SimulationState.red_lesson: Optional[str] = None`, `SimulationState.blue_lesson: Optional[str] = None`, set in `run_simulation` from each `reflect()` return.

- [ ] **Step 1: Write the failing test**

```python
def test_run_simulation_captures_each_agents_lesson_onto_state():
    orch = _orch()  # MagicMock(spec=Agent) red+blue
    orch.red_agent.reflect.return_value = "red lesson"
    orch.blue_agent.reflect.return_value = "blue lesson"
    orch.red_agent.act.return_value = "stop"   # text -> turns end cleanly
    orch.blue_agent.act.return_value = "stop"
    orch.red_agent.build_observation.return_value = "obs"
    orch.blue_agent.build_observation.return_value = "obs"
    orch.run_simulation(max_turns=1)
    assert orch.state.red_lesson == "red lesson"
    assert orch.state.blue_lesson == "blue lesson"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run python -m pytest tests/test_debrief_capture.py -v`
Expected: FAIL (AttributeError: no `red_lesson`)

- [ ] **Step 3: Implement** — add the two `Optional[str]` fields to `SimulationState`; in `run_simulation`, right after the two `reflect()` calls, set `self.state.red_lesson = red_lesson` and `self.state.blue_lesson = blue_lesson`.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run python -m pytest tests/test_debrief_capture.py -v`
Expected: PASS

- [ ] **Step 5: Commit** (if commits are enabled this session)

```bash
git add src/orchestrator.py tests/test_debrief_capture.py
git commit -m "feat(debrief): capture per-episode lessons onto state"
```

---

### Task 2: Deterministic debrief builder (`src/debrief.py`)

**Files:**
- Create: `src/debrief.py`
- Test: `tests/test_debrief.py`

**Interfaces:**
- Consumes: a finished `state` (duck-typed: `.red_lesson`/`.blue_lesson`, `.history`, `.blue_case`, tier fields) and the episode `card` (`card["verdict"]`, `card["tiers"]`).
- Produces:
  - `build_debrief(role: str, state: Any, card: Dict[str, Any], polish: Optional[Callable[[str, str], str]] = None) -> str` — the full markdown debrief section for one agent. If `polish` is given, returns `polish(skeleton, role)` wrapped in try/except that returns `skeleton` on any error or falsy result.
  - section helpers (module-level, pure): `_exec_summary(role, state, card) -> str`, `_actions(role, state) -> str`, `_learned(role, state) -> str`, `_next_step(role, state, card) -> str`, and `_automated_responses(state) -> str` (blue only; reads reflex state flags like `escalation_auto_revoked`, `remediated_user`).

- [ ] **Step 1: Write the failing tests**

```python
def _state(**kw):
    base = dict(red_lesson=None, blue_lesson=None, history=[],
                blue_case={"leads": [], "hypotheses": []})
    base.update(kw)
    return SimpleNamespace(**base)

def test_debrief_has_the_four_section_headers():
    out = build_debrief("red", _state(), {"verdict": "red reached T1", "tiers": []})
    for h in ("Executive Summary", "Actions", "Learned", "Next"):
        assert h in out

def test_exec_summary_uses_the_graded_verdict():
    out = build_debrief("blue", _state(), {"verdict": "red reached T1; blue defended nothing", "tiers": []})
    assert "blue defended nothing" in out

def test_learned_section_shows_the_captured_lesson():
    out = build_debrief("red", _state(red_lesson="establish a stable shell first"),
                        {"verdict": "x", "tiers": []})
    assert "establish a stable shell first" in out

def test_next_step_extracts_the_forward_clause():
    s = _state(red_lesson="re-exploiting wasted turns, so next time reuse the session")
    assert "reuse the session" in _next_step("red", s, {"tiers": []})

def test_next_step_falls_back_when_no_forward_clause():
    s = _state(red_lesson="the exploit worked")  # no 'next time'
    nxt = _next_step("red", s, {"tiers": []})
    assert nxt  # non-empty, no crash

def test_thin_episode_does_not_crash_and_is_nonempty():
    out = build_debrief("blue", _state(), {"verdict": "draw", "tiers": []})
    assert out.strip()

def test_blue_actions_narrate_the_case_file():
    case = {"leads": [{"id": 0, "sensor": "investigate_connections",
                       "observation": "port scan from .11", "confidence": "high", "turn": 2}],
            "hypotheses": [{"claim": "recon from .11", "confidence": "medium",
                            "lead_ids": [0], "turn": 3}]}
    out = build_debrief("blue", _state(blue_case=case), {"verdict": "x", "tiers": []})
    assert "port scan from .11" in out and "recon from .11" in out

def test_polish_failure_falls_back_to_skeleton():
    def boom(skeleton, role): raise RuntimeError("model down")
    skeleton = build_debrief("red", _state(red_lesson="x"), {"verdict": "v", "tiers": []})
    polished = build_debrief("red", _state(red_lesson="x"), {"verdict": "v", "tiers": []}, polish=boom)
    assert polished == skeleton

def test_polish_empty_return_falls_back_to_skeleton():
    skeleton = build_debrief("red", _state(), {"verdict": "v", "tiers": []})
    polished = build_debrief("red", _state(), {"verdict": "v", "tiers": []}, polish=lambda s, r: "")
    assert polished == skeleton
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_debrief.py -v`
Expected: FAIL (module not defined)

- [ ] **Step 3: Implement `src/debrief.py`** with the signatures above.
  - `_exec_summary`: a first-person paragraph framed on `card["verdict"]` (+ a line per reached/defended tier from `card["tiers"]` when present).
  - `_actions`: for red, narrate role-tagged tool calls from `state.history`; for blue, walk `state.blue_case` leads then hypotheses ("I filed N leads…; my working theory moved to …"), falling back to blue's tool calls / "no leads recorded" when the case is empty.
  - `_learned`: `getattr(state, f"{role}_lesson", None)` or "No lesson recorded this episode."
  - `_next_step`: if the lesson contains "next time" (case-insensitive), return the text after it; else a tier-derived step from `card["tiers"]`/state; else "No explicit next step recorded."
  - `_automated_responses` (blue only): read reflex flags; omit the sub-section when none fired.
  - `build_debrief`: assemble the skeleton; if `polish`, `try: out = polish(skeleton, role); return out or skeleton except Exception: return skeleton`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run python -m pytest tests/test_debrief.py -v`
Expected: PASS

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/debrief.py tests/test_debrief.py
git commit -m "feat(debrief): deterministic per-agent debrief builder"
```

---

### Task 3: Wire the debrief into the episode report + persist lessons to JSON

**Files:**
- Modify: `src/arena.py` (report write ~`:377-380`; `build_replay` call / `build_replay` in `src/arena.py:107`)
- Test: `tests/test_debrief_wiring.py`

**Interfaces:**
- Consumes: `build_debrief` (Task 2), `state.red_lesson`/`blue_lesson` (Task 1).
- Produces: `ep_NNN.md` ends with "## 🔴 Red Debrief" and "## 🔵 Blue Debrief" sections; `build_replay` output gains `"red_lesson"`/`"blue_lesson"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_replay_carries_both_lessons():
    state = SimpleNamespace(red_lesson="rl", blue_lesson="bl", turn=3, history=[],
                            blue_case={"leads": [], "hypotheses": []})
    rep = build_replay(state, {"winner": None}, 1, {})
    assert rep["red_lesson"] == "rl" and rep["blue_lesson"] == "bl"

def test_episode_report_text_includes_both_debriefs():
    # drive the smallest arena path that writes a report, or assert the composed
    # report string includes both debrief headers (compose helper under test).
    ...
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_debrief_wiring.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** — add `"red_lesson": g("red_lesson")`, `"blue_lesson": g("blue_lesson")` to `build_replay`. Where `ep_NNN.md` is written, append `build_debrief("red", orch.state, card, polish)` and `build_debrief("blue", orch.state, card, polish)` to `orch.generate_report()` before writing (`polish` is `None` unless `--narrate`; wired in Task 4). Keep the existing report body unchanged above the debriefs.

- [ ] **Step 4: Run to verify they pass + full suite**

Run: `uv run python -m pytest tests/test_debrief_wiring.py -v && uv run python -m pytest`
Expected: PASS; suite green

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/arena.py tests/test_debrief_wiring.py
git commit -m "feat(debrief): append debriefs to ep report + persist lessons to json"
```

---

### Task 4: `--narrate` optional LLM polish pass

**Files:**
- Modify: `src/debrief.py` (add `make_polish`), `src/arena.py` (CLI flag + thread `polish` into the Task 3 wiring; `run_episodes` param)
- Test: `tests/test_debrief_polish.py`

**Interfaces:**
- Consumes: an agent's `client` + `model` (reuse `orch.blue_agent.client`/`.model`).
- Produces: `make_polish(client: Any, model: str) -> Callable[[str, str], str]` — returns a polish callable that sends the skeleton to the model asking it to rewrite (not add facts) and returns the prose; raises/empty handled by `build_debrief`'s wrapper. `run_episodes(..., narrate: bool = False)`; `--narrate` CLI flag (default False) selects whether `polish` is `make_polish(...)` or `None`.

- [ ] **Step 1: Write the failing tests**

```python
def test_make_polish_sends_skeleton_and_returns_model_text():
    client = MagicMock()
    client.chat.return_value = {"message": {"content": "polished prose"}}
    polish = make_polish(client, "some-model")
    assert polish("SKELETON", "red") == "polished prose"
    assert client.chat.called

def test_narrate_flag_defaults_off_so_no_model_call(monkeypatch):
    # run_episodes(..., narrate omitted) must not construct a polish / call chat
    # assert via a sentinel that make_polish is not invoked on a default run.
    ...
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run python -m pytest tests/test_debrief_polish.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** — `make_polish` builds a one-shot chat prompt ("Rewrite this debrief as flowing first-person prose. Do NOT add facts not present.") and returns `resp["message"]["content"]`. Add `narrate` param to `run_episodes` and the `--narrate` argparse flag (default False); when set, build `polish = make_polish(orch.blue_agent.client, orch.blue_agent.model)` and pass it to the Task 3 debrief calls; else `None`.

- [ ] **Step 4: Run to verify they pass + full suite**

Run: `uv run python -m pytest tests/test_debrief_polish.py -v && uv run python -m pytest`
Expected: PASS; suite green

- [ ] **Step 5: Commit** (if enabled)

```bash
git add src/debrief.py src/arena.py tests/test_debrief_polish.py
git commit -m "feat(debrief): optional --narrate LLM polish pass (default off)"
```

---

### Task 5: Live validation (one episode)

**Files:** none (observation; may note outcome in `HANDOFF.md`).

- [ ] **Step 1** — Run one earned+observe episode (streaming to the terminal), default (no `--narrate`). Read `ep_NNN.md`: confirm both "🔴 Red Debrief" / "🔵 Blue Debrief" sections render all four parts, blue's narrates its case, and nothing is blank/garbled.
- [ ] **Step 2** — Run once more with `--narrate` and eyeball that the polished prose reads well and invents no events not in the deterministic version. If the model errors, confirm the report still contains the deterministic skeleton (fail-safe).
- [ ] **Step 3** — Record the outcome in `HANDOFF.md`.

---

## Self-Review

- **Spec coverage:** four-part skeleton (T2), first-person + graded headline (T2), hybrid deterministic+polish toggle (T2 wrapper + T4), blue spined on case (T2), "what's next" fallback (T2), lesson capture (T1), append to ep_NNN.md + persist to json (T3), determinism/fail-safe (T2/T4), live (T5). Re-render-from-JSON CLI explicitly out of scope — no task, by design.
- **Type consistency:** `build_debrief(role, state, card, polish=None)` signature identical across T2/T3/T4; `polish: Callable[[str,str],str]` matches `make_polish`'s return; `state.red_lesson`/`blue_lesson` set in T1, read in T2, carried in T3.
- **Review Focus:** thin episode (T2), no-forward-clause lesson (T2), polish failure (T2+T4), empty case (T2), `--narrate` default off (T4) — each pinned to a task's tests.
