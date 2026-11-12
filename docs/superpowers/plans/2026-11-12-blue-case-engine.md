# Blue Case/Story Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give blue an explicit, per-episode case file (leads + working hypothesis) it builds and reasons over each turn, acts on, and carries into the episode record.

**Architecture:** "B with A scaffolding" — the case is a plain dict held on `SimulationState.blue_case` (the orchestrator owns and persists it). Blue mutates it only through validated `src/case.py` functions, called at dispatch time from two new note-taking tools, so same-turn ordering holds and blue cannot write arbitrary fields. A thin-evidence floor reuses the existing `contain_attacker` dispatch seam (the one that already holds the DROP in `--observe`) to block a containment whose cited leads come from a single sensor.

**Tech Stack:** Python 3.13, pytest, uv. Existing modules: `src/agents.py` (Agent + blue tool schema/dispatch), `src/orchestrator.py` (SimulationState + step loop), `src/arena.py` (`build_replay`), `src/case.py` (new).

**Spec:** `docs/superpowers/specs/2026-11-12-purpleloop-blue-case-engine-design.md`

## Global Constraints

- Blue only; per-episode scope; **no new scoring tier** and no change to T1/T2/T3 or detect/dwell/defend logic.
- Confidence is one of exactly `"low"`, `"medium"`, `"high"`; invalid input fails safe to `"low"`, never raises.
- A malformed or missing tool arg must not crash the turn or corrupt the case (mirror the existing `_normalize_action` / per-dispatch try-except discipline).
- The case fed into blue's prompt is a compacted *view*; the full store in `SimulationState.blue_case` is never trimmed.
- `--observe` still suppresses the live DROP exactly as today; the case engine changes *why* blue decides to act, not whether observe holds the action.
- The general-purpose "investigate anything" tool is **out of scope** (deferred slice). No lead retraction/weaken tool this slice — blue re-weights by issuing a new hypothesis.

## Review Focus

- **Malformed note args** (missing `confidence`, non-list `lead_ids`, unknown `sensor`): dispatch must return an error payload, not crash — pinned in Task 3.
- **Containment with no hypothesis/leads at all** must stay allowed (backward compat with every existing contain test) — pinned in Task 4.
- **`lead_ids` citing ids that don't exist** in the case: `cited_sensors` must skip them, not KeyError — pinned in Task 1.
- **Prompt-view compaction dropping a cited lead**: the full store and the replay must still carry it, so an action's citation stays resolvable — pinned in Task 5/6.
- **Observe mode**: a held (or floor-blocked) containment must still record the intended IP + cited leads so the counterfactual is inspectable — pinned in Task 6.

---

### Task 1: Case data model (`src/case.py`)

**Files:**
- Create: `src/case.py`
- Test: `tests/test_case.py`

**Interfaces:**
- Produces:
  - `new_case() -> dict` — `{"leads": [], "hypotheses": []}`
  - `add_lead(case: dict, sensor: str, observation: str, confidence: str, turn: int) -> int` — appends `{"id", "sensor", "observation", "confidence", "turn"}`, returns the new id (monotonic, `len(leads)`-based)
  - `add_hypothesis(case: dict, claim: str, confidence: str, lead_ids: list[int], turn: int) -> None` — appends `{"claim", "confidence", "lead_ids", "turn"}`
  - `current_hypothesis(case: dict) -> Optional[dict]` — last hypothesis, or `None`
  - `cited_sensors(case: dict, lead_ids: list[int]) -> set[str]` — distinct sensors of the cited leads; ids with no matching lead are skipped
  - `compact_view(case: dict, max_leads: int = 12) -> str` — human-readable block: the last `max_leads` leads + the current hypothesis
  - `norm_confidence(value: object) -> str` — returns the value if in `{"low","medium","high"}`, else `"low"`

- [ ] **Step 1: Write the failing tests**

```python
def test_new_case_is_empty():
    assert new_case() == {"leads": [], "hypotheses": []}

def test_add_lead_returns_monotonic_ids_and_stores_fields():
    c = new_case()
    i0 = add_lead(c, "investigate_connections", "foreign IP .11", "medium", 2)
    i1 = add_lead(c, "investigate_processes", "new root proc", "high", 4)
    assert (i0, i1) == (0, 1)
    assert c["leads"][0] == {"id": 0, "sensor": "investigate_connections",
                             "observation": "foreign IP .11", "confidence": "medium", "turn": 2}

def test_current_hypothesis_is_the_last_one_or_none():
    c = new_case()
    assert current_hypothesis(c) is None
    add_hypothesis(c, "probing from .11", "low", [0], 2)
    add_hypothesis(c, "active privesc from .11", "high", [0, 1], 4)
    assert current_hypothesis(c)["claim"] == "active privesc from .11"

def test_cited_sensors_is_distinct_and_skips_unknown_ids():
    c = new_case()
    add_lead(c, "investigate_connections", "x", "low", 1)   # id 0
    add_lead(c, "investigate_connections", "y", "low", 2)   # id 1 (same sensor)
    add_lead(c, "investigate_processes", "z", "low", 3)     # id 2
    assert cited_sensors(c, [0, 1]) == {"investigate_connections"}
    assert cited_sensors(c, [0, 2, 99]) == {"investigate_connections", "investigate_processes"}

def test_norm_confidence_falls_back_to_low():
    assert norm_confidence("high") == "high"
    assert norm_confidence("bogus") == "low"
    assert norm_confidence(None) == "low"

def test_compact_view_trims_to_last_max_leads_but_mentions_hypothesis():
    c = new_case()
    for n in range(20):
        add_lead(c, "investigate_logs", f"evt{n}", "low", n)
    add_hypothesis(c, "noise", "low", [19], 20)
    view = compact_view(c, max_leads=5)
    assert "evt19" in view and "evt0" not in view
    assert "noise" in view
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_case.py -v`
Expected: FAIL (module/functions not defined)

- [ ] **Step 3: Implement `src/case.py`** with the signatures above. `add_lead` assigns `id = len(case["leads"])`. `cited_sensors` builds an id→sensor map and skips missing ids. `compact_view` renders the last `max_leads` leads and the current hypothesis as plain text.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_case.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/case.py tests/test_case.py
git commit -m "feat(blue): case data model (leads + hypotheses)"
```

---

### Task 2: Hold the case on state + hand it to blue each turn

**Files:**
- Modify: `src/orchestrator.py` (SimulationState field ~`src/orchestrator.py:80-101`; episode-reset path; blue's turn in `step` ~`src/orchestrator.py:505+`)
- Modify: `src/agents.py` (give `Agent` a `case` attribute, default `None`, reset in its episode-reset ~`src/agents.py:822`)
- Test: `tests/test_case_wiring.py`

**Interfaces:**
- Consumes: `src/case.py` `new_case`.
- Produces: `SimulationState.blue_case: dict` (default `new_case()`); the orchestrator sets `blue_agent.case = self.state.blue_case` (same reference) before the blue agent decides each turn.

- [ ] **Step 1: Write the failing tests**

```python
def test_state_starts_with_empty_case():
    assert SimulationState().blue_case == {"leads": [], "hypotheses": []}

def test_blue_agent_case_is_wired_to_state_object_each_blue_turn(_orch):
    # after a blue turn, the agent's .case is the SAME object as state.blue_case
    orch = _orch()
    orch.step()  # red
    orch.step()  # blue
    assert orch.blue_agent.case is orch.state.blue_case
```

(Use the existing `_orch()` mock fixture pattern from `tests/`; drive a mock blue turn.)

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_case_wiring.py -v`
Expected: FAIL

- [ ] **Step 3: Implement**
- Add `blue_case: Dict[str, Any] = field(default_factory=new_case)` to `SimulationState`.
- Wherever the episode resets state, the new default already re-inits it; confirm the per-episode reset creates a fresh `SimulationState` (or re-init `blue_case` if it reuses one).
- In `step`, when `role == "blue"`, set `self.blue_agent.case = self.state.blue_case` before `decide()`. Give `Agent.__init__` a `self.case = None` and clear it in its reset method.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_case_wiring.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/orchestrator.py src/agents.py tests/test_case_wiring.py
git commit -m "feat(blue): hold case on state, hand it to blue each turn"
```

---

### Task 3: Blue's note-taking tools (`record_lead`, `update_hypothesis`)

**Files:**
- Modify: `src/agents.py` (blue tool schema ~`src/agents.py:560-760`; dispatch ~`src/agents.py:1050-1131`). Do **NOT** add these to `BLUE_TOOL_PRIORITY` (they're notes, not breadth sensors).
- Test: `tests/test_case_tools.py`

**Interfaces:**
- Consumes: `src/case.py` `add_lead`, `add_hypothesis`, `norm_confidence`; `self.case` from Task 2.
- Produces: two dispatchable blue tools that mutate `self.case` at dispatch time and return a JSON string:
  - `record_lead(sensor: str, observation: str, confidence: str)` → `{"tool":"record_lead","id":<int>,"status":"ok"}`
  - `update_hypothesis(claim: str, confidence: str, lead_ids: list[int])` → `{"tool":"update_hypothesis","status":"ok"}`

- [ ] **Step 1: Write the failing tests**

```python
def test_record_lead_appends_to_the_shared_case(_blue):
    b = _blue(); b.case = new_case()
    out = b._dispatch_record_lead({"sensor": "investigate_processes",
                                   "observation": "new root proc", "confidence": "high"})
    assert json.loads(out)["status"] == "ok"
    assert b.case["leads"][0]["sensor"] == "investigate_processes"

def test_update_hypothesis_is_visible_same_turn(_blue):
    b = _blue(); b.case = new_case()
    b._dispatch_record_lead({"sensor": "investigate_connections", "observation": "x", "confidence": "low"})
    b._dispatch_update_hypothesis({"claim": "probing", "confidence": "medium", "lead_ids": [0]})
    assert current_hypothesis(b.case)["claim"] == "probing"

def test_record_lead_with_missing_confidence_does_not_crash_and_defaults_low(_blue):
    b = _blue(); b.case = new_case()
    out = b._dispatch_record_lead({"sensor": "investigate_logs", "observation": "y"})
    assert json.loads(out)["status"] == "ok"
    assert b.case["leads"][0]["confidence"] == "low"

def test_update_hypothesis_with_non_list_lead_ids_is_an_error_not_a_crash(_blue):
    b = _blue(); b.case = new_case()
    out = b._dispatch_update_hypothesis({"claim": "z", "confidence": "low", "lead_ids": "nope"})
    assert json.loads(out)["status"] == "error"

def test_note_tools_are_not_in_breadth_rotation():
    assert "record_lead" not in BLUE_TOOL_PRIORITY
    assert "update_hypothesis" not in BLUE_TOOL_PRIORITY
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_case_tools.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** the two schema entries, the two dispatch branches, and small `_dispatch_record_lead`/`_dispatch_update_hypothesis` helpers that validate (`norm_confidence`; `lead_ids` must be a list of ints else error) and call the Task 1 functions against `self.case`. Guard the whole dispatch with the existing per-tool try-except shape so a bad arg returns an error payload.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_case_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents.py tests/test_case_tools.py
git commit -m "feat(blue): record_lead / update_hypothesis note tools"
```

---

### Task 4: Single-sensor containment floor

**Files:**
- Modify: `src/agents.py` (`contain_attacker` dispatch ~`src/agents.py:1133`, the same block that already returns `status:"observed"` under observe)
- Test: `tests/test_case_floor.py`

**Interfaces:**
- Consumes: `src/case.py` `current_hypothesis`, `cited_sensors`; `self.case`.
- Produces: `contain_attacker` returns `{"tool":"contain_attacker","status":"blocked_thin_evidence","ip":<ip>,"cited_leads":<lead_ids>}` and performs **no** DROP when the current hypothesis cites leads from fewer than 2 distinct sensors. When the hypothesis cites ≥2 sensors, or there is no hypothesis / no cited leads, behavior is unchanged from today.

- [ ] **Step 1: Write the failing tests**

```python
def test_contain_blocked_when_cited_leads_are_one_sensor(_blue):
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_connections", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] == "blocked_thin_evidence"
    assert out["contained"] is not True   # no DROP credited

def test_contain_allowed_when_cited_leads_span_two_sensors(_blue):
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_processes", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] != "blocked_thin_evidence"

def test_contain_with_no_hypothesis_is_unchanged_backward_compat(_blue):
    b = _blue(); b.case = new_case()
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] != "blocked_thin_evidence"
```

- [ ] **Step 2: Run to verify they fail + the existing contain suite still passes**

Run: `uv run pytest tests/test_case_floor.py -v && uv run pytest -k contain -v`
Expected: new FAIL; existing contain tests still PASS (no regression yet)

- [ ] **Step 3: Implement** the floor at the top of the `contain_attacker` dispatch: compute `hyp = current_hypothesis(self.case)` (when `self.case`); if `hyp` and `hyp["lead_ids"]` and `len(cited_sensors(self.case, hyp["lead_ids"])) < 2`, return the blocked payload without DROP. Also add one line to `BLUE_TRIAGE_GUIDANCE`'s RESPOND/ATTRIBUTE text: act only on a hypothesis corroborated by ≥2 sensors.

- [ ] **Step 4: Run to verify pass + no regression**

Run: `uv run pytest tests/test_case_floor.py -v && uv run pytest -k contain -v`
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents.py tests/test_case_floor.py
git commit -m "feat(blue): single-sensor thin-evidence containment floor"
```

---

### Task 5: Feed the compacted case view into blue's prompt

**Files:**
- Modify: `src/agents.py` (blue's per-turn observation / guidance assembly — `decide` ~`src/agents.py:933` or `tool_guidance`)
- Test: `tests/test_case_prompt.py`

**Interfaces:**
- Consumes: `src/case.py` `compact_view`; `self.case`.
- Produces: blue's turn context includes `compact_view(self.case)` when `self.case` is set and non-empty; the full `self.case` store is never mutated by rendering.

- [ ] **Step 1: Write the failing tests**

```python
def test_blue_observation_includes_the_case_view(_blue):
    b = _blue(); b.case = new_case()
    add_lead(b.case, "investigate_connections", "foreign IP .11", "medium", 2)
    obs = b._build_observation()   # or whatever assembles blue's turn text
    assert "foreign IP .11" in obs

def test_rendering_the_view_does_not_trim_the_full_store(_blue):
    b = _blue(); b.case = new_case()
    for n in range(30):
        add_lead(b.case, "investigate_logs", f"e{n}", "low", n)
    _ = b._build_observation()
    assert len(b.case["leads"]) == 30

def test_no_case_view_when_case_is_empty_or_none(_blue):
    b = _blue(); b.case = None
    _ = b._build_observation()  # must not raise
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_case_prompt.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** — inject `compact_view(self.case)` into blue's observation text at the existing assembly point, guarded for `self.case` falsy/empty. Rendering reads only; it never writes the case.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_case_prompt.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agents.py tests/test_case_prompt.py
git commit -m "feat(blue): feed compacted case view into blue's prompt"
```

---

### Task 6: Carry the case to ep_NNN.json + record the observe/blocked counterfactual

**Files:**
- Modify: `src/arena.py` (`build_replay` ~`src/arena.py:107-130`)
- Test: `tests/test_case_replay.py`

**Interfaces:**
- Consumes: `SimulationState.blue_case`.
- Produces: `build_replay(...)` output gains `"blue_case": g("blue_case")` (the **full** store). The observe-held and floor-blocked `contain_attacker` results already carry `ip` + `cited_leads` in their output (from Tasks 3/4), so the timeline captures the counterfactual with no new structure.

- [ ] **Step 1: Write the failing tests**

```python
def test_replay_carries_the_full_case_including_old_leads():
    state = _StubState()  # duck-typed, blue_case with >12 leads incl. a cited one
    rep = build_replay(state, {"winner": None}, 1, {"observe": True})
    assert len(rep["blue_case"]["leads"]) == len(state.blue_case["leads"])

def test_observe_contain_output_carries_ip_and_cited_leads(_blue):
    b = _blue(observe=True); b.case = new_case()
    add_lead(b.case, "investigate_connections", "x", "high", 1)
    add_lead(b.case, "investigate_processes", "y", "high", 2)
    add_hypothesis(b.case, "attacker", "high", [0, 1], 2)
    out = json.loads(b._dispatch_contain_attacker({"ip": "192.168.64.11"}))
    assert out["status"] == "observed"
    assert out["ip"] == "192.168.64.11" and out["cited_leads"] == [0, 1]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_case_replay.py -v`
Expected: FAIL

- [ ] **Step 3: Implement** — add `"blue_case": g("blue_case")` to the `build_replay` dict. Ensure the `contain_attacker` observe/blocked return paths include `"ip"` and `"cited_leads"` (the current hypothesis's `lead_ids`, or `[]`).

- [ ] **Step 4: Run to verify pass + full suite green**

Run: `uv run pytest tests/test_case_replay.py -v && uv run pytest`
Expected: PASS; full suite green

- [ ] **Step 5: Commit**

```bash
git add src/arena.py src/agents.py tests/test_case_replay.py
git commit -m "feat(blue): carry case into ep_NNN.json + observe counterfactual"
```

---

### Task 7: Live validation (one episode)

**Files:** none (observation only; may write a short note into `HANDOFF.md` after).

- [ ] **Step 1** — Run one earned+observe episode against the real boxes (`.11`/`.12`) with output streaming to the terminal (user wants to watch live; no dashboard).
- [ ] **Step 2** — Read the resulting `ep_NNN.json`: confirm `blue_case` is populated — blue actually recorded ≥1 lead and ≥1 hypothesis — and that any containment carries `cited_leads`. If blue never used the note tools this episode, report that honestly as opportunistic variance (same as every prior family's live task); the plumbing is unit-proven regardless.
- [ ] **Step 3** — If the floor fired (a `blocked_thin_evidence`), note whether it was a true thin-evidence case or a false block; tune the guidance text only (no new code) if clearly wrong.
- [ ] **Step 4** — Record the outcome in `HANDOFF.md`. No commit of episode artifacts (`episode_reports/` is gitignored).

---

## Self-Review

- **Spec coverage:** case file (T1), orchestrator owns/persists + blue reasons (T2/T3), per-turn review+act same turn (T3/T4), thin-evidence floor = user's decision (T4), compacted prompt view + full store (T5), hypothesis history kept (T1 `hypotheses` list, append-only), replay carry + observe counterfactual (T6), no new scoring tier (nowhere touched), live (T7). General-purpose tool explicitly deferred — no task, by design.
- **Type consistency:** `blue_case` dict shape (`leads`/`hypotheses`) is identical across T1/T2/T5/T6; `cited_sensors`/`current_hypothesis` signatures match their T1 definitions at every call site (T4/T6).
- **Review Focus:** malformed args (T3), no-hypothesis contain (T4), unknown lead ids (T1), compaction vs. full store (T5/T6), observe counterfactual (T6) — each pinned to a task's tests.
