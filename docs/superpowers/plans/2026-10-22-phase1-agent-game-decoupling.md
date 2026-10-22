# Phase 1 — Agent/Game Decoupling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple red/blue into self-contained agents that can run standalone (no `Orchestrator`), with the arena rebuilt on top as pair + referee + reset.

**Architecture:** Incremental strangle. Relocate the "brain" (steering, phase logic, repeat-nudge, cred memory, reflection) out of `Orchestrator` and into `RedAgent`/`BlueAgent`, one cluster at a time, keeping all tests green and the arena working at every step. Scoring stays as a passive `Referee` that reads trajectories. Box-facts move behind a `TargetProfile`.

**Tech Stack:** Python 3.13, dataclasses, type hints, uv, ruff, pytest, mypy. Ollama (`gemma4:31b-cloud`) for live re-baseline only.

**Spec:** `docs/superpowers/specs/2026-10-22-phase1-agent-game-decoupling-design.md`

## Global Constraints

- Python 3.13; full type hints on all new code; f-strings; dataclasses for structured data.
- Tooling: `uv run` for everything; `ruff` clean on new/changed files; `pytest` (not unittest); `mypy` introduces no new errors.
- No new dependencies; no lockfile changes.
- **No-seeding rule (hard):** the agent never receives which accounts/services are privileged; box-facts are discovered at runtime. `TargetProfile` carries connection + objective + sensor locations + optional *technique-only* env-notes — never answers.
- **Ratchet:** all existing tests (179 at plan time) stay green at the end of every task; a red bar stops progress.
- Commit after every task. Never `git add .` — stage named paths. Do not push (human's call).

## Review Focus

The spec implies these inputs/conditions that task tests must pin (each is added to the owning task below):

- **Red campaign exhausts `max_turns` without meeting its objective** → `run()` returns `Trajectory(objective_met=False)`, no exception. (Task 10)
- **Executor raises mid-run** → `run()` returns a partial `Trajectory` with the turns so far, not a crash. (Task 10)
- **`BlueAgent.run()` has no objective** → terminates cleanly at `max_turns`. (Task 10)
- **Missing/empty `knowledge.json`** → agent loads empty lessons, no crash. (Task 8)
- **`decide()` on turn 0 (empty own-history)** → produces a valid initial observation (the `initial_enum` phase for red). (Task 7)

---

## File Structure

- Create `src/trajectory.py` — `Turn`, `Trajectory`, `Action` dataclasses (shared vocabulary; focused, dependency-free).
- Create `src/target.py` — `TargetProfile` dataclass (connection/objective/sensor-locations/env-notes).
- Create `src/referee.py` — `Referee` (scoring/tiers/verdict/dwell, reads a `Trajectory`). Extracted from `Orchestrator` in Task 11.
- Modify `src/agents.py` — add `RedAgent`/`BlueAgent` subclasses; relocate brain methods; `decide()`, `run()`, own history, reflection ownership.
- Modify `src/orchestrator.py` — shrink: brain methods leave; becomes pair-loop + grace + delegates scoring to `Referee`.
- Modify `src/arena.py` — builds subclasses; later hosts the `Learner` loop.
- Tests: `tests/test_agent_standalone.py` (new), `tests/test_referee.py` (new), characterization tests appended to `tests/test_orchestrator.py` / `tests/test_agents.py`.

---

## Task 1: Trajectory vocabulary + RedAgent/BlueAgent subclasses

Behavior-neutral scaffolding: introduce the types and the subclasses, make the arena build subclass instances. No brain moves yet.

**Files:**
- Create: `src/trajectory.py`
- Modify: `src/agents.py` (add subclasses at end), `src/arena.py` (`build_agents`)
- Test: `tests/test_agent_standalone.py`

**Interfaces:**
- Produces: `Turn(n:int, observation:str, action:Any, output:str)`, `Trajectory(role:str, turns:list[Turn], objective_met:bool=False)`; `class RedAgent(Agent)`, `class BlueAgent(Agent)` — same constructor params as `Agent`, role fixed by the subclass.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agent_standalone.py
from src.trajectory import Turn, Trajectory
from src.agents import RedAgent, BlueAgent
from src.mock_executor import MockExecutor

def test_trajectory_dataclasses_hold_turns():
    t = Trajectory(role="red", turns=[Turn(n=0, observation="o", action=None, output="x")])
    assert t.objective_met is False
    assert t.turns[0].output == "x"

def test_red_blue_agents_are_agents_with_fixed_roles():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    assert red.role == "red" and blue.role == "blue"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q`
Expected: FAIL (`ModuleNotFoundError: src.trajectory` / `ImportError: RedAgent`).

- [ ] **Step 3: Create the trajectory module**

```python
# src/trajectory.py
from dataclasses import dataclass, field
from typing import Any, List

@dataclass
class Turn:
    n: int
    observation: str
    action: Any          # tool-call list or text the agent emitted
    output: str

@dataclass
class Trajectory:
    role: str
    turns: List[Turn] = field(default_factory=list)
    objective_met: bool = False
```

- [ ] **Step 4: Add the subclasses**

In `src/agents.py`, after the `Agent` class, add subclasses that fix the role. `Agent.__init__` currently takes `role` first; the subclasses pass it:

```python
class RedAgent(Agent):
    def __init__(self, executor, model="llama3.2:latest", **kw):
        super().__init__(role="red", executor=executor, model=model, **kw)

class BlueAgent(Agent):
    def __init__(self, executor, model="llama3.2:latest", **kw):
        super().__init__(role="blue", executor=executor, model=model, **kw)
```

- [ ] **Step 5: Point `build_agents` at the subclasses**

In `src/arena.py` `build_agents`, replace `Agent(role="red", ...)` with `RedAgent(...)` and `Agent(role="blue", ...)` with `BlueAgent(...)`, keeping every other argument identical. Import `RedAgent, BlueAgent`.

- [ ] **Step 6: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (179 + 2 new). The arena now builds subclasses; behavior unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/trajectory.py src/agents.py src/arena.py tests/test_agent_standalone.py
git commit -m "refactor(agents): add Trajectory types + Red/BlueAgent subclasses"
```

---

## Task 2: TargetProfile + pull `payroll_app.php` out of core doctrine

Gather scattered box-facts into one injected object and remove the box *name* from red's core prompt (discovery, not baking).

**Files:**
- Create: `src/target.py`
- Modify: `src/agents.py` (RED earned addendum; constructor accepts `target`)
- Test: `tests/test_agents.py` (append), `tests/test_agent_standalone.py` (append)

**Interfaces:**
- Produces: `TargetProfile(host:str, flag_path:str="/root/flag.txt", objective:str="root", env_notes:str="")`; `Agent.__init__(..., target: TargetProfile | None = None)`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agents.py (append)
from src.target import TargetProfile
from src.agents import RedAgent
from src.mock_executor import MockExecutor

def test_red_core_prompt_has_no_box_specific_app_name():
    red = RedAgent(executor=MockExecutor(), earned=True)
    assert "payroll_app.php" not in red.system_prompt  # discovered, not baked

def test_env_notes_from_profile_reach_the_prompt():
    prof = TargetProfile(host="x", env_notes="HINT: a payroll web app is present")
    red = RedAgent(executor=MockExecutor(), earned=True, target=prof)
    assert "payroll web app" in red.system_prompt
```

(If the Agent stores its assembled system prompt under a different attribute, use that name; expose it as `self.system_prompt` in Step 3.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_agents.py -q -k "box_specific or env_notes"`
Expected: FAIL (`payroll_app.php` still present; `TargetProfile` missing).

- [ ] **Step 3: Create TargetProfile and thread it**

```python
# src/target.py
from dataclasses import dataclass

@dataclass
class TargetProfile:
    host: str
    flag_path: str = "/root/flag.txt"
    objective: str = "root"          # "foothold" | "exfil" | "root"
    env_notes: str = ""              # TECHNIQUE hints only (training), never answers
```

In `src/agents.py`: `Agent.__init__` gains `target: "TargetProfile | None" = None`; store `self.target = target`. When assembling the earned addendum, append `target.env_notes` (if any) as a clearly-labeled "ENVIRONMENT NOTES" block, and expose the final assembled prompt as `self.system_prompt`.

- [ ] **Step 4: De-bake the app name**

In the earned addendum (the FOOTHOLD DISCIPLINE / sqlmap block), replace the literal `payroll_app.php` example with a generic phrasing: "find the web application and its login/search forms, then run sqlmap against the form you discover (`sqlmap -u \"<discovered-url>\" --forms --batch --random-agent --dump`)." Keep the technique template; drop the box name.

- [ ] **Step 5: Run tests**

Run: `uv run python -m pytest tests/test_agents.py -q`
Expected: PASS. Then full suite: `uv run python -m pytest -q` → PASS (behavior preserved; red now discovers the app name).

- [ ] **Step 6: Commit**

```bash
git add src/target.py src/agents.py tests/test_agents.py
git commit -m "refactor(target): TargetProfile seam; discover app name, don't bake it"
```

---

## Task 3: Agent owns its own history stream

Each agent accumulates its own `Turn` list. Still populated in parallel with the shared `SimulationState.history`; not yet used for steering.

**Files:**
- Modify: `src/agents.py` (`self.history: list[Turn]`, `record_turn()`), `src/orchestrator.py` (`step()` appends to the acting agent's own history too)
- Test: `tests/test_agent_standalone.py` (append)

**Interfaces:**
- Produces: `Agent.history: list[Turn]`; `Agent.record_turn(observation:str, action, output:str) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_agent_standalone.py (append)
from src.agents import RedAgent
from src.mock_executor import MockExecutor

def test_agent_records_its_own_turns():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.record_turn(observation="obs", action=[{"x": 1}], output="out")
    assert len(red.history) == 1
    assert red.history[0].observation == "obs"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q -k own_turns`
Expected: FAIL (`AttributeError: 'RedAgent' object has no attribute 'history'`).

- [ ] **Step 3: Implement own history**

In `Agent.__init__`: `self.history: list[Turn] = []`. Add:

```python
def record_turn(self, observation: str, action, output: str) -> None:
    self.history.append(Turn(n=len(self.history), observation=observation, action=action, output=output))
```

- [ ] **Step 4: Populate it from the orchestrator (parallel to shared history)**

In `src/orchestrator.py` `step()`, where a tool output is appended to `self.state.history`, also call `agent.record_turn(observation=state_summary, action=tool_call, output=output)` for the acting agent. (One line alongside the existing append; shared history is untouched.)

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (180). Shared behavior unchanged; agents now also carry own history.

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/orchestrator.py tests/test_agent_standalone.py
git commit -m "refactor(agents): agents accumulate their own Turn history"
```

---

## Task 4: Move red phase logic + guidance into RedAgent

Relocate `_update_red_phase`, `_RED_PHASE_GUIDANCE`, `_red_phase_guidance`, `_flag_read_guidance`, `_root_available`, `_discovered_flag_paths` into `RedAgent`, reading the agent's **own** history and own foothold flag. Characterization test proves identical output.

**Files:**
- Modify: `src/agents.py` (RedAgent gains the methods), `src/orchestrator.py` (delegates red phase guidance to the agent)
- Test: `tests/test_orchestrator.py` (characterization, append)

**Interfaces:**
- Consumes: `RedAgent.history` (Task 3).
- Produces: `RedAgent.phase_guidance() -> str` (returns the `"Red Phase: ..."` string the orchestrator used to build), `RedAgent.has_foothold: bool`.

- [ ] **Step 1: Write the characterization test (captures current output)**

```python
# tests/test_orchestrator.py (append)
from src.agents import RedAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor

def test_redagent_phase_guidance_matches_legacy_flag_discovery():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    red.history = [
        Turn(0, "", {"function": {"name": "execute_command", "arguments": {"command": "whoami"}}}, "vagrant"),
        Turn(1, "", {"function": {"name": "execute_command", "arguments": {"command": "id"}}},
             "uid=900(vagrant) gid=900(vagrant) groups=900(vagrant),27(sudo)"),
    ]
    g = red.phase_guidance()
    assert "Red Phase: flag_discovery" in g
    assert "find / -maxdepth 4 -name flag.txt" in g
```

Add a second case mirroring the privilege-seam test: give the agent `has_foothold = True` and an unprivileged `id` output, assert `"Red Phase: privilege_check"` and `"ESCALATE"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_orchestrator.py -q -k redagent_phase`
Expected: FAIL (`RedAgent` has no `phase_guidance`).

- [ ] **Step 3: Move the methods into RedAgent**

Move `_RED_PHASE_GUIDANCE` (module constant) near `RedAgent`. Copy `_update_red_phase`, `_flag_read_guidance`, `_root_available`, `_discovered_flag_paths`, and the public `phase_guidance` (was `_red_phase_guidance`) onto `RedAgent`. Rewrite their internals:
- `self._red_commands()` / `self._red_tool_history()` → iterate `self.history` (filter not needed — it's already red's own).
- `TIER_FOOTHOLD in self.state.red_tiers` (the Phase-A seam) → `self.has_foothold` (a bool the agent sets when it authenticates; default `False`).
- `self.flag_path` → `self.target.flag_path if self.target else "/root/flag.txt"`.

- [ ] **Step 4: Delegate from the orchestrator**

In `src/orchestrator.py` `_build_state_summary`, replace the red branch's `self._red_phase_guidance()` call with `self.red_agent.phase_guidance()`. Set `self.red_agent.has_foothold = TIER_FOOTHOLD in self.state.red_tiers` just before the call (temporary bridge; removed in Task 7 once the agent tracks its own foothold). Delete the now-dead orchestrator copies of the moved methods.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS. The existing `test_red_phase_*` orchestrator tests still pass (they drive `_build_state_summary`, which now delegates).

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/orchestrator.py tests/test_orchestrator.py
git commit -m "refactor(red): phase logic self-contained in RedAgent"
```

---

## Task 5: Move blue tool-steering into BlueAgent

Relocate `_blue_tool_guidance`, `_blue_tools_used`, `_blue_confirmed_attackers`, breadth rotation, and `_BLUE_TOOL_PRIORITY` into `BlueAgent`, reading blue's own history. Characterization test.

**Files:**
- Modify: `src/agents.py` (BlueAgent), `src/orchestrator.py` (delegate)
- Test: `tests/test_orchestrator.py` (characterization, append)

**Interfaces:**
- Consumes: `BlueAgent.history`.
- Produces: `BlueAgent.tool_guidance(observe: bool, confirmed_attackers: list[str], contained: bool) -> str`.

Note: the contain-order depends on game facts (`observe`, who's confirmed, whether already contained). Pass those in as arguments for now — blue's *brain* decides what to say; the game supplies the current evidence/toggle. (Task 7 wires evidence from blue's own tool outputs.)

- [ ] **Step 1: Write the characterization test**

```python
# tests/test_orchestrator.py (append)
from src.agents import BlueAgent
from src.mock_executor import MockExecutor

def test_blueagent_tool_guidance_defaults_to_logs_heartbeat():
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    g = blue.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "investigate_logs" in g

def test_blueagent_contain_order_on_confirmed_attacker():
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    g = blue.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "contain_attacker" in g and "192.168.64.11" in g
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_orchestrator.py -q -k blueagent`
Expected: FAIL (`BlueAgent` has no `tool_guidance`).

- [ ] **Step 3: Move the methods**

Move `_BLUE_TOOL_PRIORITY` near `BlueAgent`. Copy `_blue_tools_used`, breadth-rotation, and `_blue_tool_guidance` (now `tool_guidance`) onto `BlueAgent`, iterating `self.history` for tools-used. The contain-order branch now reads its `observe`/`confirmed_attackers`/`contained` parameters instead of `self.observe`/`self._blue_confirmed_attackers()`/`self.state.blue_contain_turn`.

- [ ] **Step 4: Delegate from the orchestrator**

In `_build_state_summary` blue branch, call
`self.blue_agent.tool_guidance(observe=self.observe, confirmed_attackers=self._blue_confirmed_attackers(), contained=self.state.blue_contain_turn is not None)`.
Keep `_blue_confirmed_attackers` in the orchestrator for now (it reads shared history; Task 7 moves evidence to blue's own outputs). Delete the dead `_blue_tool_guidance`/`_blue_tools_used` copies.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (existing blue-guidance orchestrator tests still green via delegation).

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/orchestrator.py tests/test_orchestrator.py
git commit -m "refactor(blue): tool-steering self-contained in BlueAgent"
```

---

## Task 6: Move the repeat-nudge into Agent

`_repeat_nudge` is role-pure already; move it to the base `Agent`, reading `self.history`.

**Files:**
- Modify: `src/agents.py` (base `Agent.repeat_nudge()`), `src/orchestrator.py` (delegate)
- Test: `tests/test_orchestrator.py` (characterization, append)

**Interfaces:**
- Produces: `Agent.repeat_nudge() -> str`.

- [ ] **Step 1: Write the characterization test**

```python
# tests/test_orchestrator.py (append)
from src.agents import RedAgent
from src.trajectory import Turn
from src.mock_executor import MockExecutor

def test_repeat_nudge_fires_on_repeated_tool_calls():
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    call = {"function": {"name": "execute_command", "arguments": {"command": "ls"}}}
    red.history = [Turn(0, "", call, "a"), Turn(1, "", call, "a")]
    assert "Repetition check" in red.repeat_nudge()
```

(Confirm the exact phrase from the current `_repeat_nudge` text and match it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_orchestrator.py -q -k repeat_nudge`
Expected: FAIL (`RedAgent` has no `repeat_nudge`).

- [ ] **Step 3: Move the method**

Copy `_repeat_nudge` onto base `Agent` as `repeat_nudge(self)`, iterating `self.history` (drop the `role` arg and the role filter; `self.history` is already this agent's). Keep blue's `investigate_logs` exclusion keyed on `self.role == "blue"`.

- [ ] **Step 4: Delegate from the orchestrator**

In `_build_state_summary`, replace `self._repeat_nudge(role)` with `agent.repeat_nudge()`. Delete the orchestrator copy.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/orchestrator.py tests/test_orchestrator.py
git commit -m "refactor(agents): repeat-nudge self-contained in Agent"
```

---

## Task 7: `Agent.decide()` — the strangle seam

The agent assembles its **own** observation (own history tail + own phase/tool guidance + own nudge + own cred/evidence) and acts. The orchestrator stops building `state_summary` for the agent and calls `agent.decide()`.

**Files:**
- Modify: `src/agents.py` (`decide()`, own foothold/evidence tracking), `src/orchestrator.py` (`step()` calls `decide()`)
- Test: `tests/test_agent_standalone.py` (append)

**Interfaces:**
- Consumes: Tasks 4–6 (`phase_guidance`, `tool_guidance`, `repeat_nudge`), `self.history`.
- Produces: `Agent.decide() -> Any` (the action: tool-call list or text); `RedAgent.has_foothold`/`foothold_cred` set from own outputs; `BlueAgent.confirmed_attackers()` from own outputs.

- [ ] **Step 1: Write the failing test (Review Focus: turn-0 observation)**

```python
# tests/test_agent_standalone.py (append)
from src.agents import RedAgent
from src.mock_executor import MockExecutor

def test_decide_on_empty_history_builds_initial_observation(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    captured = {}
    monkeypatch.setattr(red, "act", lambda obs: captured.setdefault("obs", obs) or "noop")
    red.decide()
    assert "Red Phase: initial_enum" in captured["obs"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q -k initial_observation`
Expected: FAIL (`RedAgent` has no `decide`).

- [ ] **Step 3: Implement `decide()` and own-state tracking**

Add to base `Agent`:

```python
def build_observation(self) -> str:
    obs = f"Turn {len(self.history)}. Current Role: {self.role}. History: {self._own_tail()}"
    obs += self._role_guidance()     # red: phase_guidance(); blue: tool_guidance(...)
    obs += self.repeat_nudge()
    return obs

def decide(self):
    return self.act(self.build_observation())
```

`_own_tail()` returns the last 5 of `self.history` rendered like the old `history[-5:]`. `_role_guidance()` is overridden per subclass: `RedAgent` returns `self.phase_guidance()` plus its cred block (moved from the orchestrator's cred resurfacing, read from `self.foothold_cred`); `BlueAgent` returns `self.tool_guidance(observe=self.observe, confirmed_attackers=self.confirmed_attackers(), contained=self.contained)`.

Move `_capture_foothold_cred` logic onto `RedAgent` (it sets `self.foothold_cred` and `self.has_foothold` from its own tool outputs). Move `_blue_confirmed_attackers` onto `BlueAgent.confirmed_attackers()` reading `self.history`. Give `BlueAgent` an `observe` attr (already a constructor param) and a `contained` bool it sets when its own `contain_attacker` output confirms.

- [ ] **Step 4: Call `decide()` from the orchestrator**

In `src/orchestrator.py` `step()`: replace `state_summary = self._build_state_summary(role)` + `agent.act(state_summary)` with `action = agent.decide()`. The orchestrator still records the shared-history entries (for the referee, until Task 11) and still runs tier detection + grace. Remove the temporary `has_foothold` bridge from Task 4 (the agent now tracks its own). Delete `_build_state_summary` and the orchestrator's cred-resurfacing + `_blue_confirmed_attackers` once nothing references them.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS. Orchestrator tests that asserted on `_build_state_summary` output now assert on `agent.build_observation()` — update those call sites (same assertions, new entry point).

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/orchestrator.py tests/test_agent_standalone.py tests/test_orchestrator.py
git commit -m "refactor(agents): decide() — agents build own observation and self-steer"
```

---

## Task 8: Agent owns reflection + knowledge

Move knowledge load/save and reflection triggering out of the orchestrator/arena; the agent owns its lessons.

**Files:**
- Modify: `src/agents.py` (`load_knowledge`/`save_knowledge`/`reflect`), `src/orchestrator.py` + `src/arena.py` (delegate)
- Test: `tests/test_agent_standalone.py` (append; Review Focus: missing knowledge file)

**Interfaces:**
- Produces: `Agent.reflect(outcome:str) -> str | None` (calls `summarize_experience`, appends to and persists own lessons via `merge_lesson`/`dedupe_lessons`); `Agent.knowledge_path: Path`.

- [ ] **Step 1: Write the failing test (Review Focus: empty/missing knowledge)**

```python
# tests/test_agent_standalone.py (append)
from pathlib import Path
from src.agents import RedAgent
from src.mock_executor import MockExecutor

def test_agent_loads_empty_lessons_when_file_missing(tmp_path):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest",
                   knowledge_path=tmp_path / "nope.json")
    assert red.experience == []     # no crash, empty lessons
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q -k empty_lessons`
Expected: FAIL (`knowledge_path` not accepted).

- [ ] **Step 3: Move knowledge ownership**

`Agent.__init__` accepts `knowledge_path: Path | None = None`. On init, load this agent's lessons (reuse `merge_lesson`/`dedupe_lessons` already in the codebase; load only this role's list) into `self.experience`, wrapping the read in try/except → `[]` on missing/corrupt. Add `reflect(outcome)` that calls `self.summarize_experience(self.history, outcome)`, merges+dedupes into `self.experience`, and persists. Keep the existing `knowledge.json` schema (`{"red": [...], "blue": [...]}`).

- [ ] **Step 4: Delegate**

In `src/arena.py`, stop loading knowledge / driving `summarize_experience` directly; after each episode call `red.reflect(outcome)` / `blue.reflect(outcome)`. In `src/orchestrator.py`, remove `_load_knowledge` if now unused.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS. Confirm an arena mock run still writes lessons: `uv run python -m src.arena --episodes 1 --host mock` then check the knowledge file grew.

- [ ] **Step 6: Commit**

```bash
git add src/agents.py src/arena.py src/orchestrator.py tests/test_agent_standalone.py
git commit -m "refactor(agents): agents own their reflection + knowledge"
```

---

## Task 9: Each agent uses ONLY its own history — RE-BASELINE CHECKPOINT

Stop feeding the shared `history[-5:]` into observations; `_own_tail()` already reads `self.history`. Remove the orchestrator's parallel shared-history writes where only the agent needs them. **This changes what the model sees → behavior may shift.**

**Files:**
- Modify: `src/orchestrator.py` (drop shared-history reliance for observation; referee still gets what it needs)
- Test: existing suite + a live batch

- [ ] **Step 1: Confirm observation no longer reads shared history**

Grep: `uv run python -c "import re,sys; print('history[-5:]' in open('src/agents.py').read())"` should be referencing `self.history` only. Ensure `build_observation`/`_own_tail` never touch `self.state`.

- [ ] **Step 2: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS (offline behavior unchanged for unit tests; they drive agent methods directly).

- [ ] **Step 3: Commit the code change**

```bash
git add src/orchestrator.py src/agents.py
git commit -m "refactor(agents): observations read only the agent's own history"
```

- [ ] **Step 4: LIVE RE-BASELINE (cloud spend — human-gated)**

Run the standard batch and compare to the last good numbers (blue 5/0 · red root 4/5 · foothold 5/5):

```bash
uv run python -m src.arena --episodes 5 --host 192.168.64.12 \
  --jump-host 192.168.64.11 --earned --model gemma4:31b-cloud \
  --max-turns 20 --observe --remediate-grace 4
```

Expected: tier distribution within noise of baseline (red reaches root in ~4/5, foothold ~5/5, blue detects). If it drifts materially, STOP — the own-history change altered behavior; investigate before Task 10. Record the result in the commit message of Task 10 or a NOTES entry.

---

## Task 10: `Agent.run()` — the standalone loop

The agent drives itself: observe → decide → execute → record → repeat, until objective or `max_turns`. This is the definition-of-done for standalone operation.

**Files:**
- Modify: `src/agents.py` (`run()`, objective detection, error resilience)
- Test: `tests/test_agent_standalone.py` (append; Review Focus: max_turns, executor failure, blue monitor)

**Interfaces:**
- Consumes: `decide()`, `record_turn()`, executor.
- Produces: `Agent.run(max_turns:int) -> Trajectory`.

- [ ] **Step 1: Write the failing tests (all three Review-Focus cases)**

```python
# tests/test_agent_standalone.py (append)
from src.trajectory import Trajectory
from src.agents import RedAgent, BlueAgent
from src.mock_executor import MockExecutor

def test_red_run_stops_at_max_turns_without_objective(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(red, "decide", lambda: "noop")       # never wins
    traj = red.run(max_turns=3)
    assert isinstance(traj, Trajectory) and traj.objective_met is False
    assert len(traj.turns) <= 3

def test_run_survives_executor_error(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    def boom():
        raise RuntimeError("ssh died")
    monkeypatch.setattr(red, "decide", boom)
    traj = red.run(max_turns=2)                               # partial, no crash
    assert isinstance(traj, Trajectory)

def test_blue_monitor_terminates_at_max_turns(monkeypatch):
    blue = BlueAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(blue, "decide", lambda: "watch")
    traj = blue.run(max_turns=2)
    assert len(traj.turns) <= 2 and traj.objective_met is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q -k "run_stops or executor_error or monitor_terminates"`
Expected: FAIL (`run` not defined).

- [ ] **Step 3: Implement `run()`**

```python
def run(self, max_turns: int) -> Trajectory:
    traj = Trajectory(role=self.role)
    for n in range(max_turns):
        obs = self.build_observation()
        try:
            action = self.act(obs)
            output = self._execute(action)         # dispatch tool calls; "" for text
        except Exception as e:                      # resilience: partial trajectory
            traj.turns.append(Turn(n, obs, None, f"run error: {e}"))
            break
        self.record_turn(obs, action, output)
        traj.turns.append(self.history[-1])
        if self.objective_met():                    # RedAgent overrides; BlueAgent -> False
            traj.objective_met = True
            break
    return traj
```

`_execute(action)` reuses the existing per-tool dispatch (`process_tool_call` for each call; text → `""`). `RedAgent.objective_met()` returns True when it has read the flag / confirmed root (reuse the existing victory signal, read from its own last output); `BlueAgent.objective_met()` returns `False` (a monitor never "wins" on its own).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -m pytest tests/test_agent_standalone.py -q`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `uv run python -m pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agents.py tests/test_agent_standalone.py
git commit -m "feat(agents): Agent.run() standalone campaign/monitor loop"
```

---

## Task 11: Extract the Referee; shrink Orchestrator to Arena — RE-BASELINE CHECKPOINT

Scoring becomes a passive `Referee` that reads trajectories + sim facts. The orchestrator becomes a thin pair-loop (drive two `decide()`s, apply grace, reset) that hands off to the referee.

**Files:**
- Create: `src/referee.py`
- Modify: `src/orchestrator.py` (delegate scoring), `tests/test_tiers.py` (repoint to Referee)
- Test: `tests/test_referee.py` (new)

**Interfaces:**
- Produces: `Referee` with `tier_scoreboard()`, `verdict()`, `detection_dwell()`, `resolve_outcome()` reading recorded milestones + both trajectories. Same return shapes as today's `Orchestrator` methods.

- [ ] **Step 1: Write the characterization test**

```python
# tests/test_referee.py
from src.referee import Referee
from src.orchestrator import SimulationState, TIER_FOOTHOLD, TIER_ROOT

def test_referee_verdict_matches_legacy_for_foothold_defended():
    state = SimulationState()
    state.red_tiers[TIER_FOOTHOLD] = 2
    state.blue_tier_detect[TIER_FOOTHOLD] = 3
    ref = Referee(state, detect_within_turns=3)
    assert ref.verdict() == "red reached T1 (foothold); blue defended T1"
```

Add a root case mirroring an existing `test_tiers.py` assertion to prove parity.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_referee.py -q`
Expected: FAIL (`src.referee` missing).

- [ ] **Step 3: Move scoring into Referee**

Create `src/referee.py` with a `Referee` that takes the `SimulationState` (milestones) + `detect_within_turns`. Move `tier_scoreboard`, `verdict`, `detection_dwell`, `_resolve_outcome`, and the tier-detection helpers (`_check_red_foothold`, `_check_blue_*`, `_check_red_victory`) into it. The orchestrator keeps the turn loop + grace + `record_turn` wiring, and constructs a `Referee` to score; `arena.build_scorecard`/`verdict` call the referee. Keep `SimulationState` where it is (shared milestone record the referee reads).

- [ ] **Step 4: Repoint callers + run suite**

Update `tests/test_tiers.py` imports to exercise `Referee` (same assertions). Run `uv run python -m pytest -q` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/referee.py src/orchestrator.py src/arena.py tests/test_referee.py tests/test_tiers.py
git commit -m "refactor(referee): extract scoring; orchestrator is now pair-loop + referee"
```

- [ ] **Step 6: LIVE RE-BASELINE (cloud spend — human-gated)**

Re-run the Task 9 batch command. Expected: same tier distribution as the Task 9 baseline. If it holds, steps 1–5 of the spec are complete (standalone agents + arena-on-referee, behavior preserved). Record the numbers.

---

## Task 12: Extract the single-agent Learner (portable layer 2)

Pull the per-system learning loop out of the arena into a standalone `Learner` so one agent can run N episodes against a target and accumulate lessons, with no adversary or scoring.

**Files:**
- Create: `src/learner.py`
- Modify: `src/arena.py` (the dojo arena uses `Learner` internally for each side's reflection loop, or is layered on top)
- Test: `tests/test_learner.py` (new)

**Interfaces:**
- Produces: `Learner(agent).train(target, episodes:int, max_turns:int, reset_fn=None) -> list[Trajectory]` — runs `agent.run()` per episode, calls `agent.reflect()` between, returns the trajectories; lessons accumulate in the agent's knowledge.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_learner.py
from src.learner import Learner
from src.agents import RedAgent
from src.mock_executor import MockExecutor

def test_learner_runs_n_episodes_and_reflects(monkeypatch):
    red = RedAgent(executor=MockExecutor(), model="llama3.2:latest")
    monkeypatch.setattr(red, "decide", lambda: "noop")
    monkeypatch.setattr(red, "reflect", lambda outcome: red.experience.append("lesson"))
    trajs = Learner(red).train(target=None, episodes=3, max_turns=2)
    assert len(trajs) == 3
    assert red.experience.count("lesson") == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_learner.py -q`
Expected: FAIL (`src.learner` missing).

- [ ] **Step 3: Implement `Learner`**

```python
# src/learner.py
from typing import Callable, List, Optional
from src.trajectory import Trajectory

class Learner:
    def __init__(self, agent):
        self.agent = agent

    def train(self, target, episodes: int, max_turns: int,
              reset_fn: Optional[Callable] = None) -> List[Trajectory]:
        trajs: List[Trajectory] = []
        for i in range(1, episodes + 1):
            if reset_fn:
                reset_fn(self.agent.executor, i)
            self.agent.history = []                 # fresh episode
            traj = self.agent.run(max_turns)
            self.agent.reflect("neutral" if not traj.objective_met else "objective met")
            trajs.append(traj)
        return trajs
```

- [ ] **Step 4: Run tests + suite**

Run: `uv run python -m pytest tests/test_learner.py -q` → PASS; then `uv run python -m pytest -q` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/learner.py tests/test_learner.py
git commit -m "feat(learner): portable single-agent N-episode learning loop"
```

---

## Done criteria

- `RedAgent(...).run(max_turns=N)` and `BlueAgent(...).run()` execute standalone with no `Orchestrator`.
- `python -m src.arena ... --observe` still runs red-vs-blue with scoring + learning, on top of the self-contained agents.
- All tests green; two live re-baselines (Task 9, Task 11) hold against blue 5/0 · red root 4/5 · foothold 5/5.
- Box-facts routed through `TargetProfile`; `payroll_app.php` discovered, not baked.
- `Learner` delivers portable per-system learning (layer 2).
