# PurpleLoop MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a real-time "cat-and-mouse" security simulation with an attacking Red agent, a defending Blue agent, and a visual War Room dashboard.

**Architecture:** A Python-based orchestrator manages turn-based interaction between two LLM agents who communicate with a target Linux box via an SSH Tool Executor. A FastAPI server streams these events to a WebSocket-based dashboard.

**Tech Stack:** Python 3.11+, `ollama` (LLM), `paramiko` (SSH), `fastapi` + `uvicorn` (Dashboard), `pytest` (Testing).

**Spec:** `docs/superpowers/specs/2026-09-16-purpleloop-design.md`

## Global Constraints
- All target box interaction must be via SSH.
- No "nuclear" commands (e.g., `rm -rf /`) allowed via the Tool Executor.
- All tool calls and outputs must be logged for research analysis.
- The target box must be treated as a shared state; agents only interact via this state.

---

### Task 1: Project Scaffolding & Dependencies
**Files:**
- Create: `pyproject.toml`
- Create: `src/__init__.py`

**Interfaces:**
- Produces: Project environment and dependency lock.

- [ ] **Step 1: Create `pyproject.toml` with dependencies**
```toml
[project]
name = "purpleloop"
version = "0.1.0"
dependencies = [
    "ollama",
    "paramiko",
    "fastapi",
    "uvicorn",
    "jinja2",
    "pytest"
]
```
- [ ] **Step 2: Initialize `src` directory**
Run: `mkdir -p src tests templates`
- [ ] **Step 3: Verify installation**
Run: `uv pip install .` (or equivalent)
- [ ] **Step 4: Commit**
```bash
git add pyproject.toml src/ tests/ templates/
git commit -m "chore: initialize project structure and dependencies"
```

### Task 2: Tool Executor (The SSH Bridge)
**Files:**
- Create: `src/executor.py`
- Test: `tests/test_executor.py`

**Interfaces:**
- Produces: `ToolExecutor.execute(command: str) -> str`

- [ ] **Step 1: Write failing test for `execute`**
```python
def test_execute_simple_command():
    executor = ToolExecutor(host="...", user="...", pwd="...")
    assert "bash" in executor.execute("echo bash")
```
- [ ] **Step 2: Implement `ToolExecutor` using `paramiko`**
Implement `execute` method with a command blacklist and timeout handling.
- [ ] **Step 3: Implement command guardrails**
Add a list of forbidden keywords (e.g., `rm -rf /`, `mkfs`).
- [ ] **Step 4: Run tests to verify success and guardrail blocks**
Run: `pytest tests/test_executor.py`
- [ ] **Step 5: Commit**
```bash
git add src/executor.py tests/test_executor.py
git commit -m "feat: implement SSH Tool Executor with guardrails"
```

### Task 3: Agent Interface (LLM Tool Calling)
**Files:**
- Create: `src/agents.py`

**Interfaces:**
- Consumes: `ToolExecutor.execute`
- Produces: `Agent.act(state: str) -> ToolCall | Text`

- [ ] **Step 1: Define `Agent` class and System Prompts**
Define `RED_SYSTEM_PROMPT` (attack focus) and `BLUE_SYSTEM_PROMPT` (defense focus).
- [ ] **Step 2: Implement `act` method using `ollama.chat`**
Integrate the `tools` parameter to support structured function calling.
- [ ] **Step 3: Implement `process_tool_call`**
A method that takes an Ollama tool call, passes it to the `ToolExecutor`, and returns the result.
- [ ] **Step 4: Verify Red agent can call `nmap` and Blue agent can call `ls`**
Simple script to test a single round of interaction.
- [ ] **Step 5: Commit**
```bash
git add src/agents.py
git commit -m "feat: implement Red/Blue agent logic with tool calling"
```

### Task 4: Loop Orchestrator (The Engine)
**Files:**
- Create: `src/orchestrator.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: `Agent`, `ToolExecutor`
- Produces: `Orchestrator.run_simulation()`

- [ ] **Step 1: Implement `SimulationState` dataclass**
Track current turn, history of commands, and flag capture status.
- [ ] **Step 2: Implement turn-based logic**
Round-robin rotation between Red and Blue agents.
- [ ] **Step 3: Implement Victory Condition checks**
Check for flag content in `stdout` or lack of Red progress.
- [ ] **Step 4: Write failing test for turn rotation and win conditions**
```python
def test_turn_rotation():
    orch = Orchestrator(...)
    orch.step()
    assert orch.current_turn == "blue"
```
- [ ] **Step 5: Run tests and verify the simulation loop**
- [ ] **Step 6: Commit**
```bash
git add src/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: implement turn-based simulation orchestrator"
```

### Task 5: War Room Dashboard (Visualization)
**Files:**
- Create: `src/dashboard.py`
- Create: `templates/dashboard.html`

**Interfaces:**
- Consumes: `Orchestrator` events
- Produces: WebSocket stream of battle logs

- [ ] **Step 1: Implement FastAPI server with WebSocket endpoint**
Server should maintain a list of connected clients and broadcast orchestrator events.
- [ ] **Step 2: Create `dashboard.html` with side-by-side feeds**
Implement CSS for Red (Left) and Blue (Right) feeds and a central "Battle Log."
- [ ] **Step 3: Integrate `Orchestrator` events with Dashboard**
Add a callback in the orchestrator to push updates to the FastAPI server.
- [ ] **Step 4: Verify end-to-end flow (Run simulation $\rightarrow$ View in Browser)**
- [ ] **Step 5: Commit**
```bash
git add src/dashboard.py templates/dashboard.html
git commit -m "feat: implement real-time War Room dashboard"
```

### Task 6: End-to-End Integration & Tuning
**Files:**
- Create: `main.py`

- [ ] **Step 1: Create `main.py` to launch the Dashboard and Simulation**
- [ ] **Step 2: Run a full simulation against the Target Box**
- [ ] **Step 3: Tune system prompts for better tool usage**
- [ ] **Step 4: Final verification of the "Learning Loop" (Blue defends a repeated attack)**
- [ ] **Step 5: Commit**
```bash
git add main.py
git commit -m "feat: final integration and simulation tuning"
```
