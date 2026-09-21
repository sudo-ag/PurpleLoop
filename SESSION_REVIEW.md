# PurpleLoop — Session Review (2026-09-20)

## Environment
- Host: Kali Linux, Python 3.13.2
- Ollama: v0.34.2, reachable on `:11434`
- Models available: `llama3.2:1b` (~1.3GB), `llama3.2:latest` (~2GB), `qwen2.5:7b-instruct-q4_0` (~4.4GB)
- `uv` located at `/home/koda/.hermes/bin/uv` (not on PATH); project uses `uv` for deps

## Project Structure (confirmed)

```
PurpleLoop/
├── main.py                  # Entry point: dashboard subprocess + orchestrator
├── pyproject.toml           # deps: ollama, paramiko, fastapi, uvicorn, jinja2, pytest, requests
├── src/
│   ├── agents.py            # Red/Blue Agent classes + system prompts
│   ├── orchestrator.py      # Turn loop, victory conditions, report generation
│   ├── executor.py          # SSH bridge (paramiko) + Blue investigation parsers
│   ├── mock_executor.py     # Fake target for testing without real box
│   └── dashboard.py         # FastAPI: /update (push), /state (poll), /ws (live UI)
├── templates/dashboard.html # War Room UI (Tailwind + WebSocket)
├── scripts/                 # Thin shells: start, status, report, watch, run
├── tests/                   # 6 tests (4 orchestrator + 2 executor)
└── .hermes.md               # Hermes cockpit docs
```

## What Was Verified

### 1. Dependencies
- `uv sync` failed to install deps (no build-system in pyproject.toml)
- Workaround: pip installed into `.venv` via `python -m pip install ollama paramiko fastapi uvicorn jinja2 pytest requests`
- All imports confirmed working

### 2. Tests
All 6 pass:
```
tests/test_executor.py::test_execute_simple_command       PASSED
tests/test_executor.py::test_execute_forbidden_command    PASSED
tests/test_orchestrator.py::test_turn_rotation            PASSED
tests/test_orchestrator.py::test_red_victory              PASSED
tests/test_orchestrator.py::test_blue_victory_stall       PASSED
tests/test_orchestrator.py::test_max_tools_per_turn       PASSED
```

### 3. End-to-end mock run
- Ran `TARGET_HOST=mock MODEL=llama3.2:latest` via `uv run python main.py`
- Ollama calls succeed (HTTP 200), dashboard streams events, mock executor returns data
- Both agents make tool calls, turns advance, no crashes

## Model Timeout Findings

| Model | Timeout | Result |
|-------|---------|--------|
| `qwen2.5:7b-instruct-q4_0` | 120s | Both agents timeout; sim stuck at turn 3 |
| `llama3.2:latest` | 120s | Blue timeouts on turn 1; red works but slow |
| `llama3.2:latest` | 600s | Both agents respond; sim progresses to turn 9+ |
| `llama3.2:1b` | 120s | Model too weak — malformed tool calls (`type`/`function`/`parameters` instead of `function.name`/`function.arguments`) |

**Conclusion:** 7B models are too slow for 120s on this hardware. 3.2B works at 600s. 1B is too weak to follow the tool schema.

## Changes Made This Session

### Model default → `qwen2.5:7b-instruct-q4_0` (then reverted to `llama3.2:latest`)
- `main.py:22` — `model = os.getenv("MODEL", "...")`
- `src/ops.py:45` — `DEFAULT_MODEL = os.getenv("MODEL", "...")`
- `src/agents.py:121` — `Agent.__init__(..., model: str = "...")`

### Timeout bump (still in effect)
- `src/agents.py:128` — `Client(timeout=120.0)` → `Client(timeout=600.0)`
- Reason: llama3.2:latest needs more than 120s per turn on this hardware

## Known Issues / Observations

1. **Model repeats commands** — llama3.2:latest calls `whoami` ×3 in one turn, then `id` ×3, then `uname -a` ×3. Same for blue with `investigate_processes`. The system prompts say "don't repeat" but the model ignores this. This is a model quality issue, not a project bug.

2. **Blue has no active response** — The spec mentions iptables/systemctl/chmod for blue mitigation, but the implementation only has investigation tools. Blue can detect but not stop anything.

3. **`summarize_experience` works correctly** — orchestrator filters history by role before passing to each agent (red gets only red turns, blue gets only blue turns). This matches the debugging reference.

4. **No prior runs in this workspace** — No `battle_report.md`, `knowledge.json`, or `simulation.log` existed at session start. The mock run was killed at turn 9 before generating a report.

## Quick Commands Reference

```bash
# Set env vars (host IP etc.)
TARGET_HOST=10.0.0.5 TARGET_USER=root TARGET_PWD=toor
MODEL=llama3.2:latest

# Mock run (no real target)
uv run python -m src.ops start --host mock
uv run python -m src.ops run --host mock --max-minutes 30

# Real target
TARGET_HOST=10.0.0.5 TARGET_USER=root TARGET_PWD=toor \
  uv run python -m src.ops run --host 10.0.0.5 --max-minutes 60

# Check status
uv run python -m src.ops status

# Read report after a run
uv run python -m src.ops report

# Kill stuck sim
pkill -9 -f "python.*main.py"
lsof -ti :8000 | xargs kill -9
```

## Files of Note
- `docs/superpowers/specs/2026-09-16-purpleloop-design.md` — original design spec (some drift from implementation: red tools like nmap/msf not implemented, blue mitigation not implemented)
- `src/references/agent-sim-debugging.md` — diagnostic recipe for stalled/out-of-control sims
