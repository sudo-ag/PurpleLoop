# Windows WinRM Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the executor a WinRM transport so the agents can reach the Windows box (`.17`) the way Windows actually exposes itself, selectable per target, with the Linux SSH path unchanged — then run one episode and capture the failure map.

**Architecture:** `execute_remote()` is the single choke-point every sensor and red command routes through. Add a `transport` attribute to `ToolExecutor`; `execute_remote` dispatches to a new `_run_winrm()` (via `pywinrm`) when `transport == "winrm"`, else the existing SSH path untouched. Transport/OS ride in on a lightly-wired `TargetProfile` (B-lite). No bash→PowerShell translation and no sensor porting — the point is to watch Linux sensors fail on Windows and record exactly how.

**Tech Stack:** Python 3.13, `pywinrm` (new), existing SSH/expect executor, pytest, uv.

**Spec:** `docs/superpowers/specs/2026-11-24-windows-winrm-transport-design.md`

## Global Constraints

- New dependency `pywinrm` added via `uv add pywinrm` (modifies `pyproject.toml` + `uv.lock`) — user already approved.
- Credentials never committed. `.17` creds (`vagrant`/`vagrant`) come from the same arg/env path as the Linux `--pwd`, never a repo file.
- Linux SSH path stays byte-for-byte unchanged; full suite stays green (593 at plan time).
- Agent prompts/doctrine unchanged. If a prompt edit were needed to function, the abstraction is wrong.
- Do NOT install SSH on `.17`. WinRM over HTTP 5985, local `vagrant` account.
- `.17` = `192.168.64.17`; Linux boxes `.11`/`.12` unchanged.

## Review Focus

- **Wrong auth transport** (Negotiate vs NTLM vs basic over 5985): Task 1 is a live go/no-go — if `vagrant/vagrant` won't auth, stop before building. Pinned there.
- **Non-zero exit / stderr from a Windows command** must still return a string, not raise: Task 2 tests a failing-command path returns an error string.
- **SSH regression**: `transport="ssh"` (default) must route to the SSH path unchanged — Task 2 tests dispatch both directions; Task 3 keeps default `ssh`.
- **WinRM command timeout** (a hung command shouldn't wedge the run): Task 2 test asserts a timeout surfaces as an error string, mirroring `execute_local`.
- **`pywinrm` import at module load** (hard dep now): Task 1 adds it before any import; Task 2 import is top-level so a missing dep fails fast, not mid-episode.

---

### Task 1: Dependency + live WinRM auth gate (go/no-go)

Prove `vagrant/vagrant` authenticates to `.17` over WinRM **before** building anything on top. This is the design's mandated first step.

**Files:**
- Modify: `pyproject.toml` (add `pywinrm`), `uv.lock`
- Create (throwaway, not committed): `/tmp` probe script

**Interfaces:**
- Produces: confirmation that `pywinrm` + `vagrant/vagrant` over `http://192.168.64.17:5985` runs `whoami` and returns the box's username. No code artifact carried forward — this is a gate.

- [ ] **Step 1: Add the dependency** — `uv add pywinrm`
- [ ] **Step 2: Live probe** — a throwaway `-I` python script (outside the project tree) using `winrm.Session("192.168.64.17", auth=("vagrant","vagrant"), transport="ntlm")`, run `whoami` and `hostname`.
  - Run: `uv run python -I /tmp/winrm_probe/probe.py`
  - Expected: stdout contains the Windows username (e.g. `vagrant` or `win-.../vagrant`), return code 0.
  - If auth fails: try `transport="negotiate"`, then `transport="basic"` (with `server_cert_validation="ignore"`). Record which one works — it is the value Task 2 uses.
  - **If none authenticate: STOP.** Report to the user; the approach needs rethinking (creds, WinRM config, or firewall).
- [ ] **Step 3: Record the working transport** in the plan/commit message, delete the probe script.
- [ ] **Step 4: Commit** (dependency only)

```bash
git add pyproject.toml uv.lock
git commit -m "build: add pywinrm for the Windows WinRM transport"
```

---

### Task 2: `_run_winrm` + transport dispatch in the executor

**Files:**
- Modify: `src/executor.py` (`ToolExecutor.__init__` add `transport`; `execute_remote` dispatch; new `_run_winrm`)
- Test: `tests/test_executor.py`

**Interfaces:**
- Consumes: working auth transport string from Task 1.
- Produces: `ToolExecutor(..., transport: str = "ssh")`; `_run_winrm(self, command: str) -> str` returning stdout, or an error string (never raises); `execute_remote` routes to `_run_winrm` when `self.transport == "winrm"`, else unchanged SSH path.

- [ ] **Step 1: Write the failing tests** (mock `winrm.Session`, no live box)

```python
def test_execute_remote_routes_to_winrm_when_transport_winrm(monkeypatch):
    # transport="winrm" => _run_winrm called, SSH path (_run_session) not touched
def test_run_winrm_returns_stdout(monkeypatch):
    # mocked Session.run_cmd -> std_out=b"nt authority\\system\r\n", status_code=0
    # _run_winrm("whoami") == "nt authority\\system"
def test_run_winrm_nonzero_returns_error_string(monkeypatch):
    # status_code=1, std_err=b"'ps' is not recognized..." -> returns an error string, no raise
def test_run_winrm_timeout_returns_error_string(monkeypatch):
    # Session.run_cmd raises the winrm/requests timeout -> returns error string like execute_local
def test_execute_remote_ssh_path_unchanged_when_transport_ssh(monkeypatch):
    # default transport="ssh" still calls the existing _run_session/_run_jump_session path
```

- [ ] **Step 2: Run tests, verify they fail** — `uv run python -m pytest tests/test_executor.py -k winrm -v` → FAIL (no `_run_winrm`).
- [ ] **Step 3: Implement.** Add `self.transport = transport` in `__init__`. In `execute_remote`, after `_check_forbidden`, if `self.transport == "winrm"` return `self._run_winrm(command)` (before the foothold/jump/SSH logic). Implement `_run_winrm` with a module-top `import winrm`: build/cache a `winrm.Session(self.host, auth=(self.user, self.pwd), transport=<task1>)`, `run_cmd` (or `run_ps`), decode `std_out`/`std_err`, strip, return stdout on status 0 else an error string; wrap timeouts/exceptions into an error string (mirror `execute_local`). `connect()`/`_master_alive` stay SSH-only (winrm never calls them).
- [ ] **Step 4: Run tests, verify pass** — `uv run python -m pytest tests/test_executor.py -v`
- [ ] **Step 5: Commit**

```bash
git add src/executor.py tests/test_executor.py
git commit -m "feat(executor): WinRM transport dispatched from execute_remote"
```

---

### Task 3: Wire `TargetProfile` os/transport through the arena (B-lite)

**Files:**
- Modify: `src/target.py` (add `os`, `transport`), `src/arena.py` (`build_agents`/`run_episodes` construct a profile and pass `transport` to the target `ToolExecutor`), `tests/test_arena.py`

**Interfaces:**
- Consumes: `ToolExecutor(..., transport=...)` from Task 2.
- Produces: `TargetProfile(host, ..., os: str = "linux", transport: str = "ssh")`; `build_agents`/`run_episodes` gain `transport: str = "ssh"` (and/or accept a `TargetProfile`); the blue/target executor is built with that transport. Red-through-jump stays SSH (a WinRM target has no jump in this brick).

- [ ] **Step 1: Write the failing test**

```python
def test_build_agents_windows_transport_builds_winrm_executor():
    # build_agents(..., transport="winrm") -> blue.executor.transport == "winrm"
    # and default (no arg) -> "ssh" (existing Linux runs unchanged)
```

- [ ] **Step 2: Run test, verify it fails** — `uv run python -m pytest tests/test_arena.py -k winrm -v`
- [ ] **Step 3: Implement.** Add `os`/`transport` to `TargetProfile`. Thread a `transport` param (default `"ssh"`) through `run_episodes` → `build_agents`, passed to the target `ToolExecutor`. Add `--transport {ssh,winrm}` CLI arg (default `ssh`). Keep positional `_ARGS` test calls working (keyword-only/defaulted, as with the model split).
- [ ] **Step 4: Run full suite, verify green** — `uv run python -m pytest -q` → all pass (594+).
- [ ] **Step 5: Commit**

```bash
git add src/target.py src/arena.py tests/test_arena.py
git commit -m "feat(arena): select target transport via TargetProfile (ssh|winrm)"
```

---

### Task 4: Observed episode on `.17` + failure map

Live, not CI. The payoff: agents provably reach Windows; record what breaks.

**Files:**
- Create: `episode_reports/` entry (auto) + `docs/windows-failure-map-2026-11-24.md` (the write-up)

**Interfaces:**
- Consumes: Tasks 2+3 (winrm transport selectable from the CLI).

- [ ] **Step 1: Live smoke through the executor** — a short `uv run python -I` snippet building `ToolExecutor(host="192.168.64.17", user="vagrant", pwd="vagrant", transport="winrm")` and calling `.execute("whoami")`. Expected: returns the Windows user. Confirms the full path (not just Task 1's raw probe) works.
- [ ] **Step 2: Run one observed episode** against `.17`:
  ```
  TARGET_HOST=192.168.64.17 uv run python -m src.arena --episodes 1 \
    --host 192.168.64.17 --transport winrm --objective root --observe \
    --user vagrant --pwd vagrant --model glm-5.3-flash:cloud --max-turns 24
  ```
  (No `--jump-host`: WinRM target is direct. Red handed the `vagrant` cred — not `--earned` — so it acts and we watch bash fail.)
  Expected: the run completes without crashing; blue's `investigate_*` calls return errors/empty.
- [ ] **Step 3: Write the failure map** — `docs/windows-failure-map-2026-11-24.md`: per `investigate_*` sensor, what it returned on Windows (errored / empty / partially usable), and what red attempted. This is the spec input for the next project (agent self-checker).
- [ ] **Step 4: Commit**

```bash
git add docs/windows-failure-map-2026-11-24.md
git commit -m "docs: Windows failure map from first winrm episode on .17"
```

## Self-Review notes

- **Spec coverage:** goals 1–4 map to Tasks 1/2 (reach+run command), 3 (per-target selection), 4 (observed episode + failure map). Anti-goal "don't install SSH" honored (WinRM only). Non-goals (sensor porting, earned cred, HTTPS, multi-box) untouched.
- **Review Focus:** auth transport → Task 1 gate; nonzero/stderr, timeout, SSH-path dispatch → Task 2 tests; import-fast → Task 2 top-level import.
- **Proportion:** plan carries interfaces + test names, not bodies; implementer writes idiomatic pywinrm. Tasks 1 & 4 are live gates/validation (no CI test possible for a live Windows box) and say so.
