# PurpleLoop

A purple-team simulator where two LLM agents fight over a real, vulnerable machine
and **learn across episodes**. A **red** operator tries to earn its way onto the
target and reach an objective; a **blue** defender, resident on that target, tries
to detect the intrusion while it's happening and respond. The point isn't to script
their moves — it's to **script the game** (goals, scoring, guardrails) and let
behavior emerge as an arms race, with lessons compounding run over run.

> Status: active research/lab project. See [`TODO.md`](TODO.md) for the roadmap and
> current direction (the autonomous learning arena).

---

## The idea

Most agent demos put attacker and defender on the same box and hand them the answer.
PurpleLoop instead models a realistic engagement:

- **Red** lives on its **own attacker box** and has to *earn* access (brute force,
  or a quieter service exploit) — it is not handed credentials.
- **Blue** is **resident on the target it defends**, watching host and network
  signals, and can take a reversible **response action** (firewall the attacker).
- The **controller** orchestrates both over SSH but is not a player.

Because the two sides operate from different machines, blue can tell attacker
traffic from its own management traffic — which is what makes detection and
containment meaningful instead of trivial.

## Architecture — two boxes, three links

```
                ┌─────────────────────────────┐
                │        controller           │  (this repo; orchestrates, not a player)
                └──────┬───────────────┬───────┘
         red control  │               │  blue control
         plane (SSH)  │               │  plane (SSH)
                      ▼               ▼
            ┌───────────────┐   ┌────────────────────┐
            │  ATTACKER     │   │  TARGET             │
            │  Kali .11     │──▶│  Metasploitable3 .12│
            │  (red's home) │   │  (blue resident)    │
            └───────────────┘   └────────────────────┘
                   the attack (.11 → .12)
```

Three links:
1. **controller → attacker** (`.11`) SSH — red's control plane (runs nmap/hydra/etc.)
2. **controller → target** (`.12`) SSH — blue's control plane (investigations + response)
3. **attacker → target** (`.11 → .12`) — the actual attack

Red reaches the target **through** the jump host (`ssh -J kali@.11 vagrant@.12`), so
the target sees the attack arriving from `.11` — distinct from blue's own control
session. A persistent multiplexed master doesn't survive the ProxyJump here, so red's
target commands run as per-call authenticated sessions; blue uses a normal
ControlMaster. (All in `src/executor.py`.)

## What each side can do

**Red** (`run_on_attacker` on Kali + `execute_command` on the target):
- Recon and credential attacks from Kali (nmap, hydra, sqlmap, nikto, nc).
- *Earned foothold* (`RED_EARNED`): no target creds — must brute-force or exploit a
  service (e.g. a web-app SQL injection) to recover credentials, then log in.
- *Evasion* (`RED_EVASION`): after acting, scrub its own traces from the target logs
  (MITRE T1070) to defeat log-based detection.

**Blue** (investigation + response tools, resident on the target):
- `investigate_logs` (the reliable flag/brute-force detector, run as a heartbeat),
  `investigate_connections` (network recon / port-scan detection via an armed
  iptables LOG rule), `investigate_processes`, `investigate_file_access`,
  `investigate_users`, `investigate_cron`, `investigate_network`.
- `contain_attacker(ip)` — a reversible iptables DROP that firewalls the attacker's
  source IP. Blue is steered to contain only on **evidence of malice** (a scan, a
  brute-force spike, or a confirmed breach), never on a bare connection.

## Scoring

Graded, machine-checkable from ground truth (`src/orchestrator.py`):
- **Red** reaches the objective (currently `flag.txt`, a placeholder for "real
  crown jewels").
- **Blue** wins by **containing** the attacker before it reaches the objective
  (prevention), or by **detecting** the breach within a dwell window
  (`detect_within_turns`). Blue cannot win on a false alarm, and its own control
  session is filtered out so it never flags itself.

## The learning arena

`src/arena.py` runs many self-contained episodes back to back:
- fresh episode each time; **scripted reset** between episodes (flush firewall,
  clear logs) so the box starts clean;
- a **per-episode scorecard** (`episodes.jsonl`) + full **battle report**
  (`episode_reports/ep_NNN.md`) so every run is auditable;
- lessons from each episode are summarized and carried forward via
  `knowledge.json`, so strategy compounds across runs.

---

## Requirements

- **Python** managed with [`uv`](https://docs.astral.sh/uv/); `expect` available
  (the SSH transport shells out to it).
- **Ollama** reachable locally. A local model (`llama3.2:latest`) works for smoke
  tests; a stronger model (e.g. an Ollama cloud model) drives the agents far better.
- Two VMs on the same host network:
  - **Target** — Metasploitable3 (Ubuntu 14.04 box) at `192.168.64.12`
    (default creds `vagrant`/`vagrant`). See `setup_metasploitable3_arm.sh`.
  - **Attacker** — Kali at `192.168.64.11` (default creds `kali`/`kali`), with
    `nmap`, `hydra`, `nc` (and `sqlmap`/`nikto` for the quiet path) installed.

> Targets are sandboxed, owned lab machines. This is for authorized security
> research and education.

## Configuration (env vars)

| Variable | Default | Meaning |
|---|---|---|
| `TARGET_HOST` / `TARGET_USER` / `TARGET_PWD` | `192.168.64.12` / `vagrant` / `vagrant` | the box blue defends & red attacks (`mock` runs the mock executor) |
| `RED_JUMP_HOST` / `RED_JUMP_USER` / `RED_JUMP_PWD` | `192.168.64.11` / `kali` / `kali` | red's attacker box (the jump host); unset for a single-box run |
| `RED_EARNED` | `0` | red must brute-force/exploit creds from its attacker box first |
| `RED_EVASION` | `0` | red scrubs its own traces from the target logs after acting |
| `MODEL` | `llama3.2:latest` | Ollama model id for both agents |

## Running

Single episode:
```bash
uv run python main.py
# e.g. with the earned contest and a stronger model:
TARGET_HOST=192.168.64.12 RED_JUMP_HOST=192.168.64.11 RED_EARNED=1 \
MODEL=gpt-oss:120b-cloud uv run python main.py
```

A learning batch (many episodes, scored, with reset + lessons):
```bash
uv run python -m src.arena --episodes 5 \
  --host 192.168.64.12 --jump-host 192.168.64.11 --earned \
  --model gpt-oss:120b-cloud --max-turns 20
# add --evade for red log-tampering, --no-reset to skip the between-episode cleanup
```

No boxes handy? Exercise the loop against the deterministic mock (local model only):
```bash
uv run python -m src.arena --episodes 2 --host mock
```

Ops helpers (start / watch / report), optional FastAPI dashboard with `--dashboard`:
```bash
uv run python -m src.ops run --host mock
```

Tests:
```bash
uv run python -m pytest -q
```

Each run writes `battle_report.md` (latest episode); the arena also writes
`episodes.jsonl` and `episode_reports/`. These, plus `knowledge.json` and
`simulation.log`, are git-ignored run artifacts.

## Layout

```
main.py              one-episode entrypoint (reads the env vars above)
src/executor.py      ToolExecutor: SSH transport (direct + ProxyJump) and all of
                     blue's investigation + response tools
src/agents.py        red / blue LLM agents, their toolsets and system prompts
src/orchestrator.py  turn loop, graded scoring, per-turn agent steering
src/arena.py         multi-episode learning loop: scorecards, reset, reports
src/ops.py           start / status / report / watch runner (+ optional dashboard)
src/dashboard.py     optional FastAPI "war room" UI
src/mock_executor.py deterministic executor for offline smoke tests
tests/               pytest suite
TODO.md              roadmap, design decisions, and current direction
```

## Roadmap

See [`TODO.md`](TODO.md). In short: the two-box plumbing, honest scoring/detection,
blue response, earned foothold, red evasion, and the episode arena are in place; the
current frontier is **learning-signal quality** — making red a better learner so it
can discover a quiet path and win, rather than reflexively scanning into blue's
detection.
