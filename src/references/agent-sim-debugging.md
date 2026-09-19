---
name: agent-sim-debugging
description: >
  Diagnostic recipe for multi-agent LLM simulations (red/blue agents, local or
  remote LLM, executor backend, turn-based loop) that stall, time out, or
  produce wrong results.
---

# Agent-Sim Debugging

## When to use

Use when a turn-based agent simulation — two or more LLM agents, a local or
remote LLM backend, an executor (real SSH or mock) carrying out tool calls,
and an orchestrator running the loop — exhibits any of:

- `LLM Error: timed out` or equivalent in the report/log
- `No winner` despite many turns
- One agent repeatedly calling the same tool while the other is idle
- "Agents are exhausting resources" / the machine slowing down mid-run
- Results that look plausible but are clearly wrong (e.g. red learning blue's
  lessons)

This is a supplement to `systematic-debugging`: it gives the *order of
diagnosis* and the *system-specific signals* for this class of system, not the
general methodology.

## Diagnostic sequence (do in this order)

### 1. Stale processes first — they eat the resources everything else needs

Before reading a single log line, check whether old sim processes are still
alive and consuming CPU/Ollama slots:

```bash
pgrep -af "python.*main.py"
lsof -i :<dashboard_port>
```

If anything shows up from a previous run, kill it before starting a new one:

```bash
pkill -9 -f "python.*main.py"
lsof -ti :<dashboard_port> | xargs kill -9
```

**Why:** a stale `main.py` holds an Ollama client, an SSH connection (real
target), and the dashboard port. A new run launched alongside it competes for
the same resources and the model times out not because it's too weak but
because the backend is saturated. This is the most common "agents are
exhausting resources" cause and the easiest to miss because the old process
looks like part of the current run.

### 2. Tool output size vs model capacity — before blaming the model

A tool that dumps the full system state can produce more context than a small
model can process. The classic case: `ps aux` on a real system returning 133+
processes as a JSON array, each with 12+ fields. A 3.2B model given that
payload does not "fail to investigate" — it cannot practically read the input,
and its response degenerates into a generic summary of the JSON structure.

**Check:** grep the report for the tool output and eyeball the payload size.
If `investigate_processes` lists every process on the box, that's the likely
culprit, not the model's reasoning.

**Fix (at the executor, not the prompt):** summarize, don't dump.

- Keep all suspicious/critical processes + top-N by CPU (e.g. 10).
- Trim each process entry to the fields the model actually uses: pid, user,
  cpu, mem, command, suspicious, reasons. Drop vsz, rss, tty, elapsed.
- Same shape for network listings: listeners + connections, trimmed fields.

**Pitfall:** do not conclude "the model is too weak" before checking whether
the tool output is a fair test. A 133-process JSON dump is not a fair test of
a 3.2B model — it's a test of the model's ability to ignore 95% of its input.

### 3. Model timeouts vs infrastructure timeouts — separate them

Two different "timeout" words mean different things:

- **`LLM Error: timed out`** — the LLM client call to Ollama (or other backend)
  exceeded the client timeout. The model did not produce a response in time.
  Causes: (a) Ollama is overloaded from other sims/other work, (b) the prompt
  + tool-output payload is too large for the model to attend to and generate
  within the timeout, (c) the model is genuinely slow on this hardware.
- **`Timeout opening channel` / `Network is unreachable` / `Connection
  refused`** — infrastructure. SSH channel, network path, or dashboard port.
  Not the model.

**Separate them before reasoning about the model.** If the log shows SSH
errors, diagnose the target connectivity first. Don't rank model hypotheses
until the executor is reliably carrying out commands.

### 4. Target connectivity is a separate fault domain from agent behavior

When running against a real target (SSH executor), connection faults can look
like agent failures:

- Paramiko `Timeout opening channel` — the SSH session is alive but a new
  channel can't be opened. Often the target is overloaded or the connection is
  degraded. Retrying the same command is low-yield; a reconnect is more likely
  to help.
- `Network is unreachable` on reconnect — the target or path is down. Stop the
  sim; don't let it keep calling tools against a host it can't reach.

**Rule:** when the executor reports a connectivity fault, treat it as an
infrastructure fault, not an agent fault, until the connection is proven stable
over multiple successful commands.

## Pitfalls

- **Don't retry the same failing command against a real target.** If a channel
  times out, repeating the command is unlikely to succeed and burns turns. The
  executor's reconnect is the more likely fix; the agent's prompt should say so
  explicitly (permission denied → try sudo; channel timeout → stop and let the
  orchestrator reconnect, don't redouble).

- **Don't give `summarize_experience` the full battle history.** Each agent
  should reflect only on its own role's turns. Feeding red the full history
  (including blue's investigation turns) causes red to produce blue-flavored
  lessons ("always investigate threats in real time") and blue to produce
  red-flavored ones. Filter by `entry['role'] == agent.role` before passing
  history to each agent's summarizer.

- **Don't double-encode at the tool-call boundary.** If an executor method
  returns `json.dumps(dict)` (a JSON string) and the agent layer wraps that in
  another `json.dumps`, the LLM receives a JSON string inside a JSON string —
  `\"{\\\"tool\\\": ...` in the report. The LLM has to parse it twice, and the
  signal is degraded. Executor methods on the tool-call path should return plain
  dicts; the agent layer does the single `json.dumps`.

- **Don't read "No winner" as "nothing happened."** `No winner` usually means
  red couldn't capture the flag (connectivity, permissions, or it never found
  the right command) *and* blue couldn't trigger a containment win (red kept
  calling tools, even if failing). Check the tool-call counts per side and the
  actual outputs before concluding the agents were inert.

- **Don't run against the real target to test agent behavior until mock is
  stable.** The real target adds connectivity, permissions, and latency
  variables that mask whether the agents themselves are doing the right thing.
  Prove the agent logic against mock first; only move to the real target when
  mock produces a clean winner and the report shows the expected tool-call
  pattern.

## Verification after a fix

1. Kill all stale sim processes.
2. Run against mock: `uv run scripts/run --host mock --max-minutes N --interval M`.
3. Confirm in the report: a clear winner, the expected tool-call pattern per
   side (blue calls its 4 tools in order, not one over and over), and
   `summarize_experience` produces role-appropriate lessons (red learns
   exploitation lessons, blue learns investigation lessons — not each other's).
4. Only then run against the real target.

## What not to do

- Don't increase the model timeout and call it fixed. A longer timeout masks
  the symptom (oversized tool output or overloaded backend) and makes each
  turn slower; it doesn't make the model more capable.
- Don't add a "bigger model" step before trimming tool outputs. The same
  oversized payload that overwhelms a 3.2B model will still be unnecessary
  weight for a larger one; trim first, then evaluate whether a bigger model
  changes the result.
