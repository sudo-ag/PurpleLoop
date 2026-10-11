# PurpleLoop Roadmap

Purple-team agent sim: an LLM **red** agent attacks a target box from its own
attacker box while an LLM **blue** agent, resident on the target, investigates
and (eventually) responds. This file tracks where we are and where we're going.

## Vision / end states

Two products share a detection core but diverge on action model:

- **Active assessor / remediator** — blue logs into a machine, audits posture,
  and *applies fixes* (hardening, closing holes, revoking access).
- **Passive listener ready to pounce** — blue sits resident, watches telemetry,
  alerts, and *auto-responds* to an in-progress attack.

**Open decision (D1):** which end-state leads? It changes whether blue's first
real action is "harden/fix" (remediator) or "detect-and-contain" (listener).
The next steps (one response action) are shared by both, but D1 must land before
blue's response toolset grows.

## Architecture — two boxes, three links

Red and blue live on separate planes; the controller orchestrates both.

- **Target** — the Metasploitable3 VM at `192.168.64.12`. Blue is resident here,
  defending its home. Holds the objective (`/root/flag.txt`).
- **Attacker** — a Kali VM at `192.168.64.11`. Red's home.
- **Three links:**
  1. controller → attacker (`.11`) SSH — red's control plane.
  2. controller → target (`.12`) SSH — blue's control plane.
  3. attacker → target (`.11` → `.12`) — the actual attack.

Red reaches the target **through** the jump host (`ssh -J kali@.11 vagrant@.12`),
so the target sees the attacker arriving from `.11` — distinct from blue's own
control session (from the controller, `.1`). That distinguishability is what lets
blue tell attacker traffic from its own management traffic.

Config (env): `TARGET_HOST/USER/PWD`, `RED_JUMP_HOST/USER/PWD`. Unset the jump to
fall back to a single-box run. `TARGET_HOST=mock` runs the mock executor.

## Current state — plumbing + honest scoring (done)

- **Transport:** blue over an OpenSSH ControlMaster (direct); red over per-call
  ProxyJump sessions (a persistent master doesn't survive the jump here). Both
  verified live.
- **Plane separation:** two role-bound executors; blue filters its own `.1`
  control session and attributes the breach to the attacker at `.11`.
- **Scoring integrity:** blue wins ONLY on a confirmed, in-time flag catch
  (`access <= detect <= access + K`); a detection with no real access can't win.
- **Detector fidelity:** `investigate_logs` (auth.log) is the authoritative flag
  detector; baseline services (`tcpdump`, `sshd`) no longer false-BREACH; blue's
  own `stat/ls` on the flag isn't scored as a self-breach.
- **Blue cadence:** `investigate_logs` is a per-turn heartbeat, not a one-pass
  sweep — blue keeps watching for a read that lands on a later turn.
- **Agent robustness:** tool calls the model emits as JSON text (`parameters`
  key, missing args, list/function wrappers) are recovered instead of dropped.
- **Objective:** single `flag.txt`. Red starts handed `vagrant` (NOPASSWD root).

Live-verified arc on the real boxes: bogus BLUE win (false positive) → honest RED
win (blue stopped looking) → **honest BLUE win** (heartbeat caught the flag read
the next turn). The scoreboard now reflects reality.

### Known limitations to carry forward
- **Same target account:** red and blue both act as `vagrant` on the target;
  they differ by *source* (`.11` vs `.1`), not by principal. Real containment
  (lock the attacker without locking blue) wants distinct accounts — see 1b/1c.
- **atime is unreliable** on the box (`relatime`); don't lean on it for
  window-bound detection — `investigate_logs` is the reliable signal.
- **Residual turn-waste:** some model outputs still land as prose "thoughts" and
  execute nothing; the parser recovers the common JSON-text shapes but not all.

## The dials (turn ONE per iteration, then measure)

1. Red's objective — `flag.txt` → real crown jewels (shadow, SSH keys, DB creds,
   persistence, exfil).
2. Initial access — stop handing red NOPASSWD root; make the foothold earned
   (hydra against the box's weak SW-roster accounts) and escalation real.
3. Blue's powers — observe-only → **act** (contain, lock, block, revoke, fix).
4. Scoring — binary → graded on detection, dwell time, containment. (done for
   detection/dwell; containment pending.)
5. Environment — one static box → varied machines + learned baselines.

## Roadmap (sequenced)

- [x] **Step 1a — graded / dwell-time scoring** (dial 4). Winner from dwell
      between red's access and blue's detection (`detect_within_turns`).
- [x] **Two-box plumbing** — red attacks the target from the Kali jump; blue
      defends it directly; planes separate and distinguishable.
- [x] **Scoring + detector integrity** — no false-positive blue wins; honest
      detectors; blue polls the reliable detector as a heartbeat.
- [~] **Step 1b — separate red/blue identities** (box setup). Partially done:
      red and blue are distinct by source IP and blue filters its own session.
      Remaining for real containment: red as a *distinct target account* (not
      `vagrant`) so blue can lock the attacker without locking itself.
- [x] **Step 1c — blue's first response action** (dial 3). Done: blue can
      `contain_attacker(ip)` — a reversible iptables DROP on the attacker's source
      IP — and wins by containing the attacker (`.11`) before it reaches the
      objective. Scored as prevention (containment-before-access) ahead of
      detection; per-turn guidance issues a direct contain order once blue has
      observed the attacker IP. Live-verified prevention win; rule flushed at
      teardown. (Leans the D1 bias toward **listener** — revisit before the
      response toolset grows further.)
- [ ] **Step 2 — earned escalation** (dial 2). Flip `RED_FOOTHOLD` to earned:
      red cracks a weak SW-roster account with hydra, then escalates. (Needs a
      stronger model than llama3.2 to drive reliably.)
- [ ] **Step 3 — real objectives** (dial 1). Multiple sensitive targets + exfil.
- [ ] **Step 4 — environment variety + baselines** (dial 5). Config-driven
      targets; blue learns a per-host baseline → the deployable assessor.
- [ ] **D1** — decide remediator vs. listener bias (before 1c's toolset grows).
