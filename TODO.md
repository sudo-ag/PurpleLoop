# PurpleLoop Roadmap

Purple-team agent sim: an LLM **red** agent attacks a target box over SSH while
an LLM **blue** agent investigates and (eventually) responds. This file tracks
where we are and where we're going.

## Vision / end states

Two distinct products share a detection core but diverge on action model:

- **Active assessor / remediator** — blue logs into a machine, audits posture,
  and *applies fixes* (hardening, closing holes, revoking access).
- **Passive listener ready to pounce** — blue sits resident, watches telemetry,
  alerts, and *auto-responds* to an in-progress attack.

**Open decision (D1):** which end-state leads? It changes whether blue's first
real action is "harden/fix" (remediator) or "detect-and-contain" (listener).
The next few steps (scoring, detection, one response action) are shared by both,
so we can defer D1 — but it must be answered before blue's toolset grows.

## Current state — "crawl" (done)

- Transport: OpenSSH ControlMaster multiplexing, self-healing, verified live.
- Scoring: blue log analysis scoped to a per-run time window (no stale-log wins).
- Red: phase-steered (enum → find → privilege → flag-read); drives to the flag
  and reads it (`sudo cat /root/flag.txt`). Verified: RED win in 12 turns.
- Blue: tool-variety steering (won't repeat one tool); detection is truthful —
  `investigate_logs` fires BREACH on an in-window flag read; `investigate_file_access`
  no longer false-CLEANs without auditd.
- Objective: single `flag.txt`. Red starts with `vagrant` + NOPASSWD root.

### Known limitations to carry forward
- **Shared identity:** red and blue both authenticate as `vagrant`. Real
  containment is impossible until the attacker is a distinct principal. (blocks
  containment — see Step 1c)
- **Instant red win:** red wins the moment it reads the flag, so blue never gets
  a turn to respond. (fixed by Step 1a)
- **atime is unreliable** on the box (`relatime` mount) — don't lean on it for
  window-bound detection; auth.log is the reliable signal.

## Target note — use the box's real vulns

The current target is **Metasploitable3**, which ships with genuinely
exploitable services and misconfigurations. That means dials 1 and 2 don't have
to be simulated: red can **earn** initial access and escalation through real
vulns (weak/unauth services, SUID/cron misconfig, etc.) instead of being handed
`vagrant` + NOPASSWD. When we reach Steps 2–3, draw the attack paths from what's
actually on the box — more realistic telemetry for blue, and no synthetic setup.

## The dials (turn ONE per iteration, then measure)

1. Red's objective — `flag.txt` → real crown jewels (shadow, SSH keys, DB creds,
   persistence, exfil).
2. Initial access — stop handing red NOPASSWD root; make escalation earned.
3. Blue's powers — observe-only → **act** (contain, lock, block, revoke, fix).
4. Scoring — binary red-win → graded on detection, dwell time, containment.
5. Environment — one static box → varied machines + learned baselines.

## Roadmap (sequenced)

- [ ] **Step 1a — graded / dwell-time scoring** (dial 4; pure orchestrator, no
      box changes). Make blue winnable by *detecting in time*. **Next up.**
- [ ] **Step 1b — separate red/blue identities** (box setup). Red = attacker
      account; blue = defender/root. Prereq for real containment.
- [ ] **Step 1c — blue's first response action** (dial 3). One reversible action
      (`contain_session` / `lock_account`); blue wins by containing before red's
      objective.
- [ ] **Step 2 — earned escalation** (dial 2). Remove free root; red must find a
      real priv-esc path (SUID/cron/service).
- [ ] **Step 3 — real objectives** (dial 1). Multiple sensitive targets + exfil,
      giving blue more telemetry.
- [ ] **Step 4 — environment variety + baselines** (dial 5). Config-driven
      targets; blue learns a per-host baseline → the deployable assessor.
- [ ] **D1** — decide remediator vs. listener bias (must land before Step 1c's
      toolset grows).

---

## Step 1a — graded / dwell-time scoring  (detailed plan)

**Goal:** the sim no longer ends the instant red reads the flag, and blue can
win by detecting the breach quickly. Outcomes become graded, so a run is a
genuine two-sided contest.

**Model:**
- Run to a fixed turn **horizon** (don't short-circuit on red's flag read).
- Record the turn red first accesses the objective (`red_access_turn`).
- Record the turn blue first raises a confirmed BREACH (`blue_detect_turn`).
- **Dwell time** = `blue_detect_turn - red_access_turn`.
- Outcome:
  - **BLUE** if blue detects within `K` turns of red's access (`0 <= dwell <= K`).
  - **RED** if red accessed and blue never detected within the horizon
    (or detected too late, `dwell > K`).
  - **NONE/DRAW** if red never reached the objective.

**Plan (each step pauses for review):**

1. Add `red_access_turn` / `blue_detect_turn` / `detection_dwell` to
   `SimulationState`; stop returning early on red's flag read — record the turn
   and let the sim continue to the horizon.
   → verify: unit test — a run where red reads on turn 3 keeps going to horizon.
2. Add the graded outcome resolver (the BLUE / RED / NONE logic above, with a
   configurable `detect_within_turns: K`).
   → verify: unit tests for each branch (in-time detect → BLUE; no detect → RED;
   late detect → RED; no access → NONE).
3. Wire `generate_report` to show outcome + dwell time; keep the dashboard/report
   fields consistent.
   → verify: report test asserts the dwell line renders.
4. Live run against the box; confirm a decided, graded outcome and sane dwell.
   → verify: read `battle_report.md`.

**Non-goals for 1a:** no new blue actions, no identity split, no box changes.
Those are 1b/1c.
