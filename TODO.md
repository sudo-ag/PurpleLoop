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
      (Leaning listener after Step 1c.)

---

## Current direction — autonomous learning arena

Pivot (now that a capable model, e.g. `gemma4:31b-cloud`, can drive it): stop
scripting the agents' *steps*; script the *game* (goal + scoring + guardrails) and
let behavior emerge across many self-run episodes. The flag was scaffolding to
validate the pipeline on a weak model; it stays as a regression toggle.

**The game.** Two-box model. Red *earns* its way onto the vulnerable box by
exploiting a real weakness and escalates; blue detects the intrusion while it is
happening and responds. Open objectives + open tools; minimal tactic steering.

**Tiered rubric (machine-checkable from ground truth):**
- RED: T1 initial access (earned shell via a real vuln) → T2 priv-esc to root →
  T3 impact (persistence or exfil). Score = tiers reached.
- BLUE: D1 detect (true-positive, in-window, no idle false-positive) → D2
  attribute (source IP / account / technique) → D3 respond (contain before
  T2/T3). Minus penalties for false alarms / misses.
- Graded/comparative outcome (did blue detect before red escalated?).

**Decisions made:**
- First vuln surface = **weak SSH creds** (hydra vs the SW roster) for T1; widen
  to service exploits later.
- Episode reset = **scripted cleanup** between episodes (restore logs, remove
  red persistence/keys/cron, flush firewall, kill stray sessions); VM
  snapshot/restore is the later, stronger answer.
- Learning = **episodic / in-context** first (scorecard + lessons compound via
  `knowledge.json`), not weight-level RL (that's a much later, optional step).

**Build order (loop machinery first on the current game, then raise the goal):**
1. **Episode arena + scorecard** — run N episodes in-process, score each side
   against the rubric from ground truth, persist a per-episode scorecard, print
   cross-episode trends. (Prove on the current handed-flag game.)
2. **Scripted reset hook** between episodes.
3. **Earned-SSH objective + two-channel red** — remove handed `vagrant`; red runs
   hydra on Kali, then pivots with the cracked cred. Swap the flag goal for the
   tiered rubric; strip red's phase list / blue's canned steering.
4. **Learning loop** — feed each scorecard + reflection into `experience`;
   run many episodes; let strategy compound.
5. **(Later)** LLM judge for fuzzy scoring; trajectory collection for RL.

**Guardrails:** sandboxed owned target; keep `FORBIDDEN_KEYWORDS`; reversible /
cleaned actions; turn caps; per-episode reset so learning measures strategy, not
box drift.

---

## Session 2026-10-11 — learning loop live; "red trains blue" validated

Build-order step 4 (learning loop) is now working end to end on the real boxes
with `gemma4:31b-cloud`. Three changes landed and are tested (102 passing) + live-verified:

- **Causal reflection** (`Agent.summarize_experience` + `Orchestrator._outcome_brief`):
  reflection is now grounded in the episode's outcome and the agent's own last
  action, so lessons are `<action> led to <consequence>, so next time <change>`
  instead of context-free. Red's lessons flipped from "enumerate harder" (wrong)
  to "scan → contained, go quieter" (correct).
- **Blue observe/training mode** (`--observe`, blue-only): blue investigates and
  *learns* but holds containment (no real iptables DROP), so red runs its full
  kill chain and blue witnesses stages a turn-1 block would never reveal. This is
  blue's curriculum — a scaffold, not a permanent nerf.
- **Auth-sensor fix** (the big one): the PLWATCH connection-logging rule was
  unscoped (`INPUT ... NEW -j LOG`), logging every packet (loopback, broadcast,
  DNS) → `kern.log`/`syslog` hit 515 MB → rsyslog wedged → `auth.log` went dead →
  blue was blind to red's brute-force/login/sudo. Scoped the rule to
  `! -i lo -p tcp --syn`; also fixed `_parse_auth_log` to report an empty read as
  `UNAVAILABLE` (sensor gap) instead of `CLEAN` (which had hidden the outage).

**Result that matters.** Before the fix, a 5-episode observe batch: blue blind
(`blue_detect_turn` null ×5), all 5 lessons identical ("block the scanner"). After
the fix: blue detected the breach 3/3 times it completed (`detect_turn` 9/11/11),
and **blue's lessons broadened to a new kill-chain stage** — "overly permissive
sudo for `vagrant` → exfiltration → restrict sudo / least privilege." The
thesis — red's gauntlet teaches blue new defenses — now holds in practice.

### New frontier / next steps (ranked)
1. **Give blue a response for the stage it now sees.** Blue learned the
   privesc/exfil lesson but can only recommend it, not act — a "harden sudo" /
   remediation action (dial 3, D1 = remediator) would let blue *apply* what it
   learned. This is where D1 (remediator vs. listener) stops being theoretical.
2. **Separate target identities (step 1b).** Real containment needs red as a
   distinct account so blue can lock the attacker without locking itself — and so
   observe-mode can eventually ramp response back up per-technique.
3. **Detection-credit scoring (the LLM-judge item).** In observe mode blue can
   "lose" the episode but succeed at the learning objective (detected the new
   technique). Score "did blue detect the technique" separately from "did blue
   win" so training signal isn't conflated with the scoreboard.
4. **Reflection polish:** red occasionally reflects in *defender* voice ("the
   defender should disable password auth") — tighten the red prompt to attacker
   self-improvement.

### Visibility MVP (parked, for the capstone)
Decided: kill the live WebSocket dashboard (it was blank because
`_notify_dashboard` only POSTs to a URL that was never up / never persisted).
Build a **static replay viewer** off persisted per-episode files instead — no
server, no sockets. Prereq not yet done: persist a machine-readable per-turn
timeline (`ep_NNN.json`); today only prose `ep_NNN.md` + coarse `episodes.jsonl`
exist.

### Gotchas carried forward
- `gpt-oss:120b-cloud` is **gone** from the account; current strong cloud model is
  `gemma4:31b-cloud`. `minimax-m2.5:cloud` / `kimi-k2.5:cloud` are stale/retired.
- The unscoped PLWATCH rule can refill `kern.log`/`syslog` to hundreds of MB and
  wedge rsyslog; if auth logging ever looks dead again, check those file sizes and
  `sudo truncate -s 0` them + `sudo service rsyslog restart`.
