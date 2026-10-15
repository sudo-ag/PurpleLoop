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

### Progress since (same session)
- **Replay viewer — DONE.** Per-episode `ep_NNN.json` is persisted (`build_replay`
  in arena; orchestrator turn-stamps history). A static replay viewer ships as a
  Claude Artifact (loads a run's JSON, plays it turn-by-turn, red/blue lanes,
  milestones, verdict). Delivered for the professor; shareable for the capstone.
- **Separate identities (step 1b) — DONE.** Earned red now starts with NO target
  cred; `require_foothold` refuses target commands until red cracks one and proves
  it via the new `use_credential` tool (`set_target_credential` logs in to
  validate, rejects `vagrant`/`root`). Blue stays `vagrant`. Live-verified: red
  discovered `lando_calrissian:@dm1n1str8r` **via SQLi (sqlmap on payroll_app.php)**
  — the intended quiet path, unseeded — and landed as that account, not vagrant.
- **Finding:** red now lands *non-privileged* (`lando_calrissian` isn't in sudo),
  so it has T1 initial access but stalls at T2 escalation — it tried `sudo -l`
  (no tty / password required), SUID hunt, crontab, and never reached root/flag.
  The kill chain is now realistically gated at privesc. Also: red's real
  achievement (dumping the payroll credential DB) **scored nothing** under the
  single root-flag objective.

### Decision — objective model: GRADED REALISTIC TIERS (dial 1 + T1/T2/T3 rubric)
The flag was scaffolding and has served its purpose. Going forward, score what red
actually achieves at each access level rather than one all-or-nothing root-file read:
- **T1** initial foothold (earned shell as a user).
- **T2** data / credential exfil — e.g. the payroll DB credential dump red already
  pulls via SQLi. This is the realistic crown-jewel theft and the capstone story.
- **T3** root compromise — the flag (`/root/flag.txt`) **stays as the top-tier
  anchor + regression toggle**.
**Hard coupling:** every objective tier needs a matching blue *sensor*, or it is
undefendable (the flag works only because blue can detect its read). A T2 DB-exfil
objective requires a blue web/DB-access sensor, added together with the objective.
This is architectural (graded scoring + per-tier sensors) — give it its own design
pass before building.

### Remaining next steps (ranked)
1. [~] **Graded tiered objectives + per-tier blue sensors** (the decision above) —
   Slice 1 DONE (see 2026-10-12 below); Slice 2 (T2 exfil sensor) is next.
2. **Blue remediation action** (dial 3, D1 = remediator) — now UNBLOCKED by step 1b:
   blue (vagrant) can lock/strip/kill red's distinct `lando_calrissian` account, or
   fix the SQLi/leaked cred, without self-harm. Lets blue *act* on what it learns.
3. **Red privesc** (dial 2) — a real escalation path (non-sudo user → root) so the
   chain can complete to T3 again.
4. **Detection-credit scoring (LLM-judge)** — score "did blue detect the technique"
   separately from "did blue win"; fits the graded rubric above.
5. **Reflection polish** — red sometimes reflects in defender voice; tighten to
   attacker self-improvement. **main.py earned path** not yet updated to the
   use_credential flow (arena is the path that matters).

### Gotchas carried forward
- `gpt-oss:120b-cloud` is **gone** from the account; current strong cloud model is
  `gemma4:31b-cloud`. `minimax-m2.5:cloud` / `kimi-k2.5:cloud` are stale/retired.
- The unscoped PLWATCH rule can refill `kern.log`/`syslog` to hundreds of MB and
  wedge rsyslog; if auth logging ever looks dead again, check those file sizes and
  `sudo truncate -s 0` them + `sudo service rsyslog restart`.

---

## Session 2026-10-12 — graded tiers, Slice 1 (foothold + root) landed

Scoring model decided last session (GRADED REALISTIC TIERS) is now partly built.
Decisions made this session: **per-tier scoreboard** (not a flag-or-bust binary),
and **slice T2 out** (the only tier needing a new sensor + the live box) so Slice 1
stays fully offline/unit-testable.

**Slice 1 — DONE (committed `03f35b9`, pushed; 121 tests pass).**
- `SimulationState` tracks `red_tiers` / `blue_tier_detect` (tier → turn).
- **T1 foothold** wired to real signals: red-reached = a validated `use_credential`
  or any successful target command (`_check_red_foothold`); blue-detected = the auth
  log's non-control "Successful authentication" event (`_check_blue_foothold_detect`).
- **T3 root** mirrors the existing flag hooks (`red_access_turn`/`blue_detect_turn`).
- New `Orchestrator.tier_scoreboard()` + `verdict()` derive a graded result
  (`reached_turn`, `detect_turn`, `dwell`, `defended` per tier; `defended` =
  detected within `detect_within_turns` or contained at/before the tier). **Loop
  termination is unchanged** — only the *reported* result became graded, so a
  lando-style "stall at T2" now reads as "red reached T1; blue defended …" instead
  of a flat binary.
- Carried through `arena.build_scorecard`/`build_replay` (scorecard + `ep_NNN.json`
  gain `tiers`+`verdict`) and `generate_report` (tier table). Per-episode console
  line now leads with the verdict.
- Verified: 121 tests (108 + 13 new in `tests/test_tiers.py`); mock arena run prints
  `red reached T3 (root); blue defended T3` and the board shows T1 reached, T3
  reached+detected, **T2 correctly inert** (null/`—`).

**T2 is declared but INERT** — no red exfil signal, no web/DB sensor yet.

### Slice 2 (next) — T2 data/credential exfil
- **Red signal:** red completes the payroll-DB credential dump (sqlmap on
  `payroll_app.php`) — detect it in the orchestrator from the red tool history the
  way T1/T3 are detected.
- **Blue sensor (the new piece):** a web/DB-access sensor — Apache access log +
  injection/sqlmap patterns against `payroll_app.php` (and/or MySQL query log).
  Ships *with* the objective (the coupling rule). **Needs the live box to validate
  → cloud spend.**
- Wire both into the `TIER_EXFIL` slots already present in `tier_scoreboard()`.

### Not touched this session (deliberate)
- Replay **viewer** artifact still renders only the single winner, not the tier
  board — a separate visual pass (the JSON already carries `tiers`/`verdict`).
- `main.py` single-episode path still doesn't surface the scoreboard (arena-only,
  as with the earned flow).

---

## Session 2026-10-15 — loop-curbing + scoring fix; new idea: battle-style replayer

### Done this session (128 tests pass; not committed yet)
- **Anti-loop nudge** (`Orchestrator._repeat_nudge`): when an agent spends a whole
  turn re-issuing tool calls it already tried (no new action), guidance now names
  them and tells it to try something different. Blue's `investigate_logs` heartbeat
  is excluded (it is meant to repeat). Advisory — `gemma4:31b` obeys inconsistently.
- **Blue breadth rotation fix** (`_blue_tool_guidance`): the breadth picker used
  `next(t not in used_set)`, which collapsed to a permanent `investigate_file_access`
  default once every tool had been used once → the `logs→file_access` 2-cycle. Now
  picks the **least-recently-used** breadth tool, so blue keeps rotating. Live-verified:
  blue covered 5 breadth tools in one episode vs 2 before.
- **False-T3 scoring fix** (`executor._sudo_denied`): a REFUSED `sudo cat /root/flag.txt`
  still logs the attempted `COMMAND=`, so the auth-log parser scored a denied attempt
  as a real flag read (`user NOT in sudoers … COMMAND=/bin/cat /root/flag.txt` →
  `flag_access_detected=True`), back-filling a bogus T3 for BOTH sides. Both
  `flag_access` sites now require the sudo line to carry no refusal marker.
  Regression test uses the exact captured false-positive line.

### Backlog — battle-style (Pokémon-like) episode replayer
**Why:** the current replay viewer reads as a dead "red did X, blue did Y" log.
For the capstone/professor demo it should read to a **non-technical** audience at a
glance — frame the episode as a turn-based battle between RED and BLUE.

**Vision:**
- Two combatants on screen (RED attacker vs BLUE defender), facing off like a
  Pokémon battle. Each turn one side "uses a move"; the move is a **plain-language
  summary** of what that agent actually did that turn (e.g. red `sqlmap … payroll_app.php`
  → "RED used **SQL Injection!**"; blue `investigate_logs` → "BLUE used **Log Scan!**";
  blue `contain_attacker` → "BLUE used **Containment!** It's super effective!").
- **Progress bars as the stakes:** red's climb up the tiers (T1 foothold → T2 exfil
  → T3 root) and blue's detection/containment shown as HP/meter-style bars that fill
  or drain per turn, so "how close did red get / did blue stop it" is obvious visually.
- Milestones (foothold earned, breach detected, contained) land as big battle beats
  ("RED reached T1!", "BLUE detected the intrusion!", a KO-style end on the verdict).
- Keep it faithful: the flavor is cosmetic; every move/beat is derived from the real
  `ep_NNN.json` timeline + `tiers`/`verdict` (no invented drama).

**Data:** no new plumbing — `ep_NNN.json` already carries the turn-stamped timeline,
tier board, milestones, and verdict. Needs a **turn → one-line move** summarizer.

**Open design decisions (resolve at build time):**
- Move-summary source: **rule-based mapping** (tool name/args → canned move label +
  blurb; cheap, deterministic, offline, reproducible — preferred) vs. an LLM
  summarizer pass per turn (nicer prose, costs tokens, non-deterministic).
- Delivery: ship as a Claude Artifact like the current viewer (self-contained HTML,
  shareable link) vs. extend the existing viewer.
- Art/assets: simple CSS/SVG sprites + type-effectiveness flavor, or static art.
- Supersedes the earlier "replay viewer renders only the single winner, not the
  tier board" gap — the battle view *is* the tier-board visualization.
