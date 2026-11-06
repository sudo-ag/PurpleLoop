# PurpleLoop — Linux Breadth via Technique Families (Design)

Date: 2026-11-05
Status: design, pending approval
Supersedes nothing; extends `2026-10-23-purpleloop-vision-assessment-platform.md`
(north star) and consumes the planned Dirty COW arc from `HANDOFF.md`.

---

## Intent / why

PurpleLoop today has red exercising **2 of ~10+** vectors on the Linux
Metasploitable3 box it already runs against (`.12`): SQLi foothold and the
docker-group breakout. Each vector so far has been a hand-crafted arc (red
doctrine + coupled blue sensor + scoring hooks + gated live run) costing roughly
a session. The box has on the order of 10–12 distinct vectors; the Windows
Metasploitable3 box (a separate VM, the one the public "Vulnerabilities" wiki
documents) has ~21 more. One-arc-per-CVE does not scale to that, and the
capstone goal has grown: the professor wants this taken to a grander scale —
agents deployable onto real environments, eventually Windows, eventually both
sides versatile across a mixed fleet, possibly with task-delegating sub-agents.

So the near-term milestone — **red can reach every vector on the Linux box and
blue can detect (ideally prevent) each** — is not the destination. It is the
evidence that the red/blue loop generalizes *within* a box, which is the
prerequisite for spending effort on a second OS. The work must therefore leave a
**reusable substrate**, not another pile of bespoke vectors.

**The acceleration thesis.** The box's ~10 vectors collapse into ~5 **technique
families**. A family is *one red capability + one coupled blue sensor + scoring*
that covers every vector sharing that tradecraft. Build the family, get the
column. ~5 builds, not ~30. And after building two families concretely, extract
a generic engine (red capability library + blue baseline-anomaly profiler) so
families 3–5 become mostly configuration — and so the substrate is the thing
that later re-skins onto Windows.

## Goals

- Red reaches every listening-service vector on `.12` and both already-owned
  privesc paths, via **5 technique families** rather than per-CVE arcs.
- Blue has a coupled sensor for each family (the project's standing rule: every
  vector red can reach, blue can detect — no undefendable objectives).
- After families 1–2, a **generic engine** exists: red's capability library and
  blue's baseline-anomaly profiler, from which families 3–5 fall out cheaply.
- A **coverage matrix** tracks, per vector: red-reaches / blue-detects /
  blue-prevents — the measurable definition of "box covered."
- Everything built is **re-skinnable for Windows** (the loop, the engine, the
  scoring and matrix are OS-agnostic; only the sensor/exploit leaves are
  OS-specific).

## Non-goals

- The Windows box. Explicitly deferred to after the Linux box is covered
  (decided: track 1, Linux breadth-first).
- Sub-agent / task-delegation layer. North-star idea, not this project.
- Weight-level RL / fine-tuning. Learning stays episodic/in-context.
- A 24/7 production autoresponder. Assessment mode only (per the vision doc).

## Anti-goals (would make this a failure even if it "works")

- A premature generic framework built before the pattern is seen twice — the
  reason the engine is extracted *after* families 1–2, never before.
- Seeding/hinting red (giving it the exploit, the cred, the wordlist entry).
  Red must discover and learn; facts are discovered, not baked. (Standing
  decision, human was firm.)
- Sensors that false-positive on baseline services, or scoring that credits a
  denied/failed action as success. Honest scoring is non-negotiable.
- Hand-coded leaves that cannot transfer: a family whose only artifact is a
  box-specific parser teaches us nothing for Windows.

## Constraints

- **Transport:** blue over a direct SSH ControlMaster to `.12`; red over per-call
  ProxyJump through Kali `.11`. Per-call SSH means the target filesystem persists
  between calls but shell/group state does not inherit (bit the docker arc).
- **Attacker box:** Kali `.11`, `kali`/`kali`. **apt is broken** (key rotation) —
  no installing tools. Available: nmap, hydra, nc, sqlmap, nikto. **Metasploit
  `msfconsole` + `msfvenom` confirmed present** at `/usr/bin/` (verified
  2026-11-05) — the capability library leans on real msf, no apt needed.
- **Model:** `gemma4:31b-cloud` (only working strong cloud model; gpt-oss gone).
  Cloud budget is currently ample (user lifted the constraint) — batches are fine.
- **Guardrails:** `ToolExecutor.FORBIDDEN_KEYWORDS` stays. The Dirty COW arc adds
  a narrow `dojo_exploit_ok` exception (passwd/shadow allowed on the dojo only;
  `rm -rf /`, `mkfs`, `dd if=`, `shutdown`, `reboot` stay blocked; default off).
- **Live-run discipline:** any new exploit validated live is gated on a confirmed
  `.12` VM snapshot; destructive/race exploits restore after. A snapshot was
  taken 2026-11-05.
- **Box state today (verified live 2026-11-05):** kernel 3.13.0-24, gcc 4.8.4,
  auth.log alive, `/etc/passwd` clean (only root uid=0), `boba_fett` in
  `users,docker`. Listening: 21 proftpd 1.3.5, 22 sshd, 80 apache, 139/445 smbd,
  3306 mysqld, 3500 ruby/sinatra, 8080 java(tomcat/jenkins), 111/rpcbind.

## The five families

| # | Family | Red capability | Blue sensor (coupled) | Example vectors | Tier |
|---|--------|----------------|------------------------|-----------------|------|
| 1 | Privilege escalation | kernel/local exploit; SUID; service overwrite | `investigate_privileged_accounts` (rogue uid=0, SUID tamper, service-file integrity) | Dirty COW (CVE-2016-5195), docker✅, sudo✅, writable `/opt/sinatra` | T3 |
| 2 | Network-service RCE | fingerprint a listening service → run matching remote exploit | new-process / new-listener / unexpected-child spawn anomaly | ProFTPD 1.3.5 mod_copy (CVE-2015-3306), Tomcat deploy, Sinatra | T1 (new foothold) / T3 if RCE lands privileged |
| 3 | Web-app exploitation | web tradecraft (sqlmap, app-specific) | web/DB-access sensor (Apache access log + injection patterns, MySQL query log) | payroll SQLi✅ (exfil signal still inert), Drupal, phpMyAdmin | T1/T2 |
| 4 | Credential brute | hydra/service-login brute across services | auth/service-log sensor (have for SSH) | SSH✅, MySQL blank-root, FTP, SMB | T1 |
| 5 | Post-exploitation | persistence, exfil, log-tamper (have `--evade`) | cron✅ + file-access✅ sensors + exfil scoring | cron/key persistence, data exfil | T2/T3 |

## Sequence (Mechanism C — hybrid)

1. **Family 1 — Privesc, hand-crafted.** Execute the already-specced 5-step
   Dirty COW arc verbatim (guardrail exception → `investigate_privileged_accounts`
   → red doctrine → scoring → gated live). Banks a win; prerequisites verified.
2. **Family 2 — Network-service RCE, hand-crafted.** ProFTPD mod_copy exemplar.
   Deliberately give red a *second, independent foothold path* (not SSH/SQLi) to
   kill the cracking-variance bottleneck. Blue gets the new-process/new-listener
   sensor.
3. **Extract the engine.** With two concrete families in hand, pull out:
   - **Red capability library** — recon → fingerprint listening service →
     select+run exploit. Adding a service vuln becomes data, not code.
   - **Blue baseline-anomaly profiler** — blue learns the box's normal
     (processes, listeners, users, auth rhythm) and flags deviations generically.
     Sits *alongside* the hand-coded sensors at first (see open question O2).
4. **Family 3 — Web-app.** Finish the inert T2 exfil slice (red sqlmap-dump
   signal + web/DB sensor), add Drupal/phpMyAdmin. Mostly config over the engine.
5. **Families 4–5 — Credential brute + Post-ex breadth.** Fall out of the engine
   plus existing auth/cron/file sensors and exfil scoring.

Each family is itself built test-first and offline where possible, with a single
gated live validation; a family isn't "done" until its row in the coverage matrix
shows red-reach + blue-detect live.

## Coverage mechanism (how "red reaches every vector" is proven)

The per-vector goal collides with free discovery: red takes the cheapest path
(SQLi/SSH) and skips harder vectors. Resolution (decided):

- **Default = opportunistic.** Normal batches accumulate whatever coverage red
  organically finds; emergent behavior stays the baseline.
- **Fill stubborn rows = per-vector "focus scenario" configs.** A focus run
  restricts the *reachable attack surface* (e.g. only ProFTPD exposed, SSH/SQLi
  paths closed off) so red must exploit that vector to progress. This is a
  legitimate assessment scenario ("evaluate this one service"), **not seeding** —
  red still has to discover and land the exploit itself; we constrain the
  environment, never hand red the path. New harness work: a surface-restriction
  toggle on the arena (likely iptables/service-gating in `scripted_reset`).
- **Matrix auto-derived.** A `(tool, args, output) → vector` classifier runs over
  the existing episode timeline (which already carries tool+args+output per turn)
  to tag which vectors red exercised and which blue detected, feeding the matrix.
  No deep referee surgery; the referee stays per-tier, the classifier is a layer
  on top.

### Red's exploit engine + the no-seeding line (decided)

- Red drives **real `msfconsole`** on Kali for the network-service family and the
  capability library.
- Red **selects the module itself** from its own service fingerprint — the
  library never auto-fires. The module *catalog* is supplied tradecraft (the same
  precedent as the seeded docker command and Dirty COW PoC); **which service is
  vulnerable and which module applies stays red's discovery.** That is the
  no-seeding line for this project.
- Reproducibility: pin the module version and fix msf options where the module
  allows; accept the residual non-determinism already inherent in an LLM-driven
  live run (flag non-deterministic steps, per the forensics-reproducibility rule).

## Definition of done

A **coverage matrix** (persisted artifact, fills in as families land):

```
vector            | red reaches | blue detects | blue prevents
------------------+-------------+--------------+--------------
ssh brute         |     ✅      |      ✅      |      ✅
sqli payroll      |     ✅      |      (T2)    |      —
docker breakout   |     ✅      |      ✅      |      ✅
dirtycow          |     —       |      —       |      —
proftpd mod_copy  |     —       |      —       |      —
mysql blank-root  |     —       |      —       |      —
... (every listening-service vector)
```

"Linux box covered" = **red-reach + blue-detect true for every row**;
blue-prevent is the stretch per vector. This matrix is also the capstone
artifact and the template whose columns later get a Windows sibling.

## What's left to the builder

- Exact test fixtures per family (synthetic passwd for the uid=0 sensor, captured
  ProFTPD exploit output, etc.) — follow the docker arc's precedent of unit-testing
  against *real* captured output.
- The precise shape of the coverage-matrix artifact (JSON + a rendered table;
  likely an extension of the existing `episodes.jsonl` / episode-report machinery).
- Internal structure of the capability library and the anomaly profiler — to be
  designed during the step-3 extraction, informed by families 1–2.
- Whether the battle-replay viewer gains a per-family / coverage view (cosmetic,
  deferred).

## Decisions locked (2026-11-05 brainstorm)

- **Track:** Linux breadth-first; Windows deferred.
- **Mechanism:** Hybrid C — hand-craft families 1–2, extract the engine, 3–5 fall out.
- **O1 + red agency:** real `msfconsole`, red selects the module (see "no-seeding
  line" above). msf confirmed present on `.11`.
- **Coverage:** opportunistic default + per-vector focus scenarios; matrix
  auto-derived via a `(tool,args,output)→vector` classifier over the timeline.
- **Prevent column:** derived = detected AND red capped below the vector's tier
  (docker-reflex precedent); a per-family prevention reflex only where a vector
  needs one.
- **Vector list:** the closed set enumerated from the 2026-11-05 port scan
  (builder confirms at the margins — e.g. whether 111/rpcbind and multi-vector
  SMB are in scope).
- **Profiler baseline acquisition (flagged, not a blocker):** the step-3 engine
  extraction must add a cross-episode "quiet baseline" phase to the arena so the
  anomaly profiler can learn "normal" outside red's activity window; the box's
  normal legitimately includes vulnerable-but-running services, so the profiler
  keys on *change*, not on service reputation.

## Still open (default set, revisit at the step-3 extraction)

- **O2 — anomaly profiler replaces vs. coexists with hand-coded sensors.**
  *Working default:* **coexist** — the profiler augments (broad, deployable,
  catches the unforeseen) while the bespoke sensors keep their high-precision
  detections. Revisit once the profiler's real precision/recall is measured on
  families 1–2. Not a blocker for approval; affects only how families 3–5 wire
  detection.
