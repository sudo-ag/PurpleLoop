# PurpleLoop — North-Star Vision: Autonomous Purple-Team Assessment Platform

Date: 2026-10-23
Author: brainstorming session (agonzalez81) + Claude

Status: **vision / direction doc.** Not an implementation spec. It anchors the
phases after the current dojo work and is the capstone narrative. Concrete next
build (the Dirty COW arc) is tracked in `TODO.md`/`HANDOFF.md`, not here.

> How to read this: statements marked *(decided)* are the human partner's calls
> from the session. Statements marked *(my call)* are Claude's framing for the
> partner to confirm or override. *(open)* marks what a builder/the partner still
> has to settle.

---

## Intent — the why

Automated *attack* is commoditized: point a tool at a vulnerable box and it pops
— "run it, boom, exploited." Automated *defense* is not. A defender has to live
on a running system, read its telemetry, tell real malice from noise, and act
without locking out the people who belong there. That asymmetry is the
opportunity. *(decided)*

PurpleLoop's bet: build **two learning agents** — a red that attacks and a blue
that defends — and run them as a **closed adversarial loop against a company's
own, authorized infrastructure**, producing **analytics on that infrastructure's
defensive posture**. Red is the *forge*; blue is the *product*. *(decided)*

Two things define success, in the partner's own words:
1. **"Look what the agents learned that I never taught them."** The learning loop
   produces genuine, emergent tradecraft — defenses and attacks nobody scripted.
   (Already real in miniature: blue's reflections moved, unprompted, from "block
   the scanner" to "restrict docker-group membership and watch for host-mount
   containers" after it kept losing to the docker breakout.) *(decided)*
2. **"A defender tool someone could actually deploy."** Reframed this session into
   **assessment mode**: a company runs the agents against infra *it owns*, in a
   consented window, to get viable analytics — not a 24/7 autonomous responder on
   production. *(decided)*

## The deliverable — what a run produces

One run, two layers for two audiences. The report never claims "unbreakable" — a
tool that reassures is worthless. Its job is the opposite: **it will always find
an angle, and the report is this run's angle plus your trend.** *(decided)*

- **The missed angle (for engineers).** The specific *chained* path red found that
  the defenders didn't account for — e.g. "a foothold on `boba_fett` reaches root
  via the docker group, and nothing in your logging would ever show it." A scanner
  lists CVEs; it cannot produce this, because it doesn't chain foothold → privesc →
  *blind spot*. The blind spot — what red achieved that blue's telemetry never saw
  — **is** the headline finding. *(decided)*
- **The resistance / resilience metric (for management).** How far up the tiers red
  got, dwell time before blue detected, paths blue caught vs missed. Weak as a
  snapshot; the sell is the **trend** — "you're 3× harder than last quarter and you
  closed the docker blind spot." A board slide. The system already computes the
  inputs (tier board, detect/dwell, contain/remediate outcomes). *(decided)*

The emergent-learning angle is what makes the "missed angle" credible: blue finds
gaps nobody scripted, which is the evidence it generalizes beyond what defenders
anticipated. *(my call — framing)*

## The moat — why the pair, not two tools

Red alone is a crowded, commoditized market (breach-and-attack simulation:
AttackIQ, SafeBreach, Cymulate). Blue alone has nothing to defend against. The
defensible, unique thing is the **closed loop**: a fierce *adaptive* red probes a
*learning* blue on the customer's own infra, and the deliverable is the **gap
between them** — did your real defenses catch what an attacker that learns would
actually do? *(my call — the partner leans "two great tools, used where needed";
recommended framing is "the pair is the point, each usable solo." To confirm.)*

## Goals

- A portable **blue** defender agent: resident on a target, **profiles the box it
  lands on** (services, log sources, normal baseline, attack surface) before it
  defends, and augments — does not replace — a human blue team. *(decided)*
- A **red** agent made fierce by breadth: exercised across many vulnerable-box
  classes so blue sees diverse TTPs, not one trick. *(decided)*
- Agents whose *intelligence is portable*: lessons are tradecraft, box-specific
  facts are injected (`TargetProfile`) and discovered, never baked. *(decided,
  carried from Phase 1)*
- A report layer that turns a run into the two-layer deliverable above, trended
  across runs. *(decided)*

## Non-goals / anti-goals

- **Not** a 24/7 autonomous responder on live production. The false-positive /
  blast-radius / trust problem (a wrong auto-action locks out real users) is why
  autonomous response barely exists in production; assessment mode sidesteps it by
  being consented, windowed, reversible, and reported. *(decided)*
- **Not** a scanner / CVE lister. The value is the *chained, context-specific,
  blue-blind* path, which a scanner structurally cannot produce. *(decided)*
- **Not** a red-only BAS tool. That half is commodity; shipping only red forfeits
  the moat. *(my call)*
- **Anti-goal:** a report that says "you're secure." If a run can't find an angle,
  the run is suspect, not the infra. *(decided)*
- **Anti-goal:** pointing agents at systems the operator does not own/authorize.
  Out of legal scope, full stop. *(decided; see constraints)*

## Constraints

- **Authorized targets only.** VulnHub / HackTheBox / vulnerable images are used by
  **downloading and running them locally** (owned VMs, as Metasploitable is today),
  never by attacking a live public host. *(decided)*
- **Blue must be resident with telemetry.** Blue is not an attacker hitting a URL;
  it needs a login, sensors, and an attack actually in progress. This is why no
  public site offers a "both-sides" target — the both-sides is an *orchestration*
  PurpleLoop provides, not a venue to find. *(decided)*
- **The coupling rule:** every objective red can reach, and every escalation vector
  it can use, needs a matching blue sensor — or it is undefendable and unscorable.
  New attack surface ships with its detector. *(decided, carried)*
- **Reversible, cleaned actions; per-episode reset; no seeding** (red discovers, is
  not handed answers). *(decided, carried)*
- **Two runtimes, one brain** *(my call):* the arms-race *dojo* trains the
  policy — turn-based, scored, reset-able, aggressive actions fine. The *assessment*
  runtime is consented, windowed, conservative, reversible, augment-not-replace.
  Same trained agent, different runtime guardrails.

## Decided framings (recap of the calls made this session)

- Red = forge, blue = product. *(decided)*
- Deploy = assessment of owned infra for analytics, not production autoresponse.
  *(decided)*
- Deliverable = missed-angle (engineers) + resilience trend (management), never
  "unbreakable." *(decided)*
- The pair/closed-loop is the moat; each half usable solo. *(my call — confirm)*

## Enabling work — the path from dojo to platform

Roughly sequenced; detail lives in `TODO.md`.

1. **Richer narrative / multi-objective dojo box (near).** More to contest for both
   sides on already-instrumented ground: exfil the payroll DB, lateral-move to a
   second service, persistence — each with its coupled sensor. Deepens the
   both-sides curriculum and makes generalization worth doing (a one-flag box
   doesn't transfer interestingly). *(my call — recommended first)*
2. **Second Linux box via `TargetProfile` + blue baseline/auto-instrumentation
   (mid).** The real "grow out of the box": same OS, everything-else different,
   forcing all box-facts into the profile and forcing blue to *discover* its
   sensors and a normal baseline. This is the technical core of "blue learns the
   playing field it's in." *(decided direction; "learns the field" = profiling,
   my call)*
3. **Phase 2 MCP server — `run_red_campaign` / `deploy_blue` / `train_X_on` verbs.**
   Packaging the standalone agents for assessment use. *(carried)*
4. **Analytics / report layer.** Turn tier board + kill-chain timeline + blind-spot
   detection into the two-layer report; persist across runs for the trend. *(my
   call)*
5. **Windows (Metasploitable3 Windows) — north star, far.** Maximal proof of the
   portability thesis, but a *parallel* stack (Event Logs/Sysmon not auth.log,
   WinRM/SMB not SSH, PowerShell not bash, token/UAC privesc not docker/sudo). A
   second project's worth; sequencing it early would stall everything. *(my call —
   partner raised it as a future front)*

## What's left to the builder / the partner

- *(open)* **Analytics schema.** The exact fields of the missed-angle finding and
  the resilience metric, and how a run persists to support trending.
- *(open)* **One product or two.** Confirm the pair-is-the-moat framing vs. two
  independently-sold tools.
- *(open)* **Frozen vs live-learning blue in assessment.** Does deployed blue carry
  a trained-and-frozen policy, or keep learning during a customer run (riskier,
  less reproducible)?
- *(open)* **What "profiling the box" concretely enumerates** for an arbitrary
  Linux host (service discovery, log-source discovery, baseline window).
- *(open)* **Who the first real assessment target is** beyond the dojo (homelab /
  club lab / a second local vulnerable VM).
