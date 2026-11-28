# PurpleLoop — Windows Persistence Pursuit (Design)

Date: 2026-11-28
Status: APPROVED (2026-11-28) — horizon set to ~32 turns for the persistence objective
Objective target: `persistence` on a Windows (WinRM) engagement

## Intent / why

Today a Windows persistence engagement is decided in one exchange: red plants an
autostart entry, blue's `investigate_persistence_windows` baseline-diff catches it
on the next sweep (detect=1.0, dwell≈0 in every matrix cell), evicts it, and the
referee ends the episode on that first eviction as an instant blue win. There is no
contest: red has one move, blue sees everything for free, and the episode is over.

A real intrusion is a *pursuit*. A red-teamer who loses one foothold does not stop —
they re-establish through a different technique, because persistence is redundant by
design. A defender is not an oracle running one all-seeing query; they have to
*choose where to look* and *anticipate* the attacker's next vector. We want the
engagement to become several rounds of move / counter-move, decided by who is ahead
when the clock runs out: does red still hold *any* un-evicted foothold, or did blue
run the whole repertoire down.

This extends the north-star principle (agents generalise to any environment; the dojo
forges transferable lessons): a single-shot game teaches a single-shot lesson. A
pursuit forces both sides to keep adapting, which is what compounds `knowledge.json`.

## Goals

- Red can **re-establish** after an eviction, reaching for a *different* technique
  each time ("finds another way") — not re-running the burned one.
- Red has techniques that **evade blue's current sweep** until blue grows coverage,
  so evasion is real, not cosmetic.
- Blue must **choose where to look** (coverage is no longer free and total) and is
  rewarded for **anticipating** red's next vector rather than only mopping up.
- The episode **runs to the horizon** (or until red's repertoire is exhausted),
  scored by standing persistence — not ended on first eviction.
- Every technique is **reversible and leaves the box clean** (hard constraint — live
  boxes; dojo teardown + blue eviction must both fully remove it).

## Non-goals

- Linux persistence changes. This is Windows/WinRM-only; the Linux SSH-key path is
  untouched.
- New *objectives*. Still the `persistence` objective; we are deepening it, not
  adding exfil/root variants.
- A real malware payload. Planted "payloads" stay inert (a benign command such as
  `calc.exe` / a marker write); the game is about the persistence *mechanism's*
  visibility and survival, not code execution.

## Anti-goals (failure even if it technically runs)

- Red "wins" by a technique that the dojo cannot clean up → a dirty box between
  episodes. Reversibility is non-negotiable.
- Blue coverage split into so many sweeps that it can never keep up → red always
  wins; the game must stay winnable from both sides.
- Scoring that credits red for a plant it never actually landed, or blue for an
  eviction that did not remove a standing entry (the existing verified-readback /
  verified-removal discipline must hold per technique).

## Constraints

- **Live Windows box over WinRM-through-jump.** Every technique must create and
  remove cleanly via PowerShell/`cmd` the executor already drives. Slow transport —
  keep per-turn command count low.
- **Shared-jump topology** (just fixed): red and blue share the jump source IP, so
  attribution/response is by *account*, not IP. The pursuit builds on that, it does
  not reopen it.
- **Verified signals.** A plant counts only on a verified creation readback; an
  eviction counts only when a standing entry is actually removed. Mirror the existing
  `_WIN_PERSIST_PLANTED` / `remove_persistence` discipline per technique.
- **Reproducibility.** Baselines are captured at engagement start; no non-deterministic
  step may silently shift them.

## Approaches considered

**1 — Red-evades (extend red past the sensor).** Give red techniques the current
sweep misses; blue stays omniscient on its three classes until taught new ones.
*Leanest, but blue's side stays an oracle on what it does cover — less "predict",
more "blind-spot race."*

**2 — Blue-choose (split + budget blue's vision).** Keep red's three classes, make
blue sweep one class per turn. *Makes blue's choice real, but red's repertoire stays
small — more "hide in the gap" than "find another way."*

**3 — Both (CHOSEN).** Red gets new techniques beyond the swept three AND blue's
coverage is split across per-class sweeps with a per-turn cost, so blue must choose
what to watch and can anticipate. This is the only approach that delivers *both*
halves of the vision — red genuinely finding another way, and blue genuinely
hunting rather than mopping up. Larger build; phased below. Chosen by the human.

## The design (Approach 3)

### A. Plant registry (the spine both scorer and blue read)

Replace the single `red_persistence_planted_turn` / `blue_persistence_removed_turn`
scalars with a **registry**: a list of plant records on `SimulationState`:

```
persistence_plants: List[PlantRecord]
  PlantRecord = { technique: str, identity: str, planted_turn: int,
                  evicted_turn: Optional[int] }
```

- `technique` ∈ the repertoire (task, service, run_key, wmi_subscription,
  startup_folder, …).
- `identity` = a stable string naming the specific entry (e.g. `task|\SecHealth`,
  `wmi|CommandLineEventConsumer|Updater`) so eviction can be matched to a plant.
- A plant is appended when red's creation of that technique is verified.
- `evicted_turn` is set when blue removes that specific entry.
- **Standing** plants = records with `evicted_turn is None` at any moment.

Scalars that other code reads (`red_persistence_planted_turn`) become derived
(min planted_turn) for backward compatibility, or are migrated.

### B. Red repertoire ("finds another way")

Red's Windows persistence doctrine (`phase_guidance` / `RED_WINDOWS_ADDENDUM`) gains
a **ranked set of techniques**, and the directive to *rotate to the next one when a
plant is evicted*, not re-run the burned technique. Target repertoire:

1. Scheduled task (`schtasks /create …`) — swept today.
2. Auto-start service (`sc create …`) — swept today.
3. Run / RunOnce key — swept today.
4. **Startup folder** drop (`%APPDATA%\…\Start Menu\…\Startup\x.lnk|.bat`) — NOT
   swept today → evades until blue grows coverage.
5. **WMI event subscription** (`__EventFilter` + `CommandLineEventConsumer` +
   `__FilterToConsumerBinding`) — NOT swept today → evades.
6. (Stretch) COM hijack / IFEO debugger — deferred past Phase 1.

Each technique: a verified creation signal (extend `_WIN_PERSIST_PLANTED` into a
per-technique matcher returning the technique + identity), inert payload, and a
known removal command.

### C. Blue partial vision + anticipation

- **Split the one sweep into per-class sensors** (or one sensor taking a `class`
  argument): `investigate_persistence_windows` becomes per-class so a single call
  covers one class, not all. New classes (startup, WMI) get their own enumerate +
  baseline-diff, reusing `_capture_baseline` / `_diff_baseline`.
- **Cost = turns (lean default).** Blue already acts one tool call per turn; with
  coverage split, covering every class costs several turns, so red's timing and
  class choice open real windows — no new hard-budget mechanic required for Phase 1.
  (Optional dial: a hard per-turn sweep budget. Deferred.)
- **Anticipation (scored, Phase 3).** A blue action to *name the class it expects
  red to use next*; if red then plants that class and blue had pre-swept/armed it,
  blue catches at low dwell and earns a scoring bonus. Rewards being on red's tail.

### D. Eviction across the repertoire

`remove_persistence_windows` is extended to remove **every** class in the registry
(startup files, WMI filter/consumer/binding, etc.), not only Run/service/task.
Eviction sets `evicted_turn` on the matching registry record. Blue cannot win a class
it cannot both *see* (a sensor) and *remove* (an eviction path) — the two land
together per technique.

### E. Loop + scoring to the horizon

- Referee persistence branch **no longer returns an instant blue win on first
  eviction.** The episode runs to `max_turns` (or an early end if red's repertoire is
  exhausted AND nothing stands).
- **Horizon verdict:** BLUE win if no plant stands (every landed plant was evicted);
  RED win if any plant stands at the horizon. Prevention (blue cut the foothold
  before red planted anything) remains a blue win (just shipped). Dwell / rounds are
  recorded per plant for the scorecard.
- The existing "fast blue win on eviction" is replaced by "keep hunting" — eviction
  is progress, not victory, until the board is clear at the horizon.

## Phased build order (toward the full Approach 3)

- **Phase 1 — pursuit spine, one new evasive technique.** Plant registry;
  loop-to-horizon + standing-plant verdict; add ONE evasive technique end to end
  (startup folder: red plant doctrine + signal, a blue startup-folder sensor with
  baseline-diff, eviction) ; red doctrine to rotate after eviction. Proves red
  "finds another way" and the episode becomes multi-round. Verify live.
- **Phase 2 — split blue vision + second evasive technique.** Per-class sweeps;
  WMI subscription technique + sensor + eviction. Blue must choose what to watch.
- **Phase 3 — anticipation scoring** + remaining stretch techniques (COM/IFEO).

Each phase: SDD-style (decision → unit tests → live-check on `.17`), its own
commit(s), green suite before moving on.

## What's left to the builder

- Exact PowerShell for each new technique's create / enumerate / remove (must be
  idempotent + reversible; verify on `.17`).
- Whether the per-class sweep is one sensor with a `class` arg or N sensors (builder's
  call; keep tool-count sane for the model).
- Registry migration details for code currently reading the scalar turn fields.
- Dojo (`windows_dojo.py`) additions if a technique needs a pre-seeded artifact.

## Builder-check resolutions (2026-11-28)

A fresh reviewer read this doc against the code and raised five points. Four are
resolved here as design decisions; the fifth is for the human.

1. **`objective_met()` in a pursuit (steering vs learning).** `RedAgent.objective_met()`
   latches True on red's first-ever plant (append-only history) and `phase_guidance`
   only steers while `not objective_met()` — so after the first eviction red would get
   no "rotate to the next technique" steering, defeating Goal #1. **Decision:** the
   *steering* gate consults the plant registry — red keeps being steered while **no
   plant currently stands** (every landed plant has an `evicted_turn`). *Learning* is
   unchanged: the reflection brief already keys on the graded horizon outcome, which in
   this design is "did red hold a standing plant at the horizon." Consequence: the
   registry must be readable from the agent layer, not only orchestrator/referee.

2. **Plant identity namespace / eviction matching.** Red's plant is credited from red's
   command *output* (regex, no identity); blue's removal yields canonical
   `_list_win_persistence` strings (e.g. `task|\SecHealth`, leading backslash from
   `schtasks /query` that red's `/tn SecHealth` lacks). Naive arg-parsing would
   mismatch and never set `evicted_turn`. **Decision:** at plant-verification time, run
   the enumeration and capture the **new canonical entry** (diff against the
   pre-plant snapshot) as the registry `identity`, so plant and eviction share the
   `_list_win_persistence` namespace by construction.

3. **Cleanup when RED wins (plant stands at horizon).** `disconnect()` and
   `teardown_windows_case` remove accounts/firewall/audit and dojo CASE_FILES, but
   nothing removes red's *runtime* plants — masked today only because the episode ends
   on first eviction. In a pursuit the red-win state is "plants left standing," which
   would persist onto the live box (the dirty-box anti-goal). **Decision (new
   requirement):** the between-episode reset path gains an **unconditional**
   "remove every post-baseline persistence entry across all classes" sweep that runs
   regardless of episode outcome. Phase 1 cannot ship without it.

4. **Detecting "repertoire exhausted" for the early end.** No state tracks which
   techniques red has burned. **Decision:** drop the explicit early-end for Phase 1 —
   run to `max_turns`; reuse the existing `_stall_blue_win` stall path as the "red gave
   up" signal. Add exhaustion tracking later only if episodes waste turns in practice.

## Open decision for the human

5. **Horizon length (`max_turns`) for a persistence engagement.** Default today is 20.
   A multi-round pursuit — plant, hunt, evict, re-plant across several techniques — over
   slow WinRM-through-jump, with blue's coverage split so each class costs a sweep, may
   not fit in 20 turns; too short and blue structurally cannot run the repertoire down
   (the "red always wins" anti-goal). **Proposed:** raise the persistence-objective
   horizon to **~32 turns** (≈ enough for blue to cover ~4 classes and still mop up two
   rounds), tuned by live-check on `.17`. Awaiting the human's call on the number.
