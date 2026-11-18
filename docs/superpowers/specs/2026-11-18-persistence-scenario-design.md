# Scenario slice #1 — the persistence engagement — design

Date: 2026-11-18
Status: proposed (full design, awaiting approval)

## Intent / why

The project's north star is an **agentic purple loop**: red discovers and chains
real vectors, blue detects and remediates them — scored like a real engagement,
not a flag hunt. Today the win is anchored on `/root/flag.txt` (T3 root read),
which wears three hats at once (red's objective, blue's main BREACH signal, the
score). Real environments have **attack vectors and impact**, not flags.

The agreed path (build-then-extract, matching this project's own families→engine
rhythm) is to build **one non-flag scenario end-to-end**, learn what a scenario
needs, then build a second, then extract a scenario abstraction. This doc is
**slice #1: a persistence engagement**, where the win is not "red read a file"
but "**red's backdoor survived blue's eviction.**"

Persistence is the chosen first impact because its mechanics already exist
(Family 5) — so the slice is mostly *re-anchoring the objective and win*, not new
red capability — and because it is a true residency cat-and-mouse that exercises
the full detect → remediate → **verify** loop, with the pedagogical crux that a
password lock does NOT evict a planted SSH key.

## Goals

- A selectable `persistence` objective for an engagement.
- Under it, **red's objective is to plant an SSH-key backdoor that survives** —
  not optional flavor as it is today.
- **Blue wins only by removing the planted key** (`remove_persistence`) before
  episode end. Detecting it, or locking the account's password, is NOT a win —
  the key still authenticates.
- A persistence win-evaluation that decides the episode winner when
  `objective == "persistence"`, expressed as the purple ledger for the
  persistence vector: **planted (red reached) / detected (blue saw) / removed
  (blue closed).**
- The episode report states the persistence outcome in those terms.

## Non-goals / anti-goals

- **No scenario spec / loader / multi-impact dispatch.** That is the *extract*
  phase after slice #2. Slice #1 adds persistence as one more selectable
  objective alongside `foothold`/`exfil`/`root`, nothing more.
- **Not deleting the flag.** `root` stays a valid objective; persistence is a
  new sibling. The flag is demoted conceptually, not removed.
- Not changing foothold/exfil/root grading, the tier board, or existing sensors.
- Not building new red planting capability (reuse the existing plant + the
  `_check_red_persistence_planted` detector) or new blue tooling (reuse
  `investigate_persistence` / `remove_persistence`).

## Constraints

- Reuse existing mechanics: red plant + `red_persistence_planted_turn`
  (orchestrator), blue `investigate_persistence` + `remove_persistence`, the
  between-episode reset's authorized_keys cleanup.
- Tests run with `uv run python -m pytest`.
- No commit to master without the user's go-ahead; standing git rules apply.

## Approaches considered

**How the persistence win is evaluated at episode end:**

- **A — in-sim state flags (CHOSEN).** Red wins if `red_persistence_planted_turn`
  is set and blue did **not** successfully `remove_persistence` on the planted
  account after that turn; blue wins if it did. Deterministic, reuses signals
  already on `SimulationState`, no live probe. Right size for a first slice.
- **B — live re-verification.** At episode end, actually test whether the planted
  key still authenticates on the box. Ground truth, but entangles with the
  between-episode reset and needs a live probe. Deferred as the realism upgrade
  once the slice proves out.

**What counts as a blue win:** blue must have *removed* the key. Considered and
rejected "detection is enough" — it erases the whole point of persistence (the
thing that survives detection + a password lock). So the win requires the
removal action to have run and succeeded on the planted account.

## The how (decided)

Decided choices; exact signatures/wording left to the plan/builder.

1. **New objective value `"persistence"`** on `TargetProfile.objective`
   (`src/target.py`), selectable per run (CLI/arena plumbing — a builder detail,
   following how `objective` already reaches the profile).

2. **Red objective under persistence** (`RedAgent.objective_met`, doctrine in
   `src/agents.py`): when `objective == "persistence"`, red's goal is
   `red_persistence_planted_turn is not None` (it has planted a surviving
   backdoor). The red doctrine shifts planting from "optional, nothing requires
   it" to the **primary objective** under this scenario — foothold first, then
   plant and keep a key. Red still needs a foothold to plant, so the foothold
   tier remains a prerequisite, not the win.

3. **Track blue's eviction.** Add `blue_persistence_removed_turn`
   (`SimulationState`, `src/orchestrator.py`), set when blue's `remove_persistence`
   succeeds on the account red planted into. Mirrors `red_persistence_planted_turn`.

4. **Persistence win-eval.** A function (in `src/referee.py` or `src/arena.py`,
   builder's call for cohesion) that, when `objective == "persistence"`, returns
   the winner: **blue** if `blue_persistence_removed_turn` is set and after the
   plant; **red** if red planted and blue did not remove by episode end; **None**
   if red never planted (no engagement on this vector). This overrides the
   tier-based `graded_result` for persistence episodes; tier/flag grading is
   untouched for the other objectives.

5. **Report / ledger.** The episode report (debrief/scorecard) states the
   persistence vector as **planted @turn / detected @turn / removed @turn** and
   the resulting winner, so the output reads as the purple ledger the north star
   wants, not a flag verdict.

## What's left to the builder

- Exact CLI/arena plumbing to select `--objective persistence` (follow how
  `objective`/`flag_path` already flow into the profile).
- Where the win-eval lives (`referee.py` vs `arena.py`) for best cohesion with
  `graded_result`.
- Exact red doctrine wording for the persistence objective.
- Whether `blue_persistence_removed_turn` keys off the tool-result status alone
  or also re-confirms the account matches red's planted account (prefer matching
  the planted account to avoid crediting an unrelated removal).

## Verification

- **Unit:** red `objective_met()` true iff planted under persistence objective;
  win-eval returns blue when removal-after-plant, red when plant-without-removal,
  None when never planted; a password-lock-without-removal does NOT yield a blue
  win (the pedagogical crux); tier/flag grading unchanged for other objectives.
- **Regression:** full suite green; foothold/exfil/root episodes unaffected.
- **Live (after merge):** one earned+observe episode with `--objective
  persistence` — red plants a key; a blue that only locks the account loses, a
  blue that runs `remove_persistence` wins. This is the first engagement decided
  by an impact, not a flag.
