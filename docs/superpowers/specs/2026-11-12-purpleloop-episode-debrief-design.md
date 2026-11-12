# PurpleLoop — Per-Agent Episode Debrief (Executive-Summary Reports) (Design)

Date: 2026-11-12
Status: design, pending approval

---

## Intent / why

Deliverable ③ of the three the user scoped (② the blue case engine is built;
① battle replay is later). Today an episode writes `ep_NNN.md` via
`Orchestrator.generate_report()` — but that is a *factual board*: final result,
a tier table, and a raw turn-by-turn timeline. The user's words: "when I look
at them it's just output from the runs." What they want instead is **each agent
reporting to them, like a team in an office meeting** — red walks in and gives
a pentest-style debrief of what it did and learned, then blue does the same.

So ③ is a **narrative layer on top of data that already exists**, not new
instrumentation. The episode already holds everything needed: the action
timeline (`state.history` / `ep_NNN.json`), the graded verdict + tier board
(`verdict()` / `tier_scoreboard()`), blue's new case file (`state.blue_case`
— leads → evolving hypotheses, from ②), and each agent's per-episode causal
lesson (`Agent.reflect()`'s return — the "Red learned / Blue learned" line,
currently printed and folded into `knowledge.json` but not captured per
episode). This round synthesizes those into a readable, first-person debrief.

This is also the first consumer of ②'s payoff: **blue's debrief narrates the
case it built** — the leads it filed and how its hypothesis evolved — so the
reasoning the engine made explicit becomes something the user can read.

## Goals

- A **per-agent, per-episode debrief**, same four-part pentest skeleton for red
  and blue, written first-person ("I scanned…", "I found…"):
  1. **Executive summary** — one paragraph: what happened this episode.
  2. **Actions taken** — the narrative of what the agent did, in order.
  3. **What I learned** — the takeaway.
  4. **What's next** — the follow-up.
- **Hybrid generation (user's decision):** a **deterministic skeleton** built
  by rules from the episode data (reproducible — same episode → same report,
  offline, free), plus an **optional LLM polish pass** behind a toggle
  (`--narrate`, default OFF) that rewrites each agent's four sections into
  flowing prose using the episode's model.
- **Blue's Actions + What-I-Learned are spined on the case file** (②): its
  debrief walks the leads it filed and how its working hypothesis moved
  (confidence shifts, multi-sensor corroboration).
- **"What's next"** is derived from the agent's `reflect()` lesson — the
  lessons are already phrased "<action> led to <consequence>, so next time
  <change>", so the forward clause is the next-step.
- The debrief is **appended to the existing `ep_NNN.md`** (one file the user
  already opens): the factual board stays on top, the "🔴 Red Debrief" /
  "🔵 Blue Debrief" narrative sections go below.
- Each agent's per-episode lesson is **captured into the episode data** so the
  debrief (and future consumers) can read it, instead of it only being printed
  and merged into `knowledge.json`.

## Non-goals / anti-goals

- **No new scoring, no new sensors, no change to the simulation or to ②.**
  Pure synthesis/reporting over data that already exists.
- **Not deliverable ① (battle replay)** — that's the non-technical visual, a
  later separate design. ③ is prose for the user to read.
- **Not a cross-episode / batch report** — one debrief per agent per episode.
  (A batch rollup could reuse this later; out of scope now.)
- **The deterministic skeleton must stand alone** — with `--narrate` OFF the
  report is complete and readable. The LLM pass only *polishes*; it never adds
  facts the skeleton didn't already state, and it is never required for a valid
  report.
- **Anti-goal:** the LLM pass inventing events. Its input is the skeleton's own
  facts; a polished sentence that asserts something not in the episode data is
  a failure even if it reads well. Reproducibility is the default and the LLM
  step is the one explicitly-flagged non-deterministic part (per the user's
  CLAUDE.md rule to flag non-deterministic steps).

## Constraints

- House conventions: TDD, surgical, reuse existing shapes
  (`generate_report`/`build_scorecard` wiring, the `reflect()` lesson, the
  `_outcome_brief` style, `Agent.summarize_experience`'s model-call pattern for
  the optional polish).
- The deterministic skeleton is pure string assembly from the state/episode
  data — unit-testable with a duck-typed stand-in state, no model, no boxes.
- The LLM polish pass must fail safe: if the model call errors or returns
  nothing, the deterministic skeleton is emitted unchanged (never a crash, never
  an empty section).
- Must handle a thin episode gracefully: an agent that did almost nothing (no
  foothold, an empty case, no lesson) still gets a coherent (short) debrief,
  not a traceback or blank section.

## Decisions (made during the 2026-11-12 brainstorm)

- Hybrid: deterministic skeleton + optional `--narrate` LLM polish, default OFF.
- Four-part skeleton (exec summary → actions → learned → next), first-person,
  same for both agents.
- Blue's narrative spined on the case file (②).
- "What's next" from the `reflect()` lesson's forward clause.
- Appended to `ep_NNN.md`; new module `src/debrief.py` owns the building.
- Per-episode lesson captured into the episode data.

## What's left to the builder

- **Module/function shape** of `src/debrief.py` — e.g. a
  `build_debrief(role, state, lesson, polish=None) -> str` plus per-section
  helpers; the builder picks, consistent with the project's style.
- **How the per-episode lesson is captured** — where `reflect()`'s return is
  stored on the episode (scorecard field, replay field, or passed directly to
  the debrief builder) so both the deterministic and polish paths read it.
- **The deterministic "Actions" narration rules** — how a timeline entry
  (tool + args + output) becomes one plain-language line per agent; blue's
  additionally walks `blue_case` leads/hypotheses. Reuse any existing
  tool→label mapping if one exists; otherwise a small rule set.
- **The `--narrate` prompt** for the polish pass (one per agent, fed the
  skeleton's own section text; instructed to rewrite, not add facts) and which
  model/credentials it uses (default: the episode's model).
- **Exact placement/anchors** of the appended sections in `ep_NNN.md` and
  whether the console end-of-episode line points at them.
- **Test plan** — deterministic skeleton (each section from stand-in data; thin
  episode; blue case spine); lesson capture; polish fail-safe (model error →
  skeleton unchanged); `--narrate` default OFF.

## Resolved after builder check

A builder check (2026-11-12) raised six questions; all settled as the
designer's call (grounded in the project's established direction and the user's
stated preferences — none required the user).

- **Built in-process at episode end (not a re-render CLI).** The debrief is
  built right after `run_simulation` returns and appended to `ep_NNN.md`.
  `--narrate` is an in-process flag on the run. The lesson and the debrief's
  inputs are ALSO persisted into `ep_NNN.json` so a future "re-render / re-polish
  an old episode from JSON" CLI is possible — but that CLI is out of scope this
  round (YAGNI).
- **Call order is already correct.** `reflect()` runs inside `run_simulation`
  (it prints "Red learned / Blue learned" before the episode returns), which
  returns before `generate_report()` writes `ep_NNN.md` (`arena.py:371-379`).
  So the lesson exists when the debrief is built — no reorder needed; the plan
  only needs to *capture* `reflect()`'s return (today it is printed and merged
  into `knowledge.json`, not handed back) onto the episode (`state`/`card`).
- **Exec-summary headline uses the GRADED verdict, not the legacy binary.**
  `generate_report`'s "Final Result" comes from the binary
  `blue_victory`/`red_captured_flag`, which can disagree with the tier board
  (`verdict()`/`graded_result`). The debrief states the **graded** outcome
  (`verdict()` + `tier_scoreboard()`) as its headline, so it never contradicts
  the tier table on the same page. Graded tiers are the project's established
  source of truth; the binary flags are legacy.
- **"What's next" has a fallback.** `summarize_experience` can return `""`, and
  the lesson's "so next time <change>" clause is not guaranteed. The builder:
  extract the forward clause when present; else derive a next step from tier
  state (e.g. "reached T1, stalled below T2 → next: a privilege-escalation
  path"); if there is no lesson at all, state "no explicit next step recorded."
  Never empty, never a crash.
- **Determinism: the debrief reads the already-captured lesson and never
  re-invokes `reflect()`.** The lesson's model call happens once, during the
  run; the deterministic skeleton only reads its stored text. The sole
  non-deterministic step is the optional `--narrate` polish. The reproducibility
  test asserts two deterministic builds from the same episode data are identical.
- **Actions attribution is honest.** Blue's "Actions taken" narrates blue's
  OWN tool calls (source of truth: role-tagged `state.history`).
  Orchestrator-initiated reflexes (`_auto_revoke_escalation`,
  `_auto_remove_rogue`, applied staged remediation) are listed under a separate
  "Automated responses" note, NOT claimed first-person — blue does not take
  credit for reflexes it did not reason about.
