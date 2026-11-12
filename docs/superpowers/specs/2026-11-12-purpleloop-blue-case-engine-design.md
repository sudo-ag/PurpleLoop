# PurpleLoop — Blue's In-Episode Case/Story Engine (Design)

Date: 2026-11-12
Status: design, pending approval

---

## Intent / why

Blue today is "14 hardcoded sensors + a verdict." Each sensor is a bespoke
check for one anticipated vuln (there is literally a `# slots in here once it
lands` comment in `src/agents.py`). Blue's triage steering
(`BLUE_TRIAGE_GUIDANCE`: TRIAGE → ATTRIBUTE → IDENTIFY → RESPOND) tells it to
corroborate a lead across sensors *in the moment*, but nothing is written
down and carried forward. The "story" of an episode exists only implicitly in
the model's context window: blue never maintains an explicit "here's what I
believe so far, and how sure I am," never re-reads it next turn, and never
explicitly asks "does this new clue change my hypothesis?" When the episode
ends, that reasoning evaporates except for a one-line lesson.

This is the first slice of the project's north-star principle (TODO.md,
reaffirmed 2026-11-12; extends the 2026-10-22 / 2026-10-23 "agents are the
portable product, the box is the dojo" vision): **agents must generalize to
any environment, not pattern-match rules we hardcoded for this dojo.** A
defender that reasons about clues into a story transfers to a real box; a
defender that only fires pre-written per-vuln rules does not.

It also fixes the user's original complaint — "I can't tell what blue is
doing from the reports, it's just run output." A blue that assembles an
explicit, inspectable case is a blue whose timeline *reads* as a narrative.
That inspectable case is the data the later executive-summary deliverable (③)
will narrate, and the battle-replay deliverable (①) will visualize — so this
engine is the foundation both of those stand on. They are **out of scope
here** and get their own designs.

## Goals

- Blue maintains an explicit, per-episode **case file**: a list of **leads**
  (each: what was observed, the turn it landed, a confidence) plus a current
  **working hypothesis** (a short claim + a confidence), persisted across
  turns within the episode.
- **Blue does the reasoning; the orchestrator owns the structure.** The case
  file is a scratchpad the orchestrator persists and blue cannot corrupt;
  blue populates it through tools (e.g. `record_lead`, `update_hypothesis`).
  The *model* decides what connects to what and how confidence moves — nothing
  about which clues correlate is hardcoded.
- Each turn, after its sensor runs, blue reviews the case and files the new
  clue as one of: strengthens the current hypothesis, opens a new lead, or
  contradicts/weakens an existing lead. The updated case is readable by blue
  on the next turn (closed build → review → adapt loop).
- Blue **acts on the connected picture, not single triggers**: when its
  working hypothesis crosses a confidence bar, it drives its *existing*
  response actions (`contain_attacker` / `remediate_account` / etc.), citing
  the leads that justified it.
- The case file is carried through to `ep_NNN.json` (via
  `arena.build_replay`) so it is inspectable after the run and available to
  deliverables ① and ③.

## Non-goals / anti-goals

- **No general-purpose "investigate anything" tool this slice.** The other
  half of the brainstormed hybrid — blue running free-form investigative
  commands on a vuln nobody pre-wrote a sensor for — is deliberately deferred
  to a later slice. It needs its own guardrail surface and a way to score
  free-form detection; folding it in here would balloon the slice. This
  engine is built so that tool's findings can later land as leads in the same
  case, but it is not built now.
- **No new scoring tier, and no change to what counts as detect/defend.** The
  case makes blue's *existing* response decisions smarter; it does not invent
  a new thing to score. T1/T2/T3 and the detect/dwell/defend logic in
  `src/orchestrator.py` are untouched.
- **Not cross-episode memory.** The case resets each episode. Durable
  takeaways still flow into `knowledge.json` as they do now, via the existing
  reflection path — unchanged.
- **Anti-goal:** testing that the LLM reasons *correctly*. We test the
  plumbing (leads persist, the hypothesis is readable next turn, action fires
  when blue declares high confidence), never that a given model draws the
  right conclusion — that is what live episodes are for. A design that bakes
  "correct" correlations into asserts has failed, even if green.
- **Anti-goal:** red getting an equivalent engine this slice. Red's
  self-reporting is part of deliverable ③, not this one. Scope is blue only.

## Constraints

- Same house conventions as every prior family: TDD, surgical changes, reuse
  the existing engine (`_capture_baseline`/`_diff_baseline`, the
  tool-schema/dispatch/`BLUE_TOOL_PRIORITY` wiring pattern, the
  `SimulationState` field convention).
- The case must be robust to a weak/sloppy driver model: a malformed or
  missing tool call must not crash the turn or corrupt the case (mirror the
  existing `_normalize_action` / try-except-per-dispatch discipline in
  `Agent`).
- `--observe` mode interaction: the case is built and acted-on-in-reasoning
  the same way, but any real containment stays held exactly as it is today
  (the case changes *why* blue decides to act, not whether `--observe`
  suppresses the live DROP).
- Must not slow a turn meaningfully or bloat the prompt unboundedly — the
  case fed back into blue's context each turn needs a size cap / compaction
  rule (like `_compact_log_events`).

## Decisions (made during the 2026-11-12 brainstorm)

- **Architecture: "B with A as scaffolding."** Orchestrator owns and persists
  the case structure; blue reasons to fill it. (Chosen over pure-rules A,
  which would hardcode correlation and defeat the generalization goal.)
- **Case shape:** leads (observation, turn, confidence) + one working
  hypothesis (claim, confidence). Confirmed as matching the user's mental
  model.
- **Scope:** per-episode; cross-episode stays in `knowledge.json`.
- **Scoring:** unchanged.
- **Acting:** blue acts when its own stated hypothesis-confidence crosses a
  bar, driving existing response actions — "both" build-the-story *and*
  act-on-it, per the user. The report-facing payoff (the case in
  `ep_NNN.json`) is a free byproduct, not a separate mechanism.

## What's left to the builder

- **Where the case lives.** Likely a field on `SimulationState` (per the
  existing field convention) or a sibling structure the orchestrator owns;
  the builder picks, consistent with how `red_tiers`/`blue_tier_detect` are
  held.
- **The tool surface blue uses to update it** — exact tool names, arg
  schemas, and whether `record_lead` / `update_hypothesis` are one tool or
  two. Must follow the existing blue tool-schema + dispatch + priority
  wiring.
- **The confidence representation** (enum like low/med/high vs. a number) and
  **the action bar** — what hypothesis-confidence triggers which response,
  and how that threads into the existing triage guidance without contradicting
  the "corroborate before you contain" rule already in `BLUE_TRIAGE_GUIDANCE`.
- **How the case is fed back into blue's context each turn** and its
  compaction/size cap.
- **The `ep_NNN.json` / `build_replay` carry** — shape of the serialized
  case, so ① and ③ can consume it later.
- **Test plan** — plumbing-level (persistence, readback, malformed-input
  safety, action-fires-on-declared-confidence), plus one live episode as the
  only real evidence the reasoning loop works end to end.

## Resolved after builder check

A builder check (2026-11-12) surfaced five questions. Four were settled as the
designer's call (below); one needs the user and is tracked in the next section.

- **Same-turn ordering & cost (settled: no extra model call).** Blue updates
  the case via tool calls *within its existing turn* — the agent already makes
  multiple tool calls per turn, so `record_lead`/`update_hypothesis` are just
  more of them, not a second LLM round-trip. A containment decided in turn N is
  evaluated against the hypothesis as updated in turn N (same turn), so the
  loop stays build→review→act within one turn. No meaningful latency add.
- **Hypothesis history (settled: keep it).** Each turn's hypothesis (claim,
  confidence, turn) is appended to a history log, not just overwritten. It is
  cheap and it is exactly what deliverables ① (battle replay) and ③ (executive
  summary) need to show *how the story changed over time*. The current
  hypothesis is the tail of that log.
- **`--observe` records the counterfactual (settled: yes).** When `--observe`
  holds the live action, blue's case-driven "would have acted on hypothesis X,
  citing leads Y/Z" decision is still written to the case and to
  `ep_NNN.json`. Observe mode is blue's curriculum, so the whole point is to
  capture what blue *would* have done; the live DROP stays suppressed exactly
  as today.
- **Lead lifecycle & compaction (settled: full store, compact only the prompt
  view).** The complete, uncompacted case (every lead, retracted/weakened ones
  included) lives in `SimulationState` and is carried to `ep_NNN.json`.
  Compaction/size-cap applies ONLY to the view fed back into the prompt. A
  weakened or superseded lead stays in the store and stays citable, so any
  lead an action cited remains resolvable for ③ even after compaction drops it
  from the prompt view.

## Resolved by the user

- **Action bar: advisory, with a thin-evidence floor (user decided
  2026-11-12).** Blue reasons and calls its existing response action itself,
  citing the leads that justified it — faithful to the "blue reasons"
  architecture (B). The orchestrator persists the case and records the cited
  leads, and the existing "corroborate before you contain" rule stays as
  prompt-level triage guidance. The ONE code guard: a containment whose cited
  leads all come from a *single* sensor is hard-blocked. That is a floor
  against the dumbest false positive, not a correlation rule — multi-sensor
  evidence sufficiency stays blue's judgment, so nothing about "what counts as
  enough" is hardcoded. Chosen over a pure-advisory version (no floor) and a
  code-enforced quorum gate (safest, but hardcodes evidence sufficiency and
  would not transfer to a new box). Tests: the plumbing, plus the single-sensor
  block specifically.
