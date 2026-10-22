# Phase 1 — Agent/Game Decoupling (Design)

Date: 2026-10-22
Status: approved design, pre-implementation
Author: sudo-ag (+ Claude)

## Why this exists (the vision it serves)

PurpleLoop's long-term goal is that **red and blue become portable, autonomous
agents a third party can plug into their own environment** — exposed over an MCP
server as high-level verbs (`run_red_campaign(target)`, `deploy_blue(host)`),
with the agents' intelligence, workflow, and learned tradecraft running *inside*.
A classmate adds the server to their harness and commands the juggernauts; the
brain is ours, not theirs.

The work decomposes into phases:

- **Phase A (ongoing):** make red & blue juggernauts on the dojo (account triage →
  T2 exfil → blue attribution/response → stealth/evasion).
- **Phase 1 (this spec):** decouple the agent from the game so an agent can run
  itself, standalone, with no `Orchestrator`.
- **Phase 2:** wrap the autonomous agents as an MCP server.
- **Phase 3:** generalize to arbitrary owned targets (generic discovery,
  host-agnostic blue sensors, an authorization/scope model).
- **Phase 4:** multi-agent delegation + real pentest/monitor engagements that
  produce a remediation report for the target org.

Phase 1 is the structural lever: it unblocks Phase 2 (MCP) and Phase 4
(multi-agent), and every Phase A feature from here is built *in* the decoupled
shape so portability is grown into, not bolted on.

## Guiding principle: the box is the dojo, not the product

The portable asset is the **agent's intelligence + workflow**. Target-specific
knowledge is **training data**. Red's real skill is "find the injectable surface,
dump creds, triage by privilege, pivot, escalate" — not "hit `payroll_app.php`."
Two rules follow, and they are the same rule the no-seeding decision already
enforces:

1. **Doctrine favors discovery.** Box *facts* (the app's name, the account roster,
   which group is privileged) are discovered at runtime via recon, never baked
   into prompts or handed to the agent.
2. **Lessons are tradecraft-level.** `knowledge.json` accumulates portable
   technique, not box facts — so it transfers to any environment. The learned
   lessons are the crown jewels a classmate actually benefits from.

## Definition of done (Phase 1)

> In a plain Python session: `red = RedAgent(target=..., objective=...)`,
> `red.run(max_turns=N)` executes a full campaign — self-steering, **no
> `Orchestrator`** — returning a trajectory + result. `BlueAgent(host=...).run()`
> likewise. **And** the existing arena (`python -m src.arena ... --observe`) still
> runs red-vs-blue with scoring and learning, unchanged, now built *on top of*
> those self-contained agents. All 179 tests green, plus new tests for the
> standalone path.

Steps 1–5 of the migration satisfy this. Step 6 (portable single-agent Learner)
delivers "drop me in a new system and let me learn it."

## Architecture: three layers

Inner → outer. Today's `Orchestrator` fractures across all three.

1. **Agent (portable).** Brain + tools + executor + `reflect()` + owns its
   `knowledge.json`. Public surface: `decide()`, `run()`, `reflect()`.
2. **Learner / runner (portable).** Runs ONE agent for N episodes against a
   target, calls `reflect()` between passes, persists accumulated lessons. No
   adversary, no scoring. This is what `train_red_on(target, episodes=N)` uses.
3. **Arena / dojo harness (dojo-only).** Wraps the runner with the adversarial
   red-vs-blue pairing, the **referee** (tiers / verdict / dwell), the grace
   window, and scripted reset.

The clean rule: **the agent decides; the referee observes and scores.** The agent
never knows it is in a game; the game never reaches into the agent's head.

## Agent interface

```python
@dataclass
class Turn:
    n: int
    observation: str     # what the agent saw — its OWN stream only
    action: Action       # tool call(s) or text it emitted
    output: str          # result of its action

@dataclass
class Trajectory:
    role: str
    turns: list[Turn]
    objective_met: bool  # the referee reads this to score; the agent never scores itself

class Agent:                         # base: LLM loop, tool dispatch, knowledge, reflection
    def __init__(self, executor, model, target, *, experience=None): ...
    def decide(self) -> Action:      # ONE turn: build own observation -> self-steer -> act
    def run(self, max_turns) -> Trajectory:   # standalone loop: decide -> execute -> repeat
    def reflect(self, outcome) -> str | None  # owns its own lessons (load/save/summarize)

class RedAgent(Agent):               # objective-seeking campaign; run() stops on objective or max_turns
    def __init__(self, ..., objective="root", attacker_executor=None, earned=False, evade=False): ...

class BlueAgent(Agent):              # monitor; run() watches for max_turns or until stopped
    def __init__(self, ..., observe=False, remediate_grace=0): ...
```

- **`decide()` is the strangle seam.** Both the standalone `run()` and the arena
  call `agent.decide()`. The arena stops hand-feeding a `state_summary`; it drives
  alternation + scoring only. The agent builds its own observation and steers
  itself inside `decide()`.
- **Red and blue have different "done."** `RedAgent.run()` is a *campaign* — it
  terminates on objective (read flag / root / exfil) or `max_turns`.
  `BlueAgent.run()` is a *monitor* — no objective; it watches for `max_turns` or
  until externally stopped. You launch red *at* something; you leave blue running
  *on* something.

## The brain split

Every brain method is rewritten to read the agent's **own** state instead of the
shared `SimulationState`. The agent becomes self-sufficient.

| Brain piece | Was reading | Reads after |
| --- | --- | --- |
| phase logic (`_update_red_phase` + guidance) | shared `red_tiers`, shared history | red's own history + own foothold flag |
| blue tool-steering (breadth, heartbeat, contain-order) | shared history, `blue_contain_turn` | blue's own tool history + own evidence |
| repeat-nudge | shared history (role-filtered) | agent's own history |
| observation builder (`_build_state_summary`) | `history[-5:]` (both roles) | agent's own turn stream only |
| cred memory (`_capture_foothold_cred`) | wrote shared state | red's own `self.foothold_cred` |
| reflection + knowledge load/save | orchestrator-driven | agent owns its lessons |

Stays in the game (referee): tier detection, `tier_scoreboard`, `verdict`, dwell,
`_resolve_outcome`, the turn loop, reset, the grace window.

Two subtle un-tanglings:

1. **The foothold event has two independent observers.** When red authenticates,
   *red's brain* captures the cred to reuse (memory) and *the referee* notes "red
   reached T1" (scoring) — same tool output, two consumers, zero coupling. After
   the split, red's phase logic stops asking the referee "am I at T1?" and tracks
   its own foothold. (This un-tangles the Phase-A phase-seam check that currently
   reads `TIER_FOOTHOLD in red_tiers`.)
2. **`observe` mode and the grace window leave the brain entirely.** Blue's brain
   always says "evidence → contain/remediate now." The *game*, in observe mode,
   suppresses the real DROP and delays the lock — it wraps the *effect* of blue's
   action, not blue's decision. A deployed blue just acts; the training toggles
   live only in the referee.

## Observation model & target-knowledge seam

A turn's observation, assembled in `decide()` — nothing shared, nothing from the
referee:

```
own recent history (my tool calls + outputs)   # my stream only
+ my self-steering (phase / tool guidance / nudge)
+ my memory (red: earned cred; blue: confirmed attackers so far)
+ my objective + how to reach the target
```

Three-tier input model (how intelligence stays portable):

1. **Agent core (transferable doctrine).** Workflow + tradecraft; technique
   templates (sqlmap/nmap/`sudo -S`/docker breakout). **No box names.**
2. **Target profile (injected data, not baked prompt).** Connection/executor, the
   objective definition, the flag/sensor locations blue watches, and an optional
   **environment-notes** slot for dojo training nudges (empty for real targets,
   strictly *technique* framing, never *answers*). Phase 1 gathers today's
   scattered facts (prompt strings, constructor args) into one `TargetProfile` the
   agent is handed.
3. **Learned lessons (`knowledge.json`).** Kept tradecraft-level by no-seeding;
   portable across targets.

Consequence applied in Phase 1: `payroll_app.php` comes **out** of red's core
prompt — doctrine becomes "find the web app and its injectable forms," discovered
live. Generic technique templates stay in core.

### Scope guard

Phase 1 only (a) routes box-facts through `TargetProfile` instead of hardcoding,
and (b) pulls box-*names* out of core doctrine. It does **not** build generic
service-discovery for arbitrary hosts, host-agnostic blue sensors, or the
authorization model — those are Phase 3. We build the socket, not the adapter.

## Migration (strangle order)

Each step keeps all 179 tests green and is its own commit (revertible).

1. Add `Agent.decide()` (builds own observation + self-steers); `Orchestrator.step()`
   calls it instead of `agent.act(state_summary)`.
2. Move cred memory + reflection/knowledge ownership into the agent; orchestrator
   stops driving them.
3. Give each agent its own history stream (stop sharing `history[-5:]`). **May
   shift behavior** — re-baseline checkpoint.
4. Add `Agent.run()` standalone loop — new, with the standalone acceptance test.
5. Extract the **referee** (scoring reads trajectories); orchestrator shrinks to
   `Arena` = pair + referee + grace + reset. **Re-baseline checkpoint.**
6. Extract the single-agent **Learner** (layer 2) from the arena's episode loop.

Steps 1–5 meet the definition of done; step 6 delivers portable per-system
learning.

## Testing

- **Ratchet:** 179 tests green at every step; a red bar stops progress.
- **Characterization tests:** before relocating a guidance method, capture its
  current output as a golden string and assert the relocated version is
  byte-identical. Moves a brain without behavior drift.
- **New tests:** `decide()` builds the expected own-observation; `Agent.run()`
  drives a full campaign against `MockExecutor` (offline, deterministic — the
  standalone acceptance test); the `Referee` scores a canned trajectory to the
  same verdict the orchestrator produces today.

### Error handling

`run()` guards: a hard `max_turns` cap (no runaway loops); objective-met detection
to terminate a red campaign cleanly; executor failures return a *partial
trajectory* rather than crashing (tool errors are already coerced). Blue's monitor
loop needs an explicit stop condition since it has no objective.

### Re-baseline checkpoints (the only cloud spend)

Offline tests cannot catch drift from the LLM seeing different context. Two steps
change what the model sees — **step 3** (own history stream) and **step 5** (full
arena-on-referee). After each, one live `--observe` batch compared against the
last good numbers: **blue 5/0, red root 4/5, foothold 5/5**. Hold → behavior
preserved; move → we know which step did it. These two batches are the real
regression gate.

## Fallback discipline

`origin/master` is the safety net (pushed at `1ba536a`). Every strangle step is
its own commit, so any regression is one `git revert` away; `git reset --hard
origin/master` is the nuclear option.

## Out of scope (deferred to later phases)

- Generic service/attack-surface discovery for arbitrary hosts (Phase 3).
- Host-agnostic blue sensors (Phase 3).
- Authorization / scope / consent model for arbitrary targets (Phase 3).
- MCP server and high-level verbs (Phase 2).
- Multi-agent delegation and real-engagement reporting (Phase 4).
- A swappable `Policy`/`Brain` composition object (YAGNI until multi-agent).
