# PurpleLoop — Coverage Matrix (Design)

Date: 2026-11-12
Status: design, pending approval

---

## Intent / why

The breadth-families design
(`docs/superpowers/specs/2026-11-05-purpleloop-linux-breadth-families-design.md`)
names a persisted **coverage matrix** — per vector, red-reaches /
blue-detects / blue-prevents — as "also the capstone artifact" and the
measurable definition of "the Linux box is covered." Five families have
now been built (privesc, network-RCE, web-app, the generic engine, and
post-ex/SSH-persistence); nothing yet aggregates what's actually been
demonstrated across them into that artifact. This round builds it.

**Why now, concretely:** every episode already writes a timeline
(`(turn, role, name, args, output)` per tool call — confirmed by reading
a real `ep_001.json`) and a per-tier scoreboard (`reached_turn`,
`detect_turn`, `dwell`, `defended`). The breadth design's own framing —
"no deep referee surgery; the referee stays per-tier, the classifier is a
layer on top" — holds exactly: this is a reporting/aggregation layer over
data that already exists, not new red or blue capability. Smaller in
scope than any of the last two rounds.

## Goals

- A persisted coverage matrix (JSON + rendered markdown table), one row
  per named vector, three columns: red-reaches / blue-detects /
  blue-prevents, aggregated across every stored episode.
- A `(tool, name, args, output) → vector` classifier that scans
  `episode_reports/ep_*.json` timelines — the mechanism the breadth
  design names.
- **Reuse, not reimplementation, wherever a vector's red-reach or
  blue-detect signal already has a corresponding stateless orchestrator
  check** (most of them do — see "What's decided"). Avoids a second copy
  of the same matching logic drifting from the first.
- Honest about what's never fired: a vector nobody has reached/detected
  in any stored episode shows as unreached, not fabricated.

## Non-goals

- No scoring/referee changes. `red_tiers`/`blue_tier_detect`/`TIERS` are
  untouched; the matrix reads episode artifacts, it doesn't feed back
  into live scoring.
- No new red or blue capability. Every vector classified here already
  has a red doctrine/check and (where relevant) a blue sensor from a
  prior round.
- No live validation this round. The classifier runs over **already
  recorded** `ep_NNN.json` files; no new episode needs to run against
  `.11`/`.12` to prove the matrix works (though re-running it after any
  future episode is exactly the point of a persisted, re-runnable
  artifact).
- No per-vector "focus scenario" surface-restriction toggle (the breadth
  design's mechanism for forcing coverage on a vector red keeps skipping)
  — named there as later harness work, not this round.

## Anti-goals (would make this a failure even if it "works")

- A classifier that duplicates an existing check's matching logic instead
  of calling it — two copies of "what counts as a Drupal RCE" that can
  silently drift apart is exactly the kind of mistake this design avoids
  on purpose.
- Fabricating a ✅ for a vector that's never actually fired in any stored
  episode (writable-`/opt/sinatra`, SambaCry — both explored, neither
  built/attempted this project). The matrix must show these honestly as
  unreached, not leave them out and not fake a result.
- A one-shot script that has to be hand-run and manually pasted somewhere
  — it's a **persisted, re-runnable artifact**, same category as
  `episodes.jsonl`/`battle_report.md`.

## Constraints

- Input is `episode_reports/ep_*.json` on disk — the existing artifact
  `arena.build_replay` already writes. No new episode fields needed.
- Output is gitignored (operational artifact, same category as
  `episodes.jsonl`, `battle_report.md`, `knowledge.json`), not committed
  source.
- Vector list is the closed set already enumerated by the breadth design
  plus what this project has actually built/attempted since: `ssh_brute`,
  `sqli_payroll_exfil`, `proftpd_modcopy`, `drupal_drupalgeddon2`,
  `docker_breakout`, `dirtycow`, `ssh_key_persistence` (built this
  project), `writable_sinatra_privesc` (recon'd, never built),
  `sambacry` (explored this session, dead end — no writable share
  precondition), `phpmyadmin_preg_replace` (explored this session,
  dropped — credential genuinely undiscoverable without seeding, per the
  standing no-seeding rule). The last three are included specifically so
  the matrix shows them honestly as unreached/out-of-scope rather than
  omitting them.

## What's decided (the how, as decided)

**Classifier module:** new `src/coverage.py`.

**Per-vector rule, and which already-existing check it reuses (by
constructing one throwaway `Orchestrator(MagicMock(), MagicMock())`
instance per the existing test-suite precedent — e.g.
`tests/test_tiers.py`'s `_orch()` helper — purely to call these
already-stateless pure methods against stored timeline entries, no new
matching logic written for these):**

| Vector | Tier | Red-reach rule | Blue-detect rule |
|---|---|---|---|
| `ssh_brute` | T1 | reuse `_check_red_foothold(tool_call, output)` | reuse `_check_blue_foothold_detect(output)` |
| `sqli_payroll_exfil` | T2 | reuse `_check_red_data_exfil(tool_call, output)` | reuse `_check_blue_exfil_detect(output)` |
| `proftpd_modcopy` | T1 | reuse `_check_red_tier1_via_webshell(tool_call, output)` | blue entry named `investigate_webshells` with `assessment == "BREACH"` (new, simple — no existing per-sensor orchestrator check for this; shared with the Drupal row below) |
| `drupal_drupalgeddon2` | T1 | reuse `_check_red_tier1_via_drupal_rce(tool_call, output)` | same `investigate_webshells` BREACH rule as ProFTPD (the engine's own point — one sensor, two vectors) |
| `ssh_key_persistence` | — (no tier) | reuse `_check_red_persistence_planted(tool_call, output)` | blue entry named `investigate_persistence` with `assessment == "BREACH"` (new, simple) |
| `docker_breakout` | T3 | **new rule, not reusable** — no existing orchestrator check is docker-specific (red's root read there is credited through the generic `_check_red_victory`/flag-marker check, shared with every other root path). Rule: a `role == "red"` timeline entry whose `name == "execute_command"` command contains `"docker run"` AND (`"-v /:"` or `"--privileged"`), where `_check_red_victory(output)` on that SAME entry's output is true. | blue entry named `investigate_docker` with `flag_access_detected: true` (equivalently `assessment == "BREACH"`) |
| `dirtycow` | T3 | **new, deliberately looser rule** — `_check_red_rogue_root_creation` needs a live uid0 baseline (`self.blue_agent.executor._uid0_baseline`) that doesn't exist when replaying a stored, already-finished episode. Rule: a `role == "red"` `execute_command` entry whose output matches `_check_red_rogue_root_creation`'s own evidence regexes (`uid=0\((\w+)\)` with name != `"root"`, or the passwd-line form), without the baseline-exclusion step. Document this explicitly in the module docstring as intentionally looser than the live scoring check — acceptable for a reporting layer, not acceptable if ever repurposed for scoring. | blue entry named `investigate_privileged_accounts` with `assessment == "BREACH"` |
| `writable_sinatra_privesc` | — | no rule (never built) — always unreached | no rule — always undetected |
| `sambacry` | — | no rule (explored, dead end this session — no writable-share precondition exists on this box) — always unreached | no rule |
| `phpmyadmin_preg_replace` | — | no rule (explored, dropped — credential undiscoverable without seeding) — always unreached, row annotated "out of scope" in the rendered table, not blank | no rule |

**Per-episode "prevents" derivation (no new timing logic):** for a
vector that maps to a real tier, `prevented` in that episode = `reached
AND detected AND that episode's `tiers` block shows `defended: true` for
that tier` (the tier scoreboard already encodes the reach/detect timing
comparison — reuse its `defended` field directly rather than
re-deriving dwell timing in the classifier). A no-tier vector (SSH-key
persistence) has no `prevented` column value — report it as `—`, not
`false` (there is no tier to "defend").

**Aggregation across episodes:** a vector's final matrix cell is ✅ if
true in *any* scanned episode, else `—` (never observed) — matching the
breadth design's own example table's semantics.

**Output:** `coverage_matrix.json` (full detail: per-vector,
per-episode-scanned results) + `coverage_matrix.md` (the rendered table,
same shape as the breadth design doc's example) at the repo root,
gitignored.

**Entry point:** `uv run python -m src.coverage` (optional
`--episodes-dir` override, default `episode_reports/`) — scans every
`ep_*.json` found, writes both output files, prints a one-line summary
(vectors reached / detected / prevented out of the total).

## Resolved after builder check

A builder check verified most of this design directly against the real
code (confirmed the cited tool names/`assessment` strings are real, and
confirmed `_check_red_rogue_root_creation`'s baseline lookup resolves to
`None` for free when called through the same throwaway-`Orchestrator`
pattern this doc already specifies — a `MagicMock(spec=Agent)` has no
`executor` attribute set, so `getattr(self.blue_agent, "executor",
None)` safely returns `None`, giving the intentionally-loose
without-baseline-exclusion behavior with no extra code, not a
contradiction between "reuse" and "loosen" as it first read). Two real
gaps surfaced, both settled here rather than carried to the user — a
wrong guess on either is cheap to fix later, and neither changes what
gets built, only an internal shape and a footnote:

- **Timeline-entry → `tool_call` adapter (settled: build it).** The
  design's "just call these already-stateless pure methods against
  stored timeline entries" line undersold a required step: `ep_NNN.json`
  timeline entries are flattened (`{"turn","role","name","args","output"}`),
  but every reused orchestrator check expects
  `{"function": {"name": ..., "arguments": ...}}`. Getting this wrong
  doesn't crash — it silently makes every reused-row vector read
  "unreached" forever, since `tool_call.get("function", {}).get("name")`
  just returns `""` on the wrong shape. `src/coverage.py` must wrap each
  timeline entry as `{"function": {"name": entry["name"], "arguments":
  entry["args"]}}` before calling any reused check. Pinning this
  explicitly as part of the design, not left as a builder guess, given
  the silent-wrong-answer failure mode.
- **"Out of scope" annotation scope (settled: all three never-fired
  vectors get it, for table consistency).** `writable_sinatra_privesc`
  and `sambacry` (never built) get the same footnote treatment as
  `phpmyadmin_preg_replace` (actively dropped) — one `status` field
  distinguishing "active" vectors from "not attempted this project" is
  simpler than threading a true/false "out of scope" flag through only
  one of three otherwise-identical rows, and reads more honestly (none
  of the three have ever fired, regardless of why).

## What's left to the builder

- Exact JSON schema of `coverage_matrix.json` (the markdown table's shape
  is pinned above; the JSON's internal structure — e.g. whether it keeps
  a per-episode breakdown alongside the aggregate — is the builder's
  call).
- Whether `src/coverage.py` exposes a importable function (e.g.
  `build_matrix(episodes_dir) -> dict`) separately from its CLI entry
  point, for future reuse (e.g. a battle-replay-viewer coverage tab,
  mentioned as a deferred cosmetic idea in an earlier session) — keep
  the module importable, don't hard-code it as script-only, but building
  that viewer integration is explicitly not this round's work.
- Whether `docker_breakout`'s and `dirtycow`'s looser classifier rules
  need adjustment once run against this project's real stored episodes
  (neither vector has fired live yet per `HANDOFF.md`, so the builder may
  find zero real captured examples to validate the rule's shape against —
  acceptable; synthesize a plausible fixture the same way prior rounds
  did for untested paths, and say so in the test).
