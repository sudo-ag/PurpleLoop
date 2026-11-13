# Coverage Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A persisted, re-runnable coverage matrix (red-reaches /
blue-detects / blue-prevents, per vector) built by scanning every stored
`episode_reports/ep_*.json`, reusing the existing stateless orchestrator
checks wherever one already exists for a vector.

**Architecture:** A new `src/coverage.py` with a static vector registry
(each entry a red-reach + blue-detect classifier function over one raw
timeline entry), a per-episode classifier, a cross-episode aggregator,
and JSON+markdown writers behind a small CLI. No scoring/referee changes
— this reads already-written episode artifacts, it never touches
`red_tiers`/`blue_tier_detect`/live scoring.

**Tech Stack:** Python 3.13, `uv`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-11-12-purpleloop-coverage-matrix-design.md`
(read its "Resolved after builder check" section — it pins the exact
timeline→tool_call adapter shape and the unified "never fired" status
field, both load-bearing for Task 1).

## Global Constraints

- **No scoring/referee changes.** `src/referee.py` and
  `SimulationState`/`red_tiers`/`blue_tier_detect` in `src/orchestrator.py`
  are not modified by this plan.
- **Reuse existing checks, never duplicate their matching logic.** Every
  vector row in the design doc's table that names an existing orchestrator
  method MUST call that method, not re-derive its regex/condition
  independently. The one exception the design doc already names
  (`docker_breakout`'s red-reach rule) has no existing method to reuse —
  that one rule is new, and stays the only new *matching* logic besides
  the generic "sensor name + `assessment == BREACH`" shape.
- **Output artifacts are gitignored**, same category as
  `episodes.jsonl`/`battle_report.md`/`knowledge.json`. Add
  `coverage_matrix.json` and `coverage_matrix.md` to `.gitignore` as part
  of Task 2 (a one-line, additive change to an existing gitignore list —
  flag this to the user before committing, since touching config files
  needs their go-ahead per their own standing rule).
- **Never fabricate a ✅.** A vector with zero matching timeline entries
  across every scanned episode reports as unreached — never inferred,
  never defaulted to true.

## Review Focus

- **The timeline→tool_call adapter must be exact**, or every reused-check
  row silently reads "unreached" forever with no error (confirmed failure
  mode from the design doc's builder check — `tool_call.get("function",
  {}).get("name")` on the wrong shape returns `""`, no exception). A test
  must prove a real reused check fires correctly through the adapter
  against a realistic flattened timeline entry, not just test the adapter
  in isolation. (Task 1 tests.)
- **`dirtycow`'s red-reach reuse must resolve to the loose,
  without-baseline-exclusion behavior** by construction (a `MagicMock(spec=Agent)`
  blue agent has no `executor` attribute, so the baseline lookup inside
  `_check_red_rogue_root_creation` safely returns `None` and the function's
  own `_is_new` treats "no baseline" as permissive) — a test must prove
  this concretely (an output showing a NEW-looking rogue uid0 account
  credits "reached" even though no baseline was ever captured), not just
  assert the function was called. (Task 1 tests.)
- **A no-tier vector's `prevented` value must be `None`, never `False`.**
  `ssh_key_persistence` has no tier to "defend" — reporting `False` would
  read as "detected but not prevented," which is a false claim about a
  tier that doesn't exist. (Task 1 tests.)
- **Aggregation must be "true in ANY scanned episode," not "true in the
  LAST episode" or "true in ALL episodes.**" A vector reached in episode 1
  but not episode 2 must still aggregate to reached=true. (Task 1 tests.)
- **The three never-attempted vectors must render with their unified
  "not attempted this project" status in the markdown table**, distinct
  from an "active" vector that simply hasn't fired in the episodes
  scanned yet (same structural state — zero matches — different meaning
  to a reader). (Task 2 tests.)

---

### Task 1: Vector registry + per-episode classifier + aggregator

**Files:**
- Create: `src/coverage.py` (vector registry, timeline adapter,
  `classify_episode`, `aggregate`)
- Test: `tests/test_coverage.py` (new)

**Interfaces:**
- Produces: `_as_tool_call(entry: Dict[str, Any]) -> Dict[str, Any]` —
  returns `{"function": {"name": entry.get("name", ""), "arguments":
  entry.get("args") or {}}}`. This is the adapter the design doc's
  builder check found load-bearing.
- Produces: a module-level `VECTORS: List[Dict[str, Any]]`, one entry per
  vector named in the design doc's table, each shaped
  `{"name": str, "tier": Optional[int], "status": "active"|"not_attempted",
  "red_reach": Callable[[Dict], bool], "blue_detect": Callable[[Dict], bool]}`.
  Import `TIER_FOOTHOLD`, `TIER_EXFIL`, `TIER_ROOT` from `src.orchestrator`
  for the `tier` values; `ssh_key_persistence`'s `tier` is `None`.
  Construct one throwaway `Orchestrator(MagicMock(spec=Agent),
  MagicMock(spec=Agent))` per classification call (mirror
  `tests/test_tiers.py`'s `_orch()` helper exactly — same construction,
  same import of `Agent`/`Orchestrator`/`MagicMock`) to call the reused
  methods; do not share one instance across vectors/calls (keeps each
  call stateless and side-effect-free, consistent with how the plan's
  Review Focus item on `dirtycow` depends on a FRESH mock with no
  `executor` set each time).
  Per-vector functions, exactly as the design doc's table specifies:
  - `ssh_brute`: tier `TIER_FOOTHOLD`. `red_reach`: entry role == "red",
    call `orch._check_red_foothold(_as_tool_call(entry), entry.get("output","") or "")`.
    `blue_detect`: entry role == "blue", call
    `orch._check_blue_foothold_detect(entry.get("output","") or "")`.
  - `sqli_payroll_exfil`: tier `TIER_EXFIL`. `red_reach` reuses
    `_check_red_data_exfil`; `blue_detect` reuses `_check_blue_exfil_detect`
    (same calling shape as `ssh_brute`'s two checks).
  - `proftpd_modcopy`: tier `TIER_FOOTHOLD`. `red_reach` reuses
    `_check_red_tier1_via_webshell`. `blue_detect`: entry role == "blue"
    AND `entry.get("name") == "investigate_webshells"`, parse
    `entry.get("output")` as JSON, True iff `isinstance(data, dict) and
    data.get("assessment") == "BREACH"` (wrap the `json.loads` in
    try/except, False on any parse failure).
  - `drupal_drupalgeddon2`: tier `TIER_FOOTHOLD`. `red_reach` reuses
    `_check_red_tier1_via_drupal_rce`. `blue_detect`: **the exact same
    function object** as `proftpd_modcopy`'s `blue_detect` (one shared
    `investigate_webshells`-BREACH checker, reused by reference, not
    copy-pasted — this is the engine's own point, one sensor covering two
    vectors).
  - `ssh_key_persistence`: tier `None`. `red_reach` reuses
    `_check_red_persistence_planted`. `blue_detect`: role == "blue" AND
    `name == "investigate_persistence"`, same BREACH-parsing shape as
    `proftpd_modcopy`'s blue_detect (a sibling instance of the same
    parsing logic, parameterized by sensor name — see the generic helper
    below).
  - `docker_breakout`: tier `TIER_ROOT`. `red_reach`: role == "red" AND
    `name == "execute_command"`, command text (from `entry.get("args",
    {}).get("command", "")`) contains `"docker run"` AND (contains
    `"-v /:"` OR contains `"--privileged"`), AND
    `orch._check_red_victory(entry.get("output","") or "")` is True on
    that SAME entry. `blue_detect`: role == "blue" AND `name ==
    "investigate_docker"`, same BREACH-parsing shape.
  - `dirtycow`: tier `TIER_ROOT`. `red_reach`: role == "red" AND `name ==
    "execute_command"`, call `orch._check_red_rogue_root_creation(_as_tool_call(entry),
    entry.get("output","") or "")` — the fresh-mock-per-call construction
    above is what makes this read as the intentionally loose,
    without-baseline-exclusion check (verify this with the Review Focus
    test, don't just assert it). `blue_detect`: role == "blue" AND `name
    == "investigate_privileged_accounts"`, same BREACH-parsing shape.
  - `writable_sinatra_privesc`, `sambacry`, `phpmyadmin_preg_replace`:
    tier `None`, status `"not_attempted"`. Both `red_reach` and
    `blue_detect` are a shared function that always returns `False`
    (name it something like `_never`, one function object reused by
    reference across all three, not three separate trivial lambdas).
  - Write ONE small helper, e.g. `_blue_sensor_breach(sensor_name: str) ->
    Callable[[Dict], bool]`, that returns the "role==blue, name==
    sensor_name, parse output, assessment==BREACH" closure described
    above — `proftpd_modcopy`/`drupal_drupalgeddon2`'s shared
    `blue_detect`, `ssh_key_persistence`'s, and `docker_breakout`'s and
    `dirtycow`'s `blue_detect`s are all `_blue_sensor_breach("...")` calls
    with the right sensor name, not five hand-copies of the same loop.
- Produces: `classify_episode(ep_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]`.
  `ep_data` is one parsed `ep_NNN.json` (has `"timeline"`: list of
  `{"turn","role","kind","name","args","output"}`, and `"tiers"`: list of
  `{"tier","name","reached_turn","detect_turn","dwell","defended"}`).
  For each entry in `VECTORS`: `reached = any(v["red_reach"](e) for e in
  ep_data["timeline"])`; `detected = any(v["blue_detect"](e) for e in
  ep_data["timeline"])`. `prevented` for this episode is computed as:
  if `v["tier"]` is `None`, OR `not (reached and detected)`, OR no entry
  in `ep_data["tiers"]` has a matching `"tier"` field → `prevented =
  None` (no opportunity to judge prevention this episode — either the
  vector has no tier, it didn't both land and get seen, or this
  episode's board doesn't cover that tier). Otherwise (reached AND
  detected AND the tier entry exists) → `prevented =
  bool(tier_entry["defended"])`. This if/else, not a single boolean
  expression — getting it wrong collapses "never had the chance to be
  judged" and "had the chance and failed" into the same `False`, which
  breaks the aggregation step below. Returns
  `{vector_name: {"reached": bool, "detected": bool, "prevented":
  Optional[bool]}}` for every vector in `VECTORS`.
- Produces: `aggregate(per_episode: List[Dict[str, Dict[str, Any]]]) ->
  Dict[str, Dict[str, Any]]`. Takes a list of `classify_episode` outputs
  (one per scanned episode) and returns, per vector: `reached = any(ep[v]["reached"]
  for ep in per_episode)`; `detected = any(ep[v]["detected"] for ep in
  per_episode)`; for `prevented`, collect `judged = [ep[v]["prevented"]
  for ep in per_episode if ep[v]["prevented"] is not None]` (i.e. drop
  every episode where this vector was never judged this round) — then
  `prevented = None if not judged else (True if any(judged) else False)`.
  So: `None` only when NO scanned episode ever both reached+detected this
  vector (never had a chance); `False` when it had the chance at least
  once and was never defended; `True` when defended at least once.
- Consumes: `Orchestrator`, `Agent` from `src.orchestrator`/`src.agents`;
  `MagicMock` from `unittest.mock`; `TIER_FOOTHOLD`/`TIER_EXFIL`/`TIER_ROOT`
  from `src.orchestrator` (all existing).

- [ ] **Step 1: Write the failing tests** — in `tests/test_coverage.py`:
  (a) `_as_tool_call` wraps a flattened entry correctly (`{"name":
  "use_credential", "args": {...}}` → `{"function": {"name":
  "use_credential", "arguments": {...}}}`); (b) `ssh_brute`'s `red_reach`
  fires on a realistic flattened entry whose `output` is a successful
  `use_credential` JSON payload (reuse a real captured shape from
  `tests/test_tiers.py`'s existing fixtures where possible, e.g. the
  `use_credential` success JSON), and does NOT fire on a flattened
  `execute_command`/error-output entry; (c) `dirtycow`'s `red_reach`
  fires on a flattened entry whose output shows a rogue `uid=0(firefart)`
  line, **proving the loose without-baseline behavior specifically** (no
  baseline is ever set up anywhere in this test — the Review Focus item);
  (d) `docker_breakout`'s `red_reach` fires on a flattened
  `execute_command` entry whose `args.command` contains `docker run -v
  /:/mnt ...` and whose output contains a `FLAG{...}` marker, and does
  NOT fire on a `docker run` without the flag marker in output or without
  the mount flag; (e) `proftpd_modcopy` and `drupal_drupalgeddon2`'s
  `blue_detect` are literally the same function object
  (`is`-identity, not just equal behavior) and both fire on a flattened
  `investigate_webshells` BREACH entry; (f) the three `not_attempted`
  vectors' `red_reach`/`blue_detect` both return `False` on every input
  you can think to throw at them (a non-empty, plausible-looking entry,
  not just `{}`); (g) `classify_episode` on a small synthetic `ep_data`
  (2-3 timeline entries, a `tiers` list) returns the right
  reached/detected/prevented for at least one tiered vector and confirms
  `ssh_key_persistence` (no tier) always has `prevented is None`; (h)
  `aggregate` across two synthetic per-episode results — one where a
  vector is reached+detected+defended, one where it's never touched —
  aggregates to `reached=True, detected=True, prevented=True`; and a
  separate case where a vector is reached+detected but never defended in
  any episode aggregates to `prevented=False` (not `None`).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement** `src/coverage.py` per the Interfaces above.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/coverage.py tests/test_coverage.py && git commit -m "feat(coverage): vector registry + per-episode classifier + aggregator"`

---

### Task 2: Output writers + CLI + gitignore

**Files:**
- Modify: `src/coverage.py` (add `build_matrix`, `write_outputs`, `main`,
  `if __name__ == "__main__":`)
- Modify: `.gitignore` (add `coverage_matrix.json`, `coverage_matrix.md`
  — flag this change to the user before committing, per their standing
  rule on touching config files)
- Test: `tests/test_coverage.py` (extend)

**Interfaces:**
- Consumes: `classify_episode`, `aggregate`, `VECTORS` (Task 1).
- Produces: `build_matrix(episodes_dir: str = "episode_reports") ->
  Dict[str, Any]`. Globs `Path(episodes_dir).glob("ep_*.json")`, parses
  each with `json.loads`, runs `classify_episode` on each, feeds the list
  to `aggregate`, and returns `{"vectors": {name: {**aggregate_result,
  "status": v["status"]} for name, v, aggregate_result in ...},
  "episodes_scanned": [the filenames, sorted]}`. An `episodes_dir` with no
  matching files returns every vector's `reached`/`detected` as `False`
  and `prevented` as `None` (empty aggregate, not an error) with
  `"episodes_scanned": []`.
- Produces: `write_outputs(matrix: Dict[str, Any], json_path: str =
  "coverage_matrix.json", md_path: str = "coverage_matrix.md") -> None`.
  Writes `matrix` as pretty-printed JSON to `json_path`. Writes a
  markdown table to `md_path`, one row per vector, columns `vector | red
  reaches | blue detects | blue prevents`, using `✅`/`—` for
  `True`/`None`-or-`False` in the reach/detect columns (an
  `not_attempted` vector's reach/detect are always `False` → renders `—`
  either way, no special-casing needed there), and `✅`/`❌`/`—` for
  `prevented` (`True`/`False`/`None` respectively) — plus a trailing
  note line for every vector whose `status == "not_attempted"`, naming it
  explicitly (e.g. "`sambacry` — not attempted this project (see
  HANDOFF.md)"), matching the design doc's "annotated, not blank"
  requirement for all three.
- Produces: `main() -> None` — argparse with `--episodes-dir` (default
  `"episode_reports"`), `--out-json` (default `"coverage_matrix.json"`),
  `--out-md` (default `"coverage_matrix.md"`); calls `build_matrix` then
  `write_outputs`; prints one summary line, e.g. `"coverage: N/M vectors
  reached, N/M detected, N/M prevented (of M-with-a-tier)"` (derive the
  counts from the returned matrix; the builder picks the exact wording).
  `if __name__ == "__main__": main()` at module end, mirroring
  `src/arena.py`'s own entry-point shape.

- [ ] **Step 1: Write the failing tests** — (a) `build_matrix` against a
  temp directory holding two small synthetic `ep_*.json` files (written
  by the test itself, same shape as Task 1's `classify_episode` tests)
  returns the right aggregate `vectors` dict and the right
  `episodes_scanned` list; (b) `build_matrix` against an empty temp
  directory returns every vector `reached=False, detected=False,
  prevented=None` and `episodes_scanned=[]` — not an exception; (c)
  `write_outputs` on a small known matrix dict produces valid JSON
  (round-trips through `json.loads`) and a markdown table containing each
  vector's name and the right ✅/—/❌ symbols for a couple of known cases;
  (d) the markdown output contains a visible, named annotation for each
  of the three `not_attempted` vectors (assert each vector's name AND
  the word "not attempted" — or whatever exact phrase Step 3 lands on —
  both appear).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement** `build_matrix`, `write_outputs`, `main`.
  **Before committing, add `coverage_matrix.json` and
  `coverage_matrix.md` to `.gitignore`** (alongside the existing
  `episodes.jsonl`/`battle_report.md`/`knowledge.json` lines) and flag
  this one-line config change explicitly when reporting the task, rather
  than committing it silently.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green. Also
  manually run `uv run python -m src.coverage` once against the real
  `episode_reports/` directory and read the printed summary line plus
  the generated `coverage_matrix.md`, to confirm it reads sensibly
  against this project's real, already-recorded episodes (no live
  episode needs to run for this — see the design doc's Non-goals).

- [ ] **Step 5: Commit** — `git add src/coverage.py tests/test_coverage.py .gitignore && git commit -m "feat(coverage): build_matrix/write_outputs + CLI entry point"`
