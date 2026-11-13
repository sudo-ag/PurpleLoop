# Family 5 (Post-Exploitation): SSH-Key Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give red a real persistence technique (plant its own SSH key into
the account it controls) that survives blue's existing `remediate_account`
password-lock, with a coupled blue sensor + removal response + reset
cleanup, and fix the stale NOPASSWD-root assumption in red's existing
evasion doctrine.

**Architecture:** Follows the engine's established baseline-diff shape
(`_capture_baseline`/`_diff_baseline`, window-bound at
`mark_analysis_window()`) exactly like `investigate_webshells`. The sensor
is account-agnostic at baseline time (enumerates `/root` + every
`/home/*` directory, not a specific account), since blue doesn't know
which account red will land on. The removal response is model-driven
(blue calls it via tool-use), not a deterministic reflex — mirrors
`remediate_account`/`revoke_escalation`, not `remove_privileged_account`'s
auto-fire pattern. No new scoring tier: a `SimulationState` field outside
`TIERS` tracks the plant, parallel to how other non-tier signals
(`escalation_auto_revoked`, `remediated_user`) are tracked.

**Tech Stack:** Python 3.13, `uv`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-11-12-purpleloop-family5-ssh-persistence-design.md`
(read its "Resolved after builder check" section — it pins the two scope
decisions this plan builds from: plant→detect→remove only, no new
transport plumbing; and baseline coverage via `/home/*`+`/root`
enumeration, not `/etc/passwd`).

## Global Constraints

- **No new scoring tier.** Do not add anything to `referee.py`'s `TIERS`
  tuple. The persistence signal lives outside it.
- **No new `FORBIDDEN_KEYWORDS` exception.** `ssh-keygen`/`authorized_keys`/
  `.ssh` do not match any existing forbidden keyword; no `dojo_exploit_ok`
  gating needed anywhere in this plan.
- **No new reconnection plumbing.** Do not add pubkey/IdentityFile support
  to `ToolExecutor`'s SSH transport. This round proves plant→detect→remove;
  red does not reconnect through the planted key this round.
- **Sensor baseline enumerates home directories directly** (`/root` +
  `/home/*`), never `/etc/passwd` — this is what keeps the sensor usable
  against the real, non-dojo target.
- **`remove_persistence` must NOT blanket-refuse `root` as a target.**
  Unlike `remediate_account`/`revoke_escalation`/`remove_privileged_account`
  (which all refuse `_PROTECTED_ACCOUNTS = {"root", "vagrant"}`), stripping
  a planted key from `root`'s `authorized_keys` is this response's primary
  use case (red escalating to root is exactly when persistence matters
  most). It must still refuse the defender's own control account
  (`self.user`, i.e. `"vagrant"`) and reject option-like usernames (a
  leading `-`), same injection-safety discipline as its siblings — just not
  the `root` refusal.
- **Surgical removal only.** `remove_persistence` rewrites the target
  account's `authorized_keys` with exactly the baseline-known lines kept
  and non-baseline lines dropped — never truncates the whole file, never
  touches a different account's file.
- Don't commit autonomously beyond each task's own commit; don't push
  without being asked (user's CLAUDE.md).

## Review Focus

- **A box with no pre-existing `authorized_keys` content anywhere is a
  valid, common baseline** (the defender logs in by password, not key) —
  the baseline capture must distinguish "ran successfully, found zero
  keys" from "command failed," never collapsing both to the same `None`/
  empty result, or the sensor is blind on the common case, not just the
  edge case. (Task 1 tests.)
- **The sensor must attribute a new key to the RIGHT account** when
  multiple accounts exist, not just detect "something changed somewhere."
  (Task 1 tests.)
- **`remove_persistence` on `root` must not refuse the way its siblings
  do** — a test must drive this through the real method, not assume the
  Global Constraint holds by inspection. (Task 2 tests.)
- **`remove_persistence` must never delete a legitimate pre-existing key**
  — only lines absent from the baseline get dropped. (Task 2 tests.)
- **The new red-reach check must not fire on a failed/permission-denied
  key-append attempt** — mirrors every prior family's honest-scoring
  discipline; credit only on confirmed evidence the append landed. (Task 3
  tests.)

---

### Task 1: Blue sensor — `investigate_persistence`

**Files:**
- Modify: `src/executor.py` (new `_list_authorized_keys()` baseline
  reader, new `_authorized_keys_baseline` capture in
  `mark_analysis_window()`, new `investigate_persistence()` sensor method)
- Test: `tests/test_persistence_sensor.py` (new, mirrors
  `tests/test_webshell_sensor.py`'s fixture shape exactly)

**Interfaces:**
- Produces: `_list_authorized_keys(self) -> Optional[set]` — runs one
  `execute()` call that, for `/root` and every `/home/*` directory, reads
  `<dir>/.ssh/authorized_keys` if it exists and emits one line per key as
  `"<account>:<key-line>"` (account = the directory's basename), then
  prints a trailing sentinel marker (e.g. `PL_OK`) so the caller can tell
  "ran, found nothing" apart from "command failed to run at all." Returns
  `None` if the sentinel is missing from the output (command failed);
  returns the (possibly empty) set of `"<account>:<key-line>"` strings
  otherwise — an empty set is a valid, common baseline (see Review Focus).
  Use `sudo` (home dirs/`.ssh` are typically `700`, unreadable without it).
- Modifies: `mark_analysis_window()` — adds
  `self._authorized_keys_baseline = self._capture_baseline(self._list_authorized_keys)`,
  same line shape as the existing webroot/proc/ports baselines (not gated
  on `dojo_exploit_ok` — see Global Constraints).
- Produces: `investigate_persistence(self) -> Dict[str, Any]` — same
  shape as `investigate_webshells`: live-reads via
  `self._list_authorized_keys()`, diffs against
  `self._authorized_keys_baseline` via `self._diff_baseline(...)`. Returns
  `{"tool": "investigate_persistence", "new_keys": [...],
  "flag_access_detected": bool, "assessment": "CLEAN"|"BREACH",
  "baseline_unavailable": bool (only present if true)}`. `new_keys` is the
  list of `"<account>:<key-line>"` strings the diff reports as new (same
  shape the baseline set uses) — `remove_persistence` (Task 2) does not
  consume this directly (it re-derives per-account from the same stored
  baseline), but the episode report surfaces it for the live-validation
  write-up.
- Consumes: `self._diff_baseline`, `self._capture_baseline` (existing).

- [ ] **Step 1: Write the failing tests** — in `tests/test_persistence_sensor.py`,
  following `test_webshell_sensor.py`'s `_ex_returning`-style fixture
  pattern (a fake `execute()` keyed on command substrings): (a) baseline
  captures zero keys (empty authorized_keys everywhere, sentinel present)
  → `investigate_persistence()` reports CLEAN, `new_keys == []`, NOT
  `baseline_unavailable` (this is the Review Focus case — empty is valid);
  (b) a new line appears under one account's `authorized_keys` after the
  baseline → BREACH, `new_keys == ["<that account>:<that line>"]`; (c) a
  pre-existing key present at baseline time, unchanged, never flags as new
  across repeated calls; (d) two different accounts each get a baseline
  key, only one gets a NEW key later → `new_keys` names only the right
  account's line, not the other account's untouched one; (e) the sentinel
  is missing from `execute()`'s output (simulating a failed read) →
  `_list_authorized_keys()` returns `None`,
  `investigate_persistence()` reports `baseline_unavailable: True`.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement** `_list_authorized_keys`, the
  `mark_analysis_window()` addition, and `investigate_persistence` in
  `src/executor.py`, near the existing webroot/proc baseline methods.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_persistence_sensor.py && git commit -m "feat(blue): investigate_persistence sensor (SSH-key-plant detection, window-bound)"`

---

### Task 2: Blue response — `remove_persistence` + wiring + reset cleanup

**Files:**
- Modify: `src/executor.py` (new `remove_persistence(user)` method)
- Modify: `src/agents.py` (schema entry, dispatch branch,
  `BLUE_TOOL_PRIORITY` entry for `investigate_persistence`)
- Modify: `src/arena.py` (`scripted_reset` — persistence cleanup)
- Test: `tests/test_executor.py` (extend, for `remove_persistence`'s
  executor-level behavior), `tests/test_remediation.py` (extend, for the
  dispatch-wiring test — `remediate_account`'s own wiring test lives at
  roughly lines 136-141 there, mocking the executor and asserting the
  tool-call dict routes to the right method call; add
  `investigate_persistence`'s and `remove_persistence`'s sibling tests in
  the same style, same file).

**Interfaces:**
- Consumes: `self._authorized_keys_baseline` (Task 1), `self._diff_baseline`,
  `_PROTECTED_ACCOUNTS` (existing, but NOT applied to `root` here — see
  Global Constraints).
- Produces: `remove_persistence(self, user: str) -> Dict[str, Any]` on
  `ToolExecutor`. Validates `user`: non-empty, alnum/`_`/`-` only, not
  `self.user`, does not start with `-` → else `{"tool":
  "remove_persistence", "target_user": user, "removed": False,
  "assessment": "REFUSED"|"INFO", "summary": "..."}` (mirror
  `remove_privileged_account`'s exact refusal-shape, minus the `root`
  check). Resolves home dir: `"/root"` if `user == "root"` else
  `f"/home/{user}"`. Reads the account's current
  `authorized_keys` lines live. If `self._authorized_keys_baseline` is
  `None` (no trustworthy baseline), refuse rather than risk deleting a
  legitimate key — return `{"removed": False, "assessment": "INFO",
  "summary": "no baseline available; refusing to modify <user>'s keys"}`.
  Otherwise, keep only lines where `f"{user}:{line}"` is present in the
  baseline set, rewrite the file with exactly those lines (via `sudo` +
  a single `execute()` call — e.g. write the kept content to a temp file
  then `sudo cp` into place, or pipe through `sudo tee`; the implementer
  picks the exact command, matching this codebase's existing style for
  writing a file over `execute()`). Report `{"removed": True,
  "assessment": "REMOVED", "summary": "stripped N non-baseline key(s)
  from <user>'s authorized_keys"}` if any lines were dropped, else
  `{"removed": False, "assessment": "CLEAN", "summary": "no non-baseline
  keys found for <user>"}`.
- Modifies: `BLUE_TOOL_PRIORITY` in `src/agents.py` — add
  `"investigate_persistence"` (placement: after `"investigate_cron"`,
  same grouping as the other breadth sensors).
  Adds a new schema entry (mirror `investigate_webshells`'s
  parameter-less shape) and dispatch branch for `investigate_persistence`.
  Adds a new schema entry + dispatch branch for `remove_persistence`,
  mirroring `remediate_account`'s exact shape (one required `user: string`
  parameter; dispatch pulls `tool_call['function']['arguments'].get('user',
  "")`, calls `self.executor.remove_persistence(user)`, same
  try/except-to-error-json wrapper). Live in both normal and `--observe`
  mode, same as `remediate_account`/`revoke_escalation` (observe only
  holds the *network* block, not on-host responses).
- Modifies: `scripted_reset` in `src/arena.py` — adds a persistence
  cleanup block using the SAME "capture-once baseline file, restore if
  drifted" pattern already established there for `/etc/passwd`
  (`/etc/passwd.purpleloop-baseline`): for each of `/root/.ssh/authorized_keys`
  and every `/home/*/.ssh/authorized_keys` that exists, capture a
  `<file>.purpleloop-baseline` copy once (if none exists yet) and restore
  from it if the live file differs. Append one `actions.append(...)` entry
  describing this, same style as the existing entries. Remove the
  "Persistence vectors ... cleaned in a later increment" sentence from
  the function's docstring (it's no longer true).

- [ ] **Step 1: Write the failing tests** — `remove_persistence`:
  (a) refuses `self.user` (the defender's own account); (b) refuses an
  option-like username (`"-foo"`); (c) **does NOT refuse `"root"`** (the
  Review Focus case — drive this through the real method, confirm it
  proceeds rather than hitting the refusal branch); (d) with a baseline
  containing `{"lando_calrissian:ssh-ed25519 AAAA... legit"}` and a live
  read showing that line plus `"lando_calrissian:ssh-ed25519 BBBB...
  planted"`, removal keeps the legit line and drops the planted one
  (verify via the fake `execute()`'s captured write command/content, not
  just the returned summary); (e) with no baseline (`None`), refuses
  rather than modifying anything. For the schema/dispatch wiring: (f) the
  tool-use loop recognizes `investigate_persistence` and
  `remove_persistence` by name and routes to the right executor method
  (mirror however the existing `remediate_account` wiring test does this).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement** all of the above.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/executor.py src/agents.py src/arena.py tests/test_executor.py <schema/dispatch test file> && git commit -m "feat(blue): remove_persistence response + wiring + scripted_reset cleanup"`

---

### Task 3: Red doctrine — SSH-key persistence + honest signal (no tier)

**Files:**
- Modify: `src/agents.py` (new doctrine block, placement: append to
  `RED_EARNED_ADDENDUM` after the existing ProFTPD/Drupal sections, same
  placement precedent)
- Modify: `src/orchestrator.py` (new `_check_red_persistence_planted`
  check; new `SimulationState` field; wired into the turn loop)
- Test: `tests/test_tiers.py` (extend — despite the filename, this file
  already hosts every red-reach honest-scoring check, tier or not; follow
  its existing structure)

**Interfaces:**
- Produces: `_check_red_persistence_planted(self, tool_call: Dict[str, Any], output: str) -> bool`
  in `src/orchestrator.py`. Fires only when: `tool_call.function.name` is
  whichever tool red used to append the key (`execute_command` if red
  already has a target shell; the doctrine, per Task 3's design, should
  tell red to do the append via a single `execute_command` once it has a
  foothold — the builder confirms this matches how every other
  foothold-gated red action in this codebase is dispatched), output is
  not an error (`self._is_error_output`), and the output contains
  confirmable evidence the append landed — e.g. a doctrine-specified
  readback step (`grep` the just-appended key out of
  `authorized_keys` and echo it back) whose output is present verbatim.
  Never credits on "ran ssh-keygen" or "command exited 0" alone — mirrors
  `_check_red_rogue_root_creation`'s verify-don't-assume discipline.
- Produces: new `SimulationState` field in `src/orchestrator.py`, e.g.
  `red_persistence_planted_turn: Optional[int] = None` (placed alongside
  the other `Optional[int]` turn-markers like `blue_remediate_turn`) — set
  to `self.state.turn` the first time the check fires, guarded the same
  `X not in <state>`/`<state> is None` way every other first-time-only
  signal in this file already is. This field is NOT in `TIERS` and does
  NOT touch `red_tiers`/`blue_tier_detect` — per Global Constraints, no
  new tier.
- Consumes: `self._is_error_output` (existing).

- [ ] **Step 1: Write the failing tests** — in `tests/test_tiers.py`: (a)
  a realistic successful append (an `execute_command` whose output
  includes a readback line confirming the new key is present) →
  `_check_red_persistence_planted` returns `True` and, driven through the
  real `step()` loop, sets `red_persistence_planted_turn`; (b) a
  permission-denied / failed append attempt → returns `False`, field
  stays `None`; (c) calling it twice in two different turns only sets the
  field on the first (same double-credit-guard discipline as every tiered
  check, even though this isn't a tier); (d) error output → `False`.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Add the check function to
  `src/orchestrator.py` near the existing red-reach checks; add the field
  to `SimulationState`; wire it into the turn loop. Add the persistence
  doctrine block to `RED_EARNED_ADDENDUM` in `src/agents.py`: generate an
  `ed25519` keypair on Kali with no passphrase
  (`ssh-keygen -t ed25519 -f /tmp/pl_key -N ""`), append the public key to
  the controlled account's `~/.ssh/authorized_keys` (creating `~/.ssh`
  with `700` and the file with `600` if needed, **append only, never
  overwrite** — state this explicitly in the doctrine text, it is a named
  Anti-goal), then read the file back and confirm the new line is present
  as the verification step the check function keys on. Tell red this is
  tradecraft worth using especially once it suspects blue may remediate
  it, but never assert blue will or that persistence is "required" —
  red's own judgment, same as every prior tradecraft block.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/agents.py src/orchestrator.py tests/test_tiers.py && git commit -m "feat(red): SSH-key persistence doctrine + honest plant signal (no new tier)"`

---

### Task 4: Fix stale `RED_EVASION_ADDENDUM` root assumption

**Files:**
- Modify: `src/agents.py` (`RED_EVASION_ADDENDUM`)
- Test: `tests/test_tiers.py` or wherever doctrine-text assertions already
  live for this project (extend; follow the existing
  `test_doctrine_does_not_hardcode_targeturi_path`-style pattern of
  asserting against the real constant's text)

**Interfaces:**
- Modifies: `RED_EVASION_ADDENDUM` in `src/agents.py`. Replace "You have
  root (NOPASSWD sudo)" with text that conditions the log-cleanup
  technique on red having actually confirmed root (via its own `id`/
  `whoami` output showing `uid=0`), not assumed from the start. Scope
  stays root-only (per the design doc's "Resolved after builder check" —
  no foothold-level variant).

- [ ] **Step 1: Write the failing test** — assert the literal string
  `"You have root (NOPASSWD sudo)"` is NOT present in
  `RED_EVASION_ADDENDUM`, and that the text instead references confirming
  root via `id`/`whoami` before attempting the cleanup (a substring check
  on whatever exact phrasing Step 3 lands on — the implementer writes the
  real text first, then pins the test to it, same order as every other
  doctrine-wording test in this suite).

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement** the text fix.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/agents.py tests/test_tiers.py && git commit -m "fix(red): evasion doctrine no longer assumes handed NOPASSWD root"`

---

### Task 5: LIVE validation (one episode, read-only observation)

**Files:** none (operational). Produces `episode_reports/ep_NNN.*` and a
`HANDOFF.md` note.

- [ ] **Step 1:** Run one live earned+observe episode:
  `uv run python -m src.arena --episodes 1 --host 192.168.64.12 --jump-host
  192.168.64.11 --earned --observe --model gemma4:31b-cloud --max-turns 20`.
- [ ] **Step 2:** Confirm from the episode report: did red attempt the
  persistence plant this episode (opportunistic — may not, same variance
  every prior family saw)? If it did: did `_check_red_persistence_planted`
  fire honestly, and did `investigate_persistence` catch it if/when blue
  rotated to that sensor? If blue called `remove_persistence`, confirm
  from the report it targeted the right account and didn't refuse `root`
  if that's who red planted on.
- [ ] **Step 3:** Record the outcome honestly either way in `HANDOFF.md` —
  same framing as every prior family's live-run note (a real mechanism
  that red didn't take this episode is valid and informative, not a
  failure).
