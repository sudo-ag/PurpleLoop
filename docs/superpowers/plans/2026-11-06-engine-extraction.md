# Engine Extraction (Blue Helper + Catch-All Sensor; Red Capability Catalog) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pull the repeated baseline-capture/diff shape out of Family 1's and
Family 2's blue sensors into one shared helper (zero behavior change), add
one new catch-all blue sensor that watches for box changes no existing
sensor owns yet, and stand up a red capability-catalog data schema (scoped
to service-oriented families, back-filled from Family 2's existing doctrine,
not yet wired into live doctrine generation).

**Architecture:** Blue's three existing baselines (`_uid0_baseline`,
`_webroot_baseline`, `_proc_baseline`) each already follow the same shape —
capture a set via a shell command, validate it with a per-sensor callback,
store `None` on failure — but duplicate that shape inline in
`mark_analysis_window()` and `investigate_webshells()`. A thin helper
(`_capture_baseline`, `_diff_baseline`) replaces the duplication without
changing any sensor's validity semantics. A new `investigate_box_anomalies`
tool reuses that helper for two signals no sensor currently owns — listening
ports and the full user-account list (not just uid-0) — and, like the
existing sensors (and unlike Family 2's attribution-only FTP sensor), sets
`flag_access_detected` directly: a new listening port or new user account is
itself breach evidence, the same category as a new webroot file or new
uid-0 account, not mere attribution. Red's capability catalog is a small,
separate data module (`src/capabilities.py`) holding one entry — ProFTPD —
back-filled from the prose already in `RED_EARNED_ADDENDUM`; it does not
replace or regenerate that prose this round.

**Tech Stack:** Python 3.13, `uv`, `pytest`.

**Spec:** `docs/superpowers/specs/2026-11-06-purpleloop-engine-extraction-design.md`
(this plan's design doc, which itself implements step 3 of
`docs/superpowers/specs/2026-11-05-purpleloop-linux-breadth-families-design.md`'s
Mechanism C sequence).

## Global Constraints

- **No regression to Family 1/2.** The shared helper must not change when
  `investigate_privileged_accounts` or `investigate_webshells` consider
  their baseline trustworthy, or what they report. Every existing test in
  `tests/test_scoring_hardening.py`, `tests/test_webshell_sensor.py`,
  `tests/test_ftp_sessions.py`, `tests/test_blue_rce_wiring.py` must still
  pass unmodified after the refactor.
- **Baseline scope is per-episode only.** No cross-episode "quiet baseline"
  mechanism this round (user-confirmed override of the parent design doc's
  flagged note — see this plan's spec doc's "Decisions" section). The new
  sensor's baseline is captured in `mark_analysis_window()` exactly like the
  existing two.
- **Structural validity, not presence-of-one-entry.** Any new baseline
  validity check follows the lesson both existing sensors already paid for:
  validate that the read succeeded and is well-formed, never that one
  specific expected port/user is present (that's the exact mistake Family
  1's root-presence check and Family 2's `.html`-allowlist both made and
  had to fix).
- **Self-filtering.** The new sensor's user-list and listening-port reads
  must not flag blue's own control session or its own SSH-derived processes
  as new — mirror `self.control_source_ip` / `_SSH_NOISE` precedent.
- **Capability catalog is schema + one data row only.** Family 2's
  hand-written doctrine text in `RED_EARNED_ADDENDUM` (`src/agents.py`)
  stays untouched this round. The catalog entry is back-filled FROM that
  prose (a consistency check), not the other way around — doctrine
  generation reading from the catalog starts at Family 3.
- Don't commit autonomously beyond each task's own commit; don't push
  without being asked (user's CLAUDE.md).

## Review Focus

- **The shared helper silently changes a baseline's validity semantics**
  (e.g. normalizing uid0's sentinel check into webroot's structural check,
  or vice versa) — this was the builder-check's #1 flagged regression risk.
  The helper must accept a per-call validator callback, not impose one
  shape. (Task 1 tests: assert each of the three existing baselines' exact
  pre-refactor pass/fail behavior is unchanged.)
- **The new catch-all sensor false-positives on ordinary box churn**
  (ephemeral ports from short-lived connections, blue's own management
  login showing up as a "new" port/session) — must self-filter and use a
  stable signature, not raw ephemeral state. (Task 2 tests.)
- **The new sensor's own baseline-validity check repeats the exact
  presence-of-one-entry mistake** this plan explicitly calls out as the
  lesson already paid for twice. (Task 2 tests: a baseline missing a
  specific "expected" port/user must still validate if the read is
  otherwise well-formed.)
- **The capability catalog's ProFTPD entry drifts from the real doctrine
  text** (e.g. a different module name, different required preconditions)
  — silent data/prose divergence that would surface later as confusing
  behavior once Family 3 starts generating doctrine from the catalog.
  (Task 4 test: assert the catalog entry's module string and precondition
  fields literally appear in `RED_EARNED_ADDENDUM`'s ProFTPD section.)
- **`BLUE_TOOL_PRIORITY` rotation breaks again** — adding a new tool name to
  that list broke `tests/test_blue_breadth.py`'s LRU fixture once already in
  Family 2's Task 3; the same class of break can recur silently. (Task 3:
  update that fixture if needed, verify explicitly.)

---

### Task 1: Shared baseline capture/diff helper (refactor, zero behavior change)

**Files:**
- Modify: `src/executor.py` (`mark_analysis_window`, `investigate_privileged_accounts`, `investigate_webshells`, `_list_webroot`, `_list_proc_signatures`, `_uid0_accounts`)
- Test: `tests/test_baseline_helper.py` (new)

**Interfaces:**
- Produces: `_capture_baseline(self, fn: Callable[[], Optional[set]]) -> Optional[set]` — calls `fn()` inside the existing try/except-to-`None` discipline (the shape currently duplicated three times in `mark_analysis_window`), returns `None` on any exception or if `fn()` itself returns `None`. `_diff_baseline(self, baseline: Optional[set], live: Optional[set]) -> Tuple[bool, List[str]]` — returns `(False, [])` if either side is `None` (ok=False case), else `(True, sorted(live - baseline))`.
- Consumes: nothing new — wraps the existing `_uid0_accounts`, `_list_webroot`, `_list_proc_signatures` methods and the existing validity-check logic inline in each caller (the uid0 sentinel check, webroot's/proc's structural checks) as the callback passed to `_capture_baseline`, or as a post-capture check applied to its result — read the current code at `src/executor.py:654-671` (the three `mark_analysis_window` baseline blocks) and `src/executor.py:681-712, 744-778` (`investigate_privileged_accounts`, `investigate_webshells`) before deciding whether the validator lives inside the lambda passed to `_capture_baseline` or as a separate check after it returns — either is fine as long as each sensor's existing pass/fail behavior is provably unchanged.

- [ ] **Step 1: Write the failing tests** — for each of the three existing baselines, a test using the SAME scenario shapes already proven in `tests/test_scoring_hardening.py` / `tests/test_webshell_sensor.py` (a valid read, an invalid/empty read, a read that fails validation) and assert the refactored code produces byte-identical output dicts to what the pre-refactor code produces today. Also test `_diff_baseline` directly: both sides present → correct sorted diff; either side `None` → `(False, [])`.

- [ ] **Step 2: Run to verify fail** — `uv run python -m pytest tests/test_baseline_helper.py -v` → FAIL (helper doesn't exist yet).

- [ ] **Step 3: Implement.** Add `_capture_baseline`/`_diff_baseline` to `ToolExecutor`. Refactor the three `mark_analysis_window` baseline-capture blocks and `investigate_privileged_accounts`/`investigate_webshells`'s diff logic to call them, preserving each sensor's own validator exactly (uid0's `"root" in uid0` sentinel stays a sentinel; webroot's/proc's structural checks stay structural — do not normalize them to match each other, per this plan's Global Constraints).

- [ ] **Step 4: Run to verify pass** — new tests PASS, and run the FULL existing suite (`uv run python -m pytest -q`) to confirm zero regressions in `tests/test_scoring_hardening.py`, `tests/test_webshell_sensor.py`, `tests/test_ftp_sessions.py`, `tests/test_blue_rce_wiring.py`, `tests/test_tiers.py`.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_baseline_helper.py && git commit -m "refactor(blue): extract shared baseline capture/diff helper (no behavior change)"`

---

### Task 2: New catch-all sensor — `investigate_box_anomalies` (listening ports + user list)

**Files:**
- Modify: `src/executor.py` (`mark_analysis_window` — add two new baseline captures using Task 1's helper; new method)
- Test: `tests/test_box_anomalies_sensor.py` (new)

**Interfaces:**
- Produces: `investigate_box_anomalies(self) -> Dict[str, Any]` returning `{"tool": "investigate_box_anomalies", "new_ports": [...], "new_users": [...], "flag_access_detected": bool, "assessment": "BREACH"|"CLEAN", "baseline_unavailable"?: True, "ports_unavailable"?: True, "users_unavailable"?: True}` — mirrors `investigate_webshells`'s two-independent-signals shape from Task 1/already-existing code (one side failing must not blind the other, same as the existing webroot/proc independence). Instance attrs `self._ports_baseline: Optional[set[str]]`, `self._users_baseline: Optional[set[str]]`, both populated in `mark_analysis_window()` via Task 1's `_capture_baseline`.
- Consumes: `self._capture_baseline`, `self._diff_baseline` (Task 1), `self.execute()`, `self.control_source_ip` (existing, for self-filtering).

- [ ] **Step 1: Write the failing tests** — mirroring `tests/test_webshell_sensor.py`'s existing shape (new entry = breach, no change = clean, no baseline = clean+unavailable, one-side-failure leaves the other working), PLUS the two risks this task owns: (a) a self-filter test — blue's own management-login port/session must not appear as "new"; (b) a structural-validity test — a baseline capture that's missing one specific "expected" port or user (e.g. no port 22 in this particular read) must still be considered valid if the read is otherwise well-formed (non-empty, correctly shaped lines) — do NOT require any specific port/user to be present.

- [ ] **Step 2: Run to verify fail** — `uv run python -m pytest tests/test_box_anomalies_sensor.py -v` → FAIL.

- [ ] **Step 3: Implement.** `_list_listening_ports()` runs `ss -tln 2>/dev/null` (confirmed present and working on `.12` without sudo — `netstat` is also present as a fallback if `ss` is ever missing, but `ss` is the primary choice, hardcoded) and returns a set of normalized `proto:port` strings parsed from the `Local Address:Port` column (e.g. `tcp:21`); validity is structural (non-empty output, a header line plus at least one well-formed `LISTEN` row) — never "port 22 must be present." `_list_users()` runs `getent passwd | cut -d: -f1` (NOT `cut -d: -f1 /etc/passwd` — the literal string `/etc/passwd` is in `FORBIDDEN_KEYWORDS` and would be blocked outside dojo mode, the exact mistake Family 1's Task 2 made with an unconditional `cat /etc/passwd`; `getent passwd` reads the same account database without that literal substring, so no `dojo_exploit_ok` gating is needed and this sensor stays available in non-dojo runs too) and returns the set of usernames. Self-filter: a LISTENING port is server-side state, not a client connection, so blue's own SSH-in doesn't create a new listening port and no IP-based self-filter is needed here (unlike `_SSH_NOISE`, which filters blue's own process in a `ps` snapshot) — note this reasoning in the method's docstring so a future reader doesn't wonder why no filter was added. `investigate_box_anomalies()` calls `self._diff_baseline` for each of the two signals independently, same shape as `investigate_webshells`.

- [ ] **Step 4: Run to verify pass** — PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_box_anomalies_sensor.py && git commit -m "feat(blue): investigate_box_anomalies catch-all sensor (listening ports + user list)"`

---

### Task 3: Wire `investigate_box_anomalies` into the blue agent

**Files:**
- Modify: `src/agents.py` (blue tool schema + `process_tool_call` dispatch + `BLUE_TOOL_PRIORITY`, mirroring `investigate_webshells`'s wiring at `src/agents.py:597-609, 1005-1009, 1266+`)
- Test: extend `tests/test_blue_rce_wiring.py` or a new `tests/test_blue_anomaly_wiring.py`; extend `tests/test_blue_breadth.py`'s LRU fixture if adding this tool name breaks its rotation assertion (same class of break Family 2's Task 3 hit — check explicitly, don't assume it's fine).

**Interfaces:**
- Consumes: `investigate_box_anomalies` (Task 2).
- Produces: the tool name registered in schema/dispatch/priority list, following the exact zero-argument dispatch pattern `investigate_webshells`/`investigate_privileged_accounts` already use.

- [ ] **Step 1: Write the failing tests** — schema contains the new tool name; dispatch routes to `self.executor.investigate_box_anomalies()`; `BLUE_TOOL_PRIORITY` contains it; run `tests/test_blue_breadth.py` as-is first to see whether it breaks (it did, for an analogous change, in Family 2 Task 3) — if it does, that's this task's job to fix, not a surprise to report later.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Copy the `investigate_webshells` wiring pattern exactly (schema entry, dispatch `elif` branch with try/except → `{"status": "error", ...}`, append to `BLUE_TOOL_PRIORITY`). Fix `tests/test_blue_breadth.py`'s LRU history fixture if it breaks, the same way Family 2's Task 3 did.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/agents.py tests/test_blue_rce_wiring.py tests/test_blue_breadth.py && git commit -m "feat(blue): register investigate_box_anomalies"` (adjust file list to whatever test files you actually touched)

---

### Task 4: Red capability catalog — schema + ProFTPD entry (data only, not wired into doctrine generation)

**Files:**
- Create: `src/capabilities.py`
- Test: `tests/test_capabilities.py` (new)

**Interfaces:**
- Produces: a data structure — a `dataclass` or `TypedDict` named `ServiceCapability` with fields covering at minimum: `service_pattern` (what red's own fingerprint output should match — e.g. a string/regex for "ProFTPD"), `msf_module` (the exact module path), `preconditions` (e.g. "requires an already-held credential"), `tradecraft_notes` (free text — the non-seeding tradecraft, not an assertion the vuln exists). A module-level list `CAPABILITY_CATALOG: list[ServiceCapability]` with exactly one populated entry, back-filled from `RED_EARNED_ADDENDUM`'s ProFTPD section in `src/agents.py` (read that section first — it's the FTP block, roughly `src/agents.py:380-412` as of this plan's writing, but re-locate it by content since line numbers shift).
- Consumes: nothing — this is a new, standalone data module with no runtime wiring into `agents.py`'s doctrine generation this round (per this plan's Global Constraints).

- [ ] **Step 1: Write the failing tests** — `CAPABILITY_CATALOG` has exactly one entry; that entry's `msf_module` field equals the exact module string (`exploit/unix/ftp/proftpd_modcopy_exec`) that appears verbatim in `RED_EARNED_ADDENDUM`; a drift-detection test that reads `RED_EARNED_ADDENDUM` and asserts the catalog entry's `msf_module` string is a substring of it (this is the Review Focus item: catalog/prose must not silently diverge).

- [ ] **Step 2: Run to verify fail** → FAIL (module doesn't exist).

- [ ] **Step 3: Implement.** Define `ServiceCapability` and `CAPABILITY_CATALOG` in the new file. Populate the one ProFTPD entry by reading the actual current prose in `src/agents.py` and transcribing its real values — do not invent a precondition or module name different from what the doctrine text already says.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/capabilities.py tests/test_capabilities.py && git commit -m "feat(red): capability-catalog schema with ProFTPD entry (data only, not yet wired into doctrine generation)"`

---

### Task 5: Live smoke check of the new sensor (not a full gated episode — refactor-only + one new read-only sensor, lower risk than Families 1-2's live tasks)

**Files:** none (operational).

- [ ] **Step 1:** After all tasks are merged, run one live call of `investigate_box_anomalies` against the real target (via a short Python script through `ToolExecutor`, or one live episode) and confirm: it returns CLEAN with no `baseline_unavailable` on a quiescent box, it does not flag blue's own control session as new, and it runs within a few seconds (no hang).
- [ ] **Step 2:** Record the outcome in `HANDOFF.md` — confirmed clean baseline, any tuning needed.

---

## Notes carried from the spec

- Doctrine-generation actually reading from `CAPABILITY_CATALOG` starts at
  Family 3, when there's a second real entry to prove the generation code
  against — not this round.
- Cross-episode "quiet baseline" memory for `investigate_box_anomalies` is
  explicitly deferred (user-confirmed) — this sensor's baseline is
  per-episode only, like the two it sits alongside.
