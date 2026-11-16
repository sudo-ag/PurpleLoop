# Vector-Specific Remediation (paintball arms race) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give blue a general, finding-driven tool to *close the privilege-escalation vector red is using* (not ban the attacker), so a stopped red stays in the game and must pivot to a different vector — the paintball loop.

**Architecture:** A new `ToolExecutor.remediate_finding(finding)` applies a category-appropriate, reversible fix (`chmod go-w` / `chmod u-s`) to an escalation-sensor finding's path, recording the path's original mode on the executor so `scripted_reset` can re-vulnerabilise it next episode. Blue is wired to call it (reactive close); red gets a pivot doctrine line; the referee credits a "vector stopped." This is **Phase A** of the design (foundation + a live gate). Phase B (multi-round within-episode robustness) is gated on Phase A's live result and is scoped but not built here.

**Tech Stack:** Python 3.13, pytest, uv. Touches `src/executor.py`, `src/agents.py`, `src/orchestrator.py` (SimulationState), `src/arena.py` (scripted_reset), `src/referee.py`.

**Spec:** `docs/superpowers/specs/2026-11-15-purpleloop-vector-remediation-design.md`

## Global Constraints

- Test command: `uv run python -m pytest` (the `-m` form puts cwd on `sys.path`).
- **v1 scope = privilege-escalation stage.** `remediate_finding` handles `writable` (→ `chmod go-w <path>`) and `suid` (→ `chmod u-s <path>`); `sudo`/group paths stay with the existing `revoke_escalation`; `scheduled`/`capability` return `status: "unsupported"` (no action). Foothold-closing is out of scope.
- **No ban.** `remediate_finding` never blocks an IP or locks an account.
- **Reversible + reset-reverted.** Every fix records the path's pre-change octal mode on `blue_ex`; `scripted_reset` restores those modes and clears the log, so the box returns to its vulnerable baseline each episode.
- **Fail-safe + guardrail-clean.** A fix that errors or can't be verified returns `status: "error"`, never a false `"closed"`. Every command is a benign `chmod`/`stat` that must pass `FORBIDDEN_KEYWORDS` without `dojo_exploit_ok`.
- **Refuse defender/host paths.** Reject `/`, `/etc`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, and anything owned by the control account or under its home — blue must not harden itself or brick the host.
- **General, not box-specific.** The fix is chosen by finding `category` + `item` path only; no account/host/version literal appears in code.
- **No new scoring tier**; `vector_stops` is prevention-class telemetry, not a new tier.

## Review Focus

- **A `writable` path red's own account *owns*** — `chmod go-w` leaves owner write intact, so the vector is NOT closed. The fix must verify the finding's principal can no longer write (re-stat; if still writable by the flagged principal, `chown root` then re-check, else `status: "error"` — never a false `"closed"`). → Task 1.
- **A protected path in a finding** (`/etc/cron.d/x`, a control-account-owned file) → `status: "refused"`, no chmod runs. → Task 1.
- **`remediate_finding` with a malformed/partial finding** (missing `item`/`category`, wrong types) → an error payload, never a crash. → Task 2.
- **Reset when blue hardened nothing** (empty log) and **reset run twice** → no error, idempotent, box unchanged the second time. → Task 3.
- **A close that lands after red already used the vector** → recorded but NOT credited as a pre-objective stop (no fabricated prevention). → Task 4.

---

### Task 1: `remediate_finding` vector-closer (executor)

**Files:**
- Modify: `src/executor.py` (add method + a `_is_protected_path` helper + `self.hardenings` list in `__init__`)
- Test: `tests/test_remediate_finding.py` (new)

**Interfaces:**
- Produces: `ToolExecutor.remediate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]` returning `{"tool": "remediate_finding", "status": "closed"|"unsupported"|"refused"|"error", "category": str, "target": str, "fix": str, "reversible": True}`.
- Produces: `self.hardenings: List[Dict[str, str]]` — appended `{"path": item, "original_mode": "<octal>"}` on each successful close (consumed by Task 3).
- Consumes: existing `self.execute`, `self.user`, `_find_user`-style helpers.

- [ ] **Step 1: Write the failing tests** (`tests/test_remediate_finding.py`), mocking `executor.execute` to return staged `stat`/`chmod` output:
  - `test_writable_finding_is_chmod_go_w` — finding `{"category":"writable","item":"/opt/sinatra"}`; assert the issued command contains `chmod go-w /opt/sinatra`, `status == "closed"`, and `self.hardenings` records the pre-change mode.
  - `test_suid_finding_strips_suid_bit` — `{"category":"suid","item":"/usr/bin/x"}`; command contains `chmod u-s /usr/bin/x`, `status == "closed"`.
  - `test_owner_writable_requires_chown` — a writable path still writable by the flagged principal after `go-w` (staged re-stat) → the fix also issues `chown root`; if still writable, `status == "error"`, not `"closed"`.
  - `test_protected_path_is_refused` — `{"category":"writable","item":"/etc/cron.d/x"}` → `status == "refused"`, no `chmod` issued.
  - `test_unsupported_category` — `{"category":"scheduled","item":"/x"}` → `status == "unsupported"`.
  - `test_failed_chmod_is_error_not_closed` — staged chmod failure → `status == "error"`, nothing appended to `hardenings`.
  - `test_idempotent_reclose` — a path already non-writable → `status == "closed"` (no-op), no duplicate hardenings entry.
- [ ] **Step 2: Run to verify they fail** — `uv run python -m pytest tests/test_remediate_finding.py -v` → FAIL (method undefined).
- [ ] **Step 3: Implement `remediate_finding` + `_is_protected_path(path) -> bool`.** Stat the path for its original mode first; refuse protected paths; map category→fix; apply; re-stat to verify the flagged principal lost access (writable: not group/other-writable and not owner-writable by a non-root owner — `chown root` if needed); record `{path, original_mode}` on success. Init `self.hardenings = []` in `__init__`.
- [ ] **Step 4: Run to verify they pass.**
- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_remediate_finding.py && git commit`.

### Task 2: Tool schema + dispatch (agents)

**Files:**
- Modify: `src/agents.py` (tool definition in blue's tool list; dispatch branch)
- Test: `tests/test_remediate_finding_dispatch.py` (new)

**Interfaces:**
- Consumes: `ToolExecutor.remediate_finding` (Task 1).
- Produces: a `remediate_finding` entry in blue's tools and a dispatch branch returning its JSON; malformed args return an error payload (never raise).

- [ ] **Step 1: Write failing tests:**
  - `test_dispatch_calls_executor_with_finding` — a well-formed `remediate_finding` tool call reaches `executor.remediate_finding` with the finding dict and returns its payload.
  - `test_malformed_args_return_error_payload` — missing `finding`/wrong type → `{"tool":"remediate_finding","status":"error",...}`, no exception.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Add the tool schema** (description: "Close the specific privilege-escalation hole a finding reports — make a world-writable path non-writable or strip an unexpected SUID bit. Reversible, does NOT ban the attacker; the attacker stays connected and must find another path. Takes a `finding` from investigate_escalation_paths.") **and the dispatch branch** mirroring the other response tools' error-guarding.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit.**

### Task 3: Reset reverts hardening (arena)

**Files:**
- Modify: `src/arena.py` (`scripted_reset`)
- Test: `tests/test_reset_reverts_hardening.py` (new)

**Interfaces:**
- Consumes: `blue_ex.hardenings` (Task 1).
- Produces: `scripted_reset` restores each `{path, original_mode}` via `chmod <mode> <path>` and clears `blue_ex.hardenings`.

- [ ] **Step 1: Write failing tests** (mock `blue_ex.execute`, seed `blue_ex.hardenings`):
  - `test_reset_restores_recorded_modes` — a seeded hardening → reset issues `chmod <original_mode> <path>` and empties `hardenings`.
  - `test_reset_with_no_hardenings_is_noop` — empty log → no chmod-restore issued, no error.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the restore loop in `scripted_reset` (after the existing baseline restores), then `blue_ex.hardenings.clear()`.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit.**

### Task 4: "Vector stopped" scoring (state + referee)

**Files:**
- Modify: `src/orchestrator.py` (`SimulationState`: add `vector_stops: List[Dict]`; record on a successful `remediate_finding` close with the current turn), `src/referee.py` (scoreboard line)
- Test: `tests/test_vector_stop_scoring.py` (new)

**Interfaces:**
- Consumes: `remediate_finding` status + dispatch (Tasks 1–2), `state.current_turn`-equivalent.
- Produces: `state.vector_stops` entries `{"category","item","turn"}`; `Referee` exposes the count and names stopped vectors in `verdict()`/scoreboard.

- [ ] **Step 1: Write failing tests:**
  - `test_close_records_vector_stop` — a `"closed"` dispatch appends `{category,item,turn}` to `state.vector_stops`.
  - `test_refused_or_error_records_no_stop` — `"refused"`/`"error"`/`"unsupported"` add nothing.
  - `test_verdict_names_stopped_vectors` — with a stop, `Referee.verdict()` (or the scoreboard) reports the stopped vector; with none, unchanged.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** the state field + recording in the dispatch path, and the referee scoreboard line (prevention-class, no new tier).
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit.**

### Task 5: Doctrine — blue reactive close + red pivot

**Files:**
- Modify: `src/agents.py` (blue triage/remediation guidance; red earned addendum)
- Test: `tests/test_vector_remediation_doctrine.py` (new)

**Interfaces:**
- Consumes: nothing (prompt text).
- Produces: blue prompt instructs closing a closeable finding on an active attacker rather than only watching/banning; red prompt instructs pivoting off a vector that newly fails.

- [ ] **Step 1: Write failing tests** (reuse the `_agent`/`_prompt_sent` pattern from `tests/test_reflection_voice.py`):
  - `test_blue_prompt_has_reactive_close_directive` — blue's system prompt mentions closing the finding / `remediate_finding` as the response to an identified privesc vector.
  - `test_red_prompt_has_pivot_directive` — red's earned prompt tells it a path that worked before but now fails means the defender hardened it → switch vectors, don't retry.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Add the two doctrine lines** to the respective prompt constants.
- [ ] **Step 4: Run to verify pass.**
- [ ] **Step 5: Commit.**

### Task 6: Phase-A live gate (observation — no code)

**Files:** none (note outcome in `HANDOFF.md`).

- [ ] **Step 1** — When `.11`/`.12` are up, run earned (non-observe, so blue acts) episodes and confirm `remediate_finding` runs under blue's privileges and returns a real `"closed"` on a genuine box vector (e.g. the writable-Sinatra path), with the box returning to vulnerable after reset.
- [ ] **Step 2** — Confirm the key behaviour: after blue closes red's privesc vector, **red's next move on it fails and red pivots to a different vector** at least once. Honest "red thrashed instead of pivoting" is a valid finding that gates Phase B.
- [ ] **Step 3** — Record the outcome in `HANDOFF.md`. PASS → Phase B; FAIL → fix red's pivot (feedback clarity / doctrine) before building Phase B.

---

## Phase B (gated on Task 6 — scoped, not built here)

Multi-round within-episode robustness: confirm/raise reliability of several close→pivot rounds per episode; "red exhausted all closeable vectors before the objective" = blue prevention win; scoreboard reflects multiple stops. Plan Phase B as its own tasks only after the Phase-A gate passes.

## Self-Review

- **Spec coverage:** `remediate_finding` general closer (T1), blue wiring (T2), reset re-vulnerabilise (T3, refined to per-close mode capture rather than the spec's path-snapshot — box-agnostic, avoids baseline-baking), scoring stop (T4), red/blue doctrine (T5), live gate + pivot proof (T6). Phase B explicitly deferred per the spec's two-phase build. Non-goals (no ban, no foothold-closing, no persisted hardening) honored by T1/T3 constraints.
- **Type consistency:** `remediate_finding(finding: Dict) -> Dict` shape fixed in T1, consumed unchanged in T2/T4; `blue_ex.hardenings` entry shape `{path, original_mode}` defined T1, consumed T3; `vector_stops` entry `{category,item,turn}` defined T4.
- **Review Focus:** owner-writable-not-closed (T1), protected-path refusal (T1), malformed finding (T2), empty/double reset (T3), late close not credited (T4) — each pinned to a task's tests.
- **Proportion:** plan is signatures + test names + the few pinned commands (`chmod go-w`, `chmod u-s`); no transcribed bodies.
