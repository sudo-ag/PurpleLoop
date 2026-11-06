# Family 2 — Network-Service RCE (ProFTPD mod_copy) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give red a network-service RCE pivot — ProFTPD 1.3.5 `mod_copy` (CVE-2015-3306) via real Metasploit — that turns any cred red already holds into code execution through a webshell, over a channel SSH-based detection never sees. Give blue a coupled sensor (web-root/process baseline-diff) that detects it and generalizes to the family's other RCE vectors (Tomcat, Sinatra) later.

**Architecture:** Red drives real `msfconsole` on Kali via its existing `run_on_attacker` tool (no new red tool plumbing — this is doctrine, same precedent as the seeded docker command and Dirty COW PoC). The module (`exploit/unix/ftp/proftpd_modcopy_exec`) plants a PHP webshell in `/var/www/html`, then red requests the planted page to execute commands. Blue's new sensor baseline-diffs the web root's file listing and the process tree at window start, so a new file or an unexpected Apache child process is the breach signal — not the thin FTP syslog (confirmed live: it shows session open/close + source IP, not the `SITE CPFR`/`CPTO` commands, so it can't see the attack itself). Scoring adds a red-reach check for "webshell command execution achieved" (T1) alongside blue's detection credit.

**Tech Stack:** Python 3.13, `uv`, `pytest`. Target: `ProFTPD 1.3.5` on `.12:21`, `DocumentRoot /var/www/html` (world-writable, confirmed live). Attacker: `msfconsole`/`msfvenom` on Kali `.11` (confirmed present).

**Spec:** `docs/superpowers/specs/2026-11-05-purpleloop-linux-breadth-families-design.md` (Family 2 row). This plan also corrects one spec assumption, see "Decisions / corrections" below.

## Global Constraints

- No seeding: the msf module **catalog** is supplied tradecraft (same precedent as the seeded docker command), but **which service is vulnerable and which module applies stays red's discovery** — red fingerprints the FTP banner itself and selects the module; nothing auto-fires.
- Honest scoring: red's T1-via-webshell credit requires actual command-execution evidence from the planted page's response, not merely "ran msfconsole" or "the exploit reported success."
- Blue's new sensor must self-filter blue's own control session the same way the auth-log/connections sensors do (confirmed live: my own manual FTP test logged from the controller IP, exactly the false-positive risk Family 1 hit with `scripted_reset`). Window-bind every baseline the same way Family 1's sensors do — don't repeat Family 1's root-presence mistake; validate a baseline read by structure, not by the presence/absence of any single expected entry that an attack could legitimately remove.
- `run_on_attacker` rides the attacker executor's `self.timeout` (default 60s). `msfconsole` module-cache load + exploit run can exceed that. This plan raises the attacker executor's timeout for `--earned` runs where msf is in play — see Task 3.
- Reproducibility: pin the msf module's options where it allows (RHOSTS/RPORT/SITEPATH); accept residual LLM-driven non-determinism (flag it, don't fight it).
- Don't commit autonomously beyond each task's own commit; don't push (user's CLAUDE.md).

## Decisions / corrections from live verification (2026-11-06)

- **Anonymous FTP is refused** on `.12` even though the server offers it (`331` then `530`). This is **not** a crack-nothing initial-access vector — it's a **pivot**: red needs some existing cred (from SQLi, hydra, or any Family-1/4 tradecraft) to log into FTP, which then unlocks `mod_copy` regardless of whether that account has a usable shell. The spec's "second independent foothold path, kills the cracking bottleneck" framing is revised to: **"lateral pivot — turns any cred into RCE via a different, SSH-invisible channel."** User confirmed this reframing and approved proceeding.
- **Metasploit module confirmed:** `exploit/unix/ftp/proftpd_modcopy_exec`. Runs as `nobody` (unprivileged) — this is a **T1** vector, not T3.
- **FTP syslog visibility confirmed thin:** default ProFTPD logs session open/close + source IP only (no `TransferLog`/`ExtendedLog` directives set). The real signal is the attack's *effect* (new web-root file / unexpected child process), not the FTP session log. The session log is still useful as a *secondary* attribution/dwell-time signal, same two-layer precedent as Family 1's `investigate_docker` (live posture check + daemon-log backstop).

## Review Focus

- **A rogue file that happens to share a name with something legitimate** (e.g. a future app drops its own temp file in `/var/www/html`) must not false-credit a breach — the baseline-diff must be a real diff against a captured snapshot, not a hardcoded filename check. (Task 1 tests.)
- **Blue's own manual/operational commands touching the web root or process list** (if any future reset/housekeeping ever does) must not self-flag, mirroring the Family-1 `scripted_reset` lesson — bake this consideration into the sensor's design now, even though nothing currently issues such commands. (Task 1 tests + a comment noting the precedent.)
- **The FTP session log's source-IP self-filter** must exclude blue's own control session the same way SSH/connections already do — verified against the real log line shape (`proftpd[PID]: localhost (IP[IP]) - FTP session opened.`). (Task 2 tests.)
- **A webshell command that returns an error or empty page** must not credit red's T1-via-RCE signal — only a real, attributable command-output in the response counts. (Task 4 tests.)
- **`run_on_attacker`'s default 60s timeout cutting off msfconsole mid-run** — must be addressed before the live task, not discovered during it. (Task 3.)

---

### Task 1: Blue sensor — web-root + process baseline-diff (`investigate_webshells`)

**Files:**
- Modify: `src/executor.py` (`mark_analysis_window` — add baseline capture; new method)
- Test: `tests/test_webshell_sensor.py` (new)

**Interfaces:**
- Produces: `investigate_webshells(self) -> Dict[str, Any]` returning `{"tool": "investigate_webshells", "new_files": [...], "new_processes": [...], "flag_access_detected": bool, "assessment": "BREACH"|"CLEAN", "baseline_unavailable"?: True}`. Instance attrs `self._webroot_baseline: Optional[set[str]]`, `self._proc_baseline: Optional[set[str]]` (a stable process signature — command string, not pid, since pids churn), both populated in `mark_analysis_window()`. `flag_access_detected=True` iff `new_files` or `new_processes` is non-empty against a captured baseline.
- Consumes: `self.execute()` (no `dojo_exploit_ok` needed — `find`/`ls`/`ps` on `/var/www/html` and process list are not forbidden commands).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_webshell_sensor.py
def test_new_webroot_file_is_a_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()  # captures baseline: {"index.html"}, {"apache2 -k start"}
    ex._stub_webroot_files(["index.html", "shell.php"])
    r = ex.investigate_webshells()
    assert r["new_files"] == ["shell.php"]
    assert r["flag_access_detected"] is True and r["assessment"] == "BREACH"

def test_no_change_is_clean():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    r = ex.investigate_webshells()
    assert r["flag_access_detected"] is False and r["assessment"] == "CLEAN"

def test_unexpected_apache_child_is_a_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    ex.mark_analysis_window()
    ex._stub_procs(["apache2 -k start", "sh -c id"])  # webshell-spawned child
    r = ex.investigate_webshells()
    assert "sh -c id" in r["new_processes"] and r["flag_access_detected"] is True

def test_no_baseline_is_clean_not_breach():
    ex = _ex_returning(webroot_files=["index.html"], procs=["apache2 -k start"])
    # mark_analysis_window() never called -> no baseline
    r = ex.investigate_webshells()
    assert r["flag_access_detected"] is False and r.get("baseline_unavailable") is True
```

- [ ] **Step 2: Run to verify fail** — `uv run python -m pytest tests/test_webshell_sensor.py -v` → FAIL.

- [ ] **Step 3: Implement.** In `mark_analysis_window()`, after the existing `_uid0_baseline` block, add: `self._webroot_baseline = self._list_webroot()` (wrapped in try/except → `None` on failure, same discipline as the uid0 baseline) and `self._proc_baseline = self._list_proc_signatures()`. `_list_webroot()` runs `find /var/www/html -type f 2>/dev/null` (recursive — a webshell could land in a subdirectory) and returns a set of relative paths; validate the read by checking it's non-empty and contains at least one expected top-level entry's *pattern* (a file ending `.html` or a known subdir name) rather than one specific hardcoded filename — don't repeat Family 1's root-presence mistake. `_list_proc_signatures()` runs `ps -eo args --no-headers 2>/dev/null` (command strings, not pids) and returns a set, dropping noise (the SSH session's own shell/sftp process — filter by a command-string pattern, not pid, since the baseline must stay stable across reconnects). `investigate_webshells()` does `live_files = self._list_webroot(); live_procs = self._list_proc_signatures()`; if either baseline is `None`, return CLEAN + `baseline_unavailable: True`; else `new_files = sorted(live_files - self._webroot_baseline)`, `new_processes = sorted(live_procs - self._proc_baseline)`; BREACH iff either is non-empty.

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_webshell_sensor.py && git commit -m "feat(blue): investigate_webshells baseline-diff sensor (web-root + process tree)"`

---

### Task 2: Blue sensor — FTP session visibility (secondary signal)

**Files:**
- Modify: `src/executor.py` (`investigate_logs` or a sibling method — read the current `investigate_logs` signature first; add an `log_type="ftp"` branch or a new `investigate_ftp_sessions()` method, whichever fits the existing dispatch pattern better)
- Test: `tests/test_ftp_sessions.py` (new)

**Interfaces:**
- Produces: a method returning FTP session events (`source_ip`, `opened`/`closed`, timestamp) parsed from `grep -i ftp /var/log/syslog`, filtered by `self.control_source_ip` and `self._within_window()` exactly like the existing auth-log/connections parsers.
- Consumes: `self.control_source_ip` (existing), `self._within_window()` (existing), `_find_all_ip` (existing helper).

- [ ] **Step 1: Write the failing tests** — a fake `execute()` returning the REAL captured log line shape (`"Nov  6 00:48:25 ubuntu proftpd[3470]: localhost (192.168.64.1[192.168.64.1]) - FTP session opened."` — this exact format was captured live) with the source IP equal to `control_source_ip`: assert it's filtered out (not reported as an attacker session). A second line with a DIFFERENT source IP: assert it IS reported.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Parse `proftpd\[\d+\]: localhost \(([^\[]+)\[`-style lines for the source IP (mirror whatever regex style `_parse_connections`/`_parse_auth_log` already use for IP extraction — read them first). Exclude `self.control_source_ip`. This is attribution-only — it does NOT set `flag_access_detected`; Task 1's sensor is the sole breach signal for this family. Document that explicitly in the docstring.

- [ ] **Step 4: Run to verify pass** → PASS.

- [ ] **Step 5: Commit** — `git add src/executor.py tests/test_ftp_sessions.py && git commit -m "feat(blue): FTP session visibility (attribution only, self-filtered)"`

---

### Task 3: Register both sensors + raise the attacker-executor timeout for msf

**Files:**
- Modify: `src/agents.py` (blue tool schema + `process_tool_call` dispatch + `BLUE_TOOL_PRIORITY`, mirroring the `investigate_docker`/`investigate_privileged_accounts` wiring precedent)
- Modify: `src/arena.py` (the `attacker_ex = ToolExecutor(host=jump_host, ...)` construction — add a longer `timeout` when `earned` red is in play)
- Test: `tests/test_blue_rce_wiring.py` (new), extend `tests/test_arena.py` or wherever `build_agents` is tested for the timeout change

**Interfaces:**
- Consumes: `investigate_webshells` (Task 1), the FTP-visibility method (Task 2).
- Produces: both tool names in the blue schema/dispatch; `attacker_ex = ToolExecutor(host=jump_host, user=jump_user, pwd=jump_pwd, timeout=300)` (or similar — pick a value comfortably above a cold `msfconsole` module-cache load; document the choice in a comment referencing this task).

- [ ] **Step 1: Write the failing tests** — schema contains both new tool names; dispatch routes correctly; `build_agents` constructs the attacker executor with the raised timeout.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Copy the Task-1-era wiring pattern exactly. Add both to `BLUE_TOOL_PRIORITY` after `investigate_privileged_accounts`. Raise the attacker executor's timeout.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/agents.py src/arena.py tests/test_blue_rce_wiring.py && git commit -m "feat(blue): register RCE-family sensors; raise attacker-executor timeout for msf"`

---

### Task 4: Red doctrine — ProFTPD mod_copy via real msfconsole

**Files:**
- Modify: `src/agents.py` (red doctrine block, near the existing privesc/docker triage guidance)
- Modify: `src/orchestrator.py` (new red-reach check, mirroring `_check_red_rogue_root_creation`'s pattern)
- Test: `tests/test_red_rce_doctrine.py` (new), extend `tests/test_tiers.py`

**Interfaces:**
- Produces: red's earned doctrine includes: (1) fingerprint any FTP service's banner (`nmap -sV` or a raw banner grab — red's own discovery, not asserted), (2) if it's ProFTPD and red already holds ANY cred, attempt the module via `run_on_attacker` (`msfconsole -q -x "use exploit/unix/ftp/proftpd_modcopy_exec; set RHOSTS <target>; set RPORT 21; set FTPUSER <held-cred-user>; set FTPPASS <held-cred-pass>; set SITEPATH /var/www/html; run"`), (3) a verify step requesting the planted page and confirming command output appears in the response. `_check_red_tier1_via_webshell(tool_call, output) -> bool` in orchestrator.py: fires only on a `run_on_attacker` (or the relevant HTTP-request tool) call whose output contains unambiguous command-execution evidence (e.g. the specific marker string red's own verify command would produce, like `id` output `uid=`), gated the same way the existing red-reach checks reject error/empty output.
- Consumes: red's existing held-credential state (however earned red currently tracks a cracked cred — read that mechanism before wiring this in, don't invent a parallel one).

- [ ] **Step 1: Write the failing tests** — doctrine text contains the fingerprint-first instruction and the module invocation shape; a negative case for `earned=False`; orchestrator test: webshell output containing `uid=0(` or similar credits T1 (or doesn't double-credit if T1 already reached via another path — check how T1 crediting already guards against double-credit elsewhere and mirror it); error/empty output does not credit.

- [ ] **Step 2: Run to verify fail** → FAIL.

- [ ] **Step 3: Implement.** Write the doctrine text; implement the check function; wire it into the turn loop beside the existing red-reach checks.

- [ ] **Step 4: Run to verify pass** → PASS; full suite green.

- [ ] **Step 5: Commit** — `git add src/agents.py src/orchestrator.py tests/test_red_rce_doctrine.py tests/test_tiers.py && git commit -m "feat(red): ProFTPD mod_copy doctrine via real msfconsole; T1-via-webshell scoring"`

---

### Task 5: LIVE validation (one episode, not gated the way Family 1's privesc was — no destructive/irreversible exploit here, but still a real run against the box)

**Files:** none (operational). Produces `episode_reports/ep_NNN.*` and a `HANDOFF.md` note.

- [ ] **Step 1:** Run one live earned+observe episode: `uv run python -m src.arena --episodes 1 --host 192.168.64.12 --jump-host 192.168.64.11 --earned --observe --model gemma4:31b-cloud --max-turns 20`.
- [ ] **Step 2:** Confirm from `ep_NNN.json`: did red attempt the FTP/mod_copy path at all this episode (it's opportunistic — may take several episodes before red's model chooses it over SQLi/SSH, same variance as Family 1)? If it did: did blue's `investigate_webshells` fire correctly (new file or new process), and did red's T1-via-webshell signal credit honestly (only on real command-output evidence)?
- [ ] **Step 3:** Confirm the box is left clean: any webshell file planted during the episode should be identifiable (it's new, not present in any prior baseline) — note whether cleanup needs its own reset step (a new `scripted_reset` addition to remove files under `/var/www/html` that weren't present at a captured clean baseline, mirroring Family 1's passwd-baseline pattern) if a webshell actually got planted. **If it does, that's a Task 6 follow-up, not solved in this task.**
- [ ] **Step 4:** Record the outcome (fired or not, any tuning needed) in `HANDOFF.md`, same honesty standard as Family 1's live-run notes — a non-firing episode due to red choosing another path is a valid, informative outcome, not a plan failure.

---

## Notes carried from the spec

- This family's sensor (web-root + process baseline-diff) is written to generalize to the family's other example vectors (Tomcat deploy, Sinatra) without modification — both are also "plant something, watch for it to run" patterns. Confirming that generalization is future work, not this plan.
- If Task 5 shows red never opportunistically attempts this vector across several episodes (the known cracking/path-choice variance), the spec's "focus scenario" mechanism (restrict reachable surface to force the vector) is the documented next step — not built in this plan, which stays opportunistic-only per the spec's phased coverage mechanism.
