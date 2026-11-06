# PurpleLoop — Family 3, Part 1: Finish the Inert T2 Exfil Slice (Design)

Date: 2026-11-06
Status: design, approved
Supersedes nothing; implements the first half of
`2026-11-05-purpleloop-linux-breadth-families-design.md`'s Family 3
(web-app exploitation) row — specifically its "finish the inert T2 exfil
slice" framing. Drupal/phpMyAdmin (the rest of Family 3) is explicitly
deferred, not part of this round.

---

## Intent / why

`referee.py` declares `TIER_EXFIL` (T2) but credits it nowhere —
`orchestrator.py` imports the constant and never uses it. Meanwhile red
*already* performs the actual exfil action every episode it takes the
web path: its primary route to a foothold credential is
`sqlmap -u "<url>" --forms --batch --random-agent --dump` against the
payroll app, which pulls real rows (including credentials) off the box.
The tier exists in name only because nothing watches for it. This round
wires it up — on both sides — using the exact signal that's actually
there, verified live, not assumed.

## Live grounding (done before writing this doc, 2026-11-06)

- **MySQL isn't logging.** The payroll DB's `mysqld` (a non-default
  instance at `/etc/mysql-default/my.cnf`, socket
  `/run/mysql-default/mysqld.sock`) has no general/query log configured —
  only `log-error`. Enabling one mid-episode would be a new
  environment-touching config change, out of scope for this round.
- **Apache's access log IS a real, usable signal — but attribution-only.**
  `CustomLog ${APACHE_LOG_DIR}/access.log combined` is the only log
  directive on the box's one vhost. "combined" format does not log POST
  bodies, so the actual SQL injection payload is invisible — same shape of
  limitation as Family 2's FTP syslog (sees the knock, not the content).
  But a real captured excerpt from an actual past episode's sqlmap run
  shows a distinctive, genuinely detectable pattern:
  ```
  192.168.64.11 - - [06/Nov/2026:05:08:01 +0000] "GET /payroll_app.php HTTP/1.1" 200 460 "-" "Mozilla/5.0 (Windows; U; ...) ... Safari/533.20.27"
  192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 390 "-" "Mozilla/5.0 (Windows; U; ...) Safari/533.20.27"
  192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 177 "-" "Mozilla/5.0 (Windows; U; ...) Safari/533.20.27"
  192.168.64.11 - - [06/Nov/2026:05:08:02 +0000] "POST /payroll_app.php HTTP/1.1" 200 177 "-" "Mozilla/5.0 (Windows; U; ...) Safari/533.20.27"
  ```
  A burst of GET+multiple-POST requests to `/payroll_app.php`, clustered
  within 1-2 seconds, each with a DIFFERENT user-agent string (Opera,
  curl, antique Firefox/Safari builds) — exactly `sqlmap --random-agent`'s
  rotation. This is a real, distinctive fingerprint, not a guess.
- **The payroll app's real credentials and DB name are visible in its own
  source** (`/var/www/html/payroll_app.php`): `mysqli('127.0.0.1', 'root',
  'sploitme', 'payroll')`. Not used directly by this design, but confirms
  the app and its data genuinely exist to be dumped.

## Goals

- **Red side:** credit T2 honestly, on real evidence that data actually
  came back — a new orchestrator check mirroring `_check_red_tier1_via_webshell`'s
  pattern (not "ran sqlmap," not "exploit completed," but genuine extracted
  rows in sqlmap's own output).
- **Blue side:** a new sensor watching the Apache access log for the
  burst-of-requests-from-a-foreign-IP pattern against the payroll endpoint,
  attribution-only (does NOT set `flag_access_detected` on its own — the
  log can't see the payload or the response, same epistemic limit Family
  2's FTP sensor had) — paired with a `_check_blue_exfil_detect` check
  crediting `blue_tier_detect[TIER_EXFIL]`.
- T1 and T2 end up both credited within the same episode's SQLi exploit
  chain (decided this session) — but this is NOT a new T1-crediting path.
  **T1 stays exactly as it already works today**: credited later, on a
  separate turn, when red calls `use_credential` with the dumped password
  and the call succeeds (the existing `_check_red_foothold` mechanism,
  unchanged). **T2 is the only new check this round adds**, firing earlier
  (same turn as the dump) on sqlmap's own output showing genuine extracted
  rows. The two checks are independent and never share evidence — T2 does
  NOT prove T1, and dumping data is not treated as proof a credential
  *works* (only `use_credential` succeeding proves that). "Not
  double-dipping" means: these are two true, separately-evidenced facts
  about one exploit chain (got data; later, got in), not one piece of
  evidence credited twice. Confirmed live against all 5 captured episodes
  in `episode_reports/`: the dump always happens several turns before
  `use_credential`, never the same tool call.

## Non-goals

- Drupal, phpMyAdmin, or any other Family 3 vector. This round finishes
  the EXISTING payroll SQLi's exfil slice only.
- A MySQL query-log-based sensor. Not enabled by default; enabling it is
  new environment-touching scope this round doesn't need.
- A prevention reflex for T2. Unlike T1's escalation-path reflex or T3's
  rogue-account removal, there is no "undo" action for data that already
  left the box — detection is the honest ceiling for this tier by its
  nature. (Blue could, in principle, revoke the exposed DB credential or
  firewall the attacker IP after detection, but that's a genuinely new
  capability, not wiring up something already inert — deferred.)

## Anti-goals

- Crediting T2 on sqlmap's own exit code or "run completed" banner —
  mirrors every prior family's honest-scoring lesson (Family 2's msf
  banner, Family 1's Dirty COW compile step: running the tool is never
  proof, only verified evidence is).
- A blue sensor that claims more certainty than the log actually supports
  — the Apache log shows a burst, not a confirmed breach; it stays
  attribution-only, exactly like Family 2's FTP sensor, not a new
  "flag_access_detected"-setting signal pretending to see the payload.

## Decisions (this session)

- T2 fires on the same dump action that gets T1, when both are true —
  confirmed with the user, who agreed this is accurate scoring, not a
  double-credit bug.
- Scope is the existing payroll SQLi only; Drupal/phpMyAdmin deferred to a
  follow-up (same pattern as Family 1→2: prove one concretely before
  adding more surface).
- No MySQL-log sensor, no prevention reflex — both explicitly deferred,
  not forgotten (see Non-goals).

## What's left to the builder

- Exact method name/signature for the new blue sensor (mirror
  `investigate_ftp_sessions`'s attribution-only shape and
  `investigate_box_anomalies`'s independent-baseline pattern where it
  applies — read both before choosing).
- Exact burst-detection heuristic (window size, request-count threshold,
  what counts as "clustered") — pick something that would catch the real
  captured pattern above without false-firing on a single legitimate page
  load; the plan should state the exact thresholds and justify them
  against this doc's captured log excerpt.
- Exact evidence pattern for `_check_red_data_exfil`'s "genuine extracted
  rows" check against sqlmap's real output shape (its `[N entries]` +
  table markers, or whatever sqlmap's `--dump` output actually looks like
  when it succeeds vs. when it finds nothing) — verify against a real
  captured sqlmap run if one exists in `episode_reports/`, or against
  sqlmap's documented output format if not.
- Whether the new blue sensor needs `self.control_source_ip`-style
  self-filtering (blue is resident on the target and investigates via SSH
  text commands — it's unlikely blue ever generates its own HTTP traffic
  to the payroll app, but the plan should confirm this rather than assume
  it, the same discipline every prior sensor's self-filter check applied).

---

**For agentic workers:** this design doc pairs with an implementation plan
written via `superpowers:writing-plans`, executed via
`superpowers:subagent-driven-development` — same process as Families 1–2
and the engine extraction.
