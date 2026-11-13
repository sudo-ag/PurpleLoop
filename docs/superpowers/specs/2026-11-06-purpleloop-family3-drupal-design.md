# PurpleLoop — Family 3, Part 2: Drupal RCE (Design)

Date: 2026-11-06
Status: design, approved
Supersedes nothing; implements the Drupal half of
`2026-11-05-purpleloop-linux-breadth-families-design.md`'s Family 3 row.
phpMyAdmin (the other remaining half) is a deliberate follow-on, not part
of this round (decided this session — do Drupal first, since it's the
more novel vector and the clearer test of whether the engine extraction
actually pays off).

---

## Intent / why

Drupal 7.5 is a real, full install at `/var/www/html/drupal` on `.12`
(confirmed live), and it's vulnerable to two real, well-known CVEs.
Unlike Family 2's ProFTPD path — which turned out to be a credential
*pivot*, not an independent foothold — this one needs no pre-existing
credential at all: it's genuinely the second independent foothold path
the original Family 2 framing wanted and didn't get. It's also the first
real chance to see whether the engine extraction (Families 1-2's
baseline-diff sensors, generalized) actually does its job: this round
may need **zero new blue sensor code**, only red doctrine, one new
scoring check, and a capability-catalog entry.

## Live grounding (done before writing this doc, 2026-11-06)

- **Drupal 7.5 confirmed** (`define('VERSION', '7.5');` in
  `includes/bootstrap.inc`), installed at `/var/www/html/drupal` — a
  subdirectory of the SAME webroot the payroll app and `investigate_webshells`
  already live in (`/var/www/html`).
- **Path discoverability confirmed live with red's actual toolset, not just assumed.** A plain `curl http://192.168.64.12/` from Kali `.11` returns an Apache directory listing with `drupal/` (and `phpmyadmin/`) linked directly at the web root — the same recon action already visible in captured episodes (red routinely fetches this index page as part of its normal enumeration, e.g. `episode_reports/ep_001.md`). No directory-brute tool, no new red capability, and no change to the target's Apache config is needed — the path is already sitting in plain sight for anything that fetches `/`.
- **Two real msf modules confirmed present** via `msfconsole -q -x "search drupal"`
  on Kali `.11`:
  - `exploit/unix/webapp/drupal_drupageddon` (CVE-2014-3704, SA-CORE-2014-005,
    "Drupalgeddon 1") — unauthenticated SQL injection via the Form API,
    disclosed 2014-10-15, Rank excellent.
  - `exploit/unix/webapp/drupal_drupalgeddon2` (CVE-2018-7600,
    SA-CORE-2018-002, "Drupalgeddon 2") — unauthenticated Forms API
    property injection → RCE, disclosed 2018-03-28, Rank excellent, **Check
    supported: Yes**. `info` confirms: `Privileged: No` (lands as
    `www-data` — T1, not T3), `TARGETURI` defaults to `/` (our install is
    at `/drupal/`, so red's own recon of the path — already visible in the
    directory listing it's already seen — has to feed this), and it has
    **two meaningfully different target shapes**: "PHP In-Memory" (runs one
    command, returns output directly, no file ever touches disk) vs. "PHP
    Dropper" (plants a persistent PHP file in the webroot). Both are
    vulnerable since Drupal 7.5 is well below both CVEs' fixed versions
    (7.32, 7.58).
- **This target-shape split matters for detection, and it's a genuine
  open question, not glossed over — correction below is from the
  builder-check, since my first pass misattributed which sensor owns
  which signal.** Both signals actually live in the SAME existing
  sensor, `investigate_webshells` (Family 2) — NOT split across two
  sensors as I first wrote. `investigate_webshells` already diffs BOTH
  the web root's file listing (`new_files`) AND the process tree
  (`new_processes`) in one method. If red's exploit run uses the Dropper
  target, the file-diff half catches the new file. If red uses the
  In-Memory target, there's no file, but the exploit still has to spawn
  a command (e.g. `id`) as a child of the PHP/Apache process — the SAME
  sensor's process-diff half catches that. `investigate_box_anomalies`
  (engine extraction) is NOT involved in detecting either Drupal exploit
  shape — it only diffs listening ports and user accounts, nothing
  process-related. **Whoever validates the live task must watch
  `investigate_webshells`'s output, not `investigate_box_anomalies`'s —
  watching the wrong tool here could wrongly conclude "the engine has a
  gap" when it actually fired correctly.** Neither signal is guaranteed
  to fire; which one does depends on which target red's own model picks,
  and that choice is red's to make freely (not seeded).
  This round does not force a target choice onto red's doctrine — doing so
  would be steering exploit mechanics past the no-seeding line this
  project holds hard. Both existing sensors stay as the detection layer,
  unmodified; this is treated as a feature of the engine extraction
  actually working, and reported honestly either way after the live task.

## Goals

- Red doctrine: fingerprint-first (same discipline as every prior family
  — Drupal's presence and version are things red reads off the directory
  listing/`CHANGELOG.txt` it can already see, never asserted), then,
  if Drupal is identified, drive the matching msf module via the existing
  `run_on_attacker` tool (no new red tool plumbing).
- A new orchestrator check, `_check_red_tier1_via_drupal_rce`, mirroring
  `_check_red_tier1_via_webshell`'s evidence discipline exactly: credit T1
  only on genuine command-execution evidence in the module's own output
  (or a follow-up verification command's output) — never on "exploit
  completed" or a session merely opening.
- One new `CAPABILITY_CATALOG` entry (Drupal), back-filled the same way
  Family 2's ProFTPD entry was — data only, not wired into live doctrine
  generation (same deferred-to-Family-4-or-later boundary the engine
  extraction set).
- **No new blue sensor this round, by design** — this is the point being
  tested. If the live task shows a real gap (neither existing sensor
  fires on red's actual exploit path), that's reported honestly as a
  finding, not patched reflexively mid-round.

## Non-goals

- phpMyAdmin — explicit follow-on, not this round.
- Forcing red's target-shape choice (In-Memory vs. Dropper) — see above;
  this is red's free choice, not doctrine's to make.
- Any change to `investigate_webshells` or `investigate_box_anomalies` —
  if this round finds either needs a change to actually catch Drupal's
  RCE, that's a finding for the NEXT round, not a scope-creep fix
  mid-plan (mirrors the project's standing discipline against
  discovering-and-immediately-patching inside an unrelated task).

## Anti-goals

- Crediting T1 on the module's `[+]`/session-opened banner alone — same
  anti-pattern every prior family's honest-scoring lesson warns against.
- Hardcoding `TARGETURI=/drupal/` into doctrine as an assertion that the
  path exists — the doctrine should instruct red to use the path its OWN
  recon already found (the directory listing it saw), not hand it a
  pre-known value as fact.

## Decisions (this session)

- Scope is Drupal only; phpMyAdmin deferred to a follow-on round.
- No new blue sensor built preemptively — the two existing sensors
  (webshell file-diff, box-anomalies process-diff) are the detection
  layer, and whether they're sufficient is itself part of what this
  round's live validation is testing.
- Red's exploit-target choice (In-Memory vs. Dropper) is not steered by
  doctrine.

## Resolved during design (read the module's actual Ruby source, Kali `.11`)

- **The evidence-shape question is answered, not open.** Read
  `/usr/share/metasploit-framework/modules/exploits/unix/webapp/drupal_drupalgeddon2.rb`
  directly: setting `PAYLOAD cmd/unix/generic` auto-sets
  `datastore['DUMP_OUTPUT'] = true` (the module does this itself,
  line ~195 — `"Naughty datastore modification"` per its own comment),
  and that payload (`modules/payloads/singles/cmd/unix/generic.rb`) takes
  a `CMD` option (the literal shell command to run) via
  `Msf::Sessions::CommandShellOptions`. When `DUMP_OUTPUT` is set, the
  module does `print_line(res.body)` — the raw HTTP response body, which
  for a successful `cmd/unix/generic` payload with `CMD id` IS `id`'s own
  stdout, echoed back. **This is the exact same `uid=\d+\(\w+\)` evidence
  pattern already used by `_check_red_rogue_root_creation` and
  `_check_red_tier1_via_webshell`** — no new evidence shape needed, no
  separate curl-verification step needed (unlike Family 2, where the
  module's own output never confirmed execution and a follow-up HTTP
  fetch was required). The full doctrine command shape:
  `msfconsole -q -x "use exploit/unix/webapp/drupal_drupalgeddon2; set RHOSTS <target>; set RPORT 80; set TARGETURI <path red's own recon found>; set PAYLOAD cmd/unix/generic; set CMD id; run"`.
- This also resolves the target-shape question practically: `cmd/unix/generic`
  is itself the "In-Memory"-shaped path (no file dropped), so the doctrine
  naturally defaults toward the path with directly-verifiable evidence
  without needing to steer red's choice — red is simply given this as the
  tradecraft to draw on, same precedent as every prior family's catalog
  text, and remains free to try something else.

## What's left to the builder

- The exact `CAPABILITY_CATALOG` entry's fields, back-filled from
  whatever doctrine text this round writes (mirroring Family 2's
  pattern).
- Whether `_check_red_tier1_via_drupal_rce` can literally reuse
  `_check_red_rogue_root_creation`'s or `_check_red_tier1_via_webshell`'s
  existing `uid=\d+\(\w+\)` regex verbatim, or needs its own copy gated on
  a different command-name check (`drupalgeddon`/`drupal` in the
  `run_on_attacker` command, mirroring the `http` gate
  `_check_red_tier1_via_webshell` uses to reject attacker-box-local `id`
  runs) — read both existing checks' exact gating logic first and decide
  based on what's actually DRY vs. what risks conflating two different
  red-reach paths into one function.

---

**For agentic workers:** this design doc pairs with an implementation plan
written via `superpowers:writing-plans`, executed via
`superpowers:subagent-driven-development` — same process as every prior
family.
