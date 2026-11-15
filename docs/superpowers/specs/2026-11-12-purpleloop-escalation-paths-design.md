# PurpleLoop — Blue's Escalation-Paths Sensor (General-Purpose Privesc Posture) (Design)

Date: 2026-11-12
Status: design, pending approval

---

## Intent / why

Blue today can *reason* (the ② case engine) and *report* (③ debrief), but it can
only ever *look* through hand-written, one-per-vuln sensors (`investigate_docker`,
`investigate_webshells`, …). Drop it on a box with a weakness nobody pre-wired —
an odd SUID binary, a world-writable script that root runs on a timer — and it is
blind. This is the exact gap the standing north-star names (TODO.md, 2026-11-12):
agents must generalize to any environment, not pattern-match rules we hardcoded
for this dojo.

This round builds the first **general-purpose investigation capability**: a
privilege-escalation **posture scanner**. It is not another per-vuln rule — it is
the "delta from known-good" move that catches the thing nobody wrote a rule for,
and it is deliberately built to feed the ② case engine so blue *chains* findings
into privesc paths instead of listing files.

## Goals

- A single new blue sensor (working name `investigate_escalation_paths`) that runs
  a **read-only enumeration battery** and returns **structured, deviation-flagged
  findings** — never raw dumps:
  - SUID/SGID binaries (`find / -perm -4000 -o -perm -2000 -type f`)
  - file capabilities (`getcap -r /`)
  - sudo rules (what the current principal can read; see grounding caveat)
  - world-writable / weak-principal-writable files and dirs, weighted toward
    anything a *privileged* consumer reads
  - scheduled execution: system + per-user crontabs, `/etc/cron.*`, systemd
    timers and the units they fire
  - writable PATH entries, writable service binaries, writable unit files
  - **package-integrity delta** (`dpkg -V` / `debsums`, `rpm -Va` where present) —
    the known-good backbone
- **Deviation backbone is deterministic, inside the tool.** A finding is
  "interesting" only when state is *unexpected*: off an embedded distro SUID
  allowlist, hash-deviates from the package DB, is GTFOBins-shellable (embedded
  set), or is writable by a non-privileged principal. Raw presence of a normal
  SUID binary is boring and is dropped.
- **Chaining + ranking is blue's, via the ② case engine.** The tool emits each
  flagged finding shaped as a **candidate lead** (category, item, principal,
  why-flagged, blast-radius hint). Blue files the ones that matter with
  `record_lead` and connects them into a privesc-path hypothesis with
  `update_hypothesis` — e.g. `writable-by-me` + `run-by-root` + `scheduled` = one
  path. Nothing about which chains matter is hardcoded.
- Runs against the **real target** (blue is resident), returning CLEAN vs a list
  of flagged findings, window-bound and reset-safe like every existing sensor.

## Non-goals / anti-goals

- **No new scoring tier, and no change to T1/T2/T3 or the ② case structure.** This
  is a posture/assessment sensor (the `investigate_docker` precedent: it informs,
  it doesn't invent a thing to score). Its findings can feed blue's *existing*
  responses; it adds none.
- **No "harden the finding" response this slice** (strip the write bit, re-own the
  SUID). That is the natural follow-on and is deferred — this round is *find and
  chain*, not *fix*.
- **The tool does not chain or rank.** If it emitted ready-made ranked privesc
  paths it would be hardcoding the correlation we deliberately left to blue. The
  tool stops at deviation-flagged facts.
- **Not an exploit tool.** Read-only enumeration only; it never attempts a privesc,
  only surfaces the posture.
- **Anti-goal:** returning raw command dumps and calling it a sensor. A finding is
  a *flagged deviation*, not a line of `find` output. A tool that returns the whole
  SUID list has failed, even if the list is correct.
- **Anti-goal:** testing that the LLM chains *correctly*. We test the mechanical
  layer (deviation-flagging: allowlist, package delta, GTFOBins, writability) and
  the plumbing; whether blue draws the right chain is for live episodes.

## Constraints

- House conventions: TDD, surgical, reuse the existing sensor
  schema/dispatch/`BLUE_TOOL_PRIORITY` wiring, the `_capture_baseline`/
  `_diff_baseline` engine where a baseline fits, and the ② case tools.
- **Read-only + guardrails.** Every command is a benign read (`find`, `getcap`,
  `dpkg -V`, `systemctl list-timers`, reading world-readable cron). It must pass
  `FORBIDDEN_KEYWORDS` without needing `dojo_exploit_ok`; anything that would need
  the guard exemption is out of scope for this sensor.
- **Fail safe, never false-flag.** A command that errors or returns nothing yields
  `baseline_unavailable` / CLEAN for that category, never a fabricated finding
  (the Family-1 lesson: a sensor that can't read must not credit).
- Bounded output: cap the findings fed back into blue's context (compaction rule),
  like `_compact_log_events` — the point is the flagged subset, not a dump.

## Decisions (made during the 2026-11-12 brainstorm)

- Hybrid: tool does deterministic deviation-flagging; blue chains + ranks via ②.
- One sensor, structured flagged findings shaped as candidate leads.
- Deterministic backbone: package-integrity delta + embedded SUID allowlist +
  embedded GTFOBins set + writability-by-weak-principal.
- No new scoring tier; detect/report only; hardening response deferred.
- Read-only, guardrail-clean, fail-safe.

## What's left to the builder

- **Exact tool name, output schema, and the finding dataclass/shape** (category,
  item, principal, why-flagged, blast-radius hint) — consistent with how the other
  `investigate_*` sensors return structured JSON.
- **The embedded known-good data**: the distro SUID allowlist (Ubuntu 14.04 /
  Metasploitable3 baseline) and the GTFOBins-shellable set — how they are stored
  and kept small/auditable.
- **The "weak principal" definition** in practice (world-writable + group-writable
  by non-privileged groups; blue does not know which account red holds, so it
  anchors on "writable by any non-root principal").
- **Which enumeration commands actually run under blue's `vagrant` privileges**
  (grounding caveat): `sudo -l` needs a tty, `/etc/sudoers` needs root — the
  builder gates or drops the reads that privilege forbids and keeps what `vagrant`
  can do, verified live when the boxes are back.
- **How findings reach the case engine**: the tool returns candidate leads; the
  builder decides whether blue files them by its own reasoning (preferred, per the
  hybrid) or the orchestrator pre-files them — and the doctrine line that tells
  blue to chain them.
- **Test plan**: deviation-flagging (off-allowlist SUID flagged, normal one not;
  package-DB hash delta flagged; GTFOBins binary flagged; world-writable-consumed-
  by-privileged flagged), fail-safe on unreadable categories, bounded output, and
  one live validation episode.

## Resolved after builder check

A builder check (2026-11-12) raised four questions; all settled as the
designer's call (one follows directly from the brainstorm's own emphasis).

- **"Known-good" = package provenance/integrity first (distro-agnostic), not a
  distro-bound allowlist.** The brainstorm already named this: "package
  integrity (`dpkg -V`) is the backbone." So the primary, *generalizing*
  deviation source is the system's own package DB — `dpkg -V` / `debsums`
  (`rpm -Va` where present) flags any package file whose hash deviated, and a
  SUID/privileged binary owned by *no* package (`dpkg -S` / `rpm -qf` miss) is
  itself a flag. This needs no embedded allowlist and works on any
  Debian/RPM host — which is the whole point. Secondary net: a target-captured
  baseline via `_capture_baseline` at episode start (the dojo box is clean
  before red acts, so that snapshot is valid "known-good") to catch
  "what changed since clean." GTFOBins stays a small static embedded set
  (a known list of shell-spawning binaries, distro-agnostic). The Ubuntu-14.04
  SUID allowlist is **demoted** to an optional de-noising hint, never the
  primary — a static allowlist is the least-generalizing piece and the
  north-star is generalization.
- **Unreadable category → a distinct `unavailable` status, never CLEAN.**
  Per the Family-1 lesson the spec cites: a sensor that cannot read must not
  credit. The result schema carries, per category, one of `clean` (ran, no
  deviation), `findings` (ran, flagged items), or `unavailable` (could not
  read). CLEAN never stands in for "never ran"; the doctrine tells blue an
  `unavailable` category is a blind spot, not an all-clear.
- **"Writable" = world-writable + writable by a non-root group (mode bits),
  de-noised by provenance; the tool does NOT join writable↔scheduled — blue
  does.** Effective-access-as-`vagrant` is narrower but blue doesn't know which
  account red holds, so the tool anchors on "writable by any non-root
  principal" via mode bits, then drops items a package reports as unmodified
  (provenance de-noise). The **chain itself** (a writable file that a root cron
  line or systemd unit executes) is left to blue: the tool emits the writable
  item and the scheduled item as *separate* candidate leads, each carrying the
  file path so blue can match them, and blue connects them with
  `update_hypothesis`. That join is exactly the "edge is the alert" chaining the
  hybrid assigns to blue — the tool joining it would hardcode the correlation.
- **Request-driven, cached per episode.** The sensor runs when blue calls it
  (like every blue tool), and because a host-wide `find /` + `getcap -r /` is
  expensive, the first call scans and later calls in the same episode return the
  cached posture. It is a posture *snapshot*, not a per-turn timed-event
  detector, so "window-bound" here means reset between episodes (the cache
  clears on `reset_episode`), not a re-scan every turn. Scans exclude
  `/proc`, `/sys`, and cross-filesystem noise (`-xdev` where sensible).
