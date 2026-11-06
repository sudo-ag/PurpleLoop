# PurpleLoop — Generic Engine Extraction (Design)

Date: 2026-11-06
Status: design, approved
Supersedes nothing; implements step 3 of
`2026-11-05-purpleloop-linux-breadth-families-design.md`'s Mechanism C
sequence, now that Families 1 (privesc) and 2 (network-RCE) are both built,
reviewed, merged, and live-validated.

---

## Intent / why

Families 1 and 2 each hand-built the same shape of blue sensor from scratch:
capture a baseline in `mark_analysis_window()` (try/except-to-`None`,
structural validity check — never "is one specific expected entry present,"
after Family 1's root-presence mistake and Family 2's `.html`-allowlist
mistake taught us that lesson twice), diff it later, flag non-empty diff as
breach. That repetition is real and extractable now. Red's side did NOT
repeat as cleanly — Family 1's tradecraft (compile and run a local kernel
PoC) and Family 2's tradecraft (pick an msf module off a service fingerprint)
are structurally different kinds of capability, not two instances of one
shape. Forcing them into a single schema now would be the exact anti-goal
the parent design doc already named: a premature framework built before the
pattern is seen twice. So this extraction is **asymmetric by design**: blue
gets a real generalization, red gets a narrower one scoped only to the
families that actually share a shape.

## Goals

- Blue: a shared low-level helper (capture-a-set-with-structural-validity,
  diff-two-sets) that both existing sensors adopt, reducing boilerplate
  without changing their behavior or their already-reviewed, already-live-
  tested semantics.
- Blue: one new tool — a generic "anything on this box changed that nobody
  has a bespoke sensor for yet" anomaly profiler — sitting *alongside* the
  existing hand-coded sensors (not replacing them), as a safety net for
  vectors Families 3–5 haven't built specific detection for yet, and as the
  shape that will later transfer to Windows (process/listener/user diffing
  is OS-agnostic even when the parsing commands differ).
- Red: a data-driven fingerprint → capability catalog (service pattern →
  msf module / tool + tradecraft notes), consumed by doctrine-generation
  code instead of hand-written prose, **scoped only to the service-oriented
  families** (2: network-RCE, and the upcoming 3: web-app, 4: cred-brute —
  all three are "red sees a service, picks from a catalog of things to try
  against that service type"). Adding a new service-vuln entry becomes a
  data row, not a new doctrine paragraph.
- No regression to Family 1 or Family 2's already-merged, already-live-
  tested behavior — this extraction is refactor + addition, not a rewrite.

## Non-goals

- Forcing Family 1's privesc doctrine or the future Family 5's post-ex
  doctrine into the capability-catalog schema — they aren't
  fingerprint-a-listening-service shaped, and forcing them would be overfit
  from too few examples.
- Replacing the existing per-family sensors with the generic profiler. The
  profiler is a net underneath them, not a rewrite of them.
- Building an actual SIEM product (Wazuh, Security Onion, etc.) or new
  attacker tooling beyond msf. Logged as a future-expansion idea in
  `TODO.md` — explicitly not this round. The generic anomaly profiler below
  is the seed of that idea, written in plain Python, not a product
  integration.
- Coverage-matrix tooling, focus-scenario harness work. Still deferred per
  the parent design doc.

## Anti-goals

- A capability-catalog schema so general it stops teaching anything
  specific about any one service (the parent doc's "hand-coded leaves that
  cannot transfer" anti-goal, inverted: an abstraction so loose it's just a
  pile of free-text strings isn't an abstraction).
- A generic blue profiler that false-positives on normal box churn (new
  ephemeral processes, log rotation) — it must reuse the same window-binding
  and structural-validity discipline the two hand-coded sensors already
  proved out, not invent a looser standard.

## Decisions (user-approved this session)

- Blue gets the real generalization (shared helper + new catch-all
  profiler); red gets the narrower one (capability catalog scoped to
  families 2–4 only). Confirmed in-chat; user agreed this reflects that the
  two families' red tradecraft doesn't actually share a shape yet.
- Future-expansion idea — red tooling beyond msf, blue defender-grade
  tooling (auditd/osquery/EDR-style agents), eventually a SIEM-like
  layer — logged in `TODO.md`, explicitly deferred, not scoped into this
  extraction.
- **Baseline scope (user-confirmed, overrides the parent doc's locked
  note):** the parent design doc flagged that the step-3 profiler "must add
  a cross-episode quiet-baseline phase to the arena." This round explicitly
  does NOT build that. The new catch-all profiler reuses the existing
  per-episode `mark_analysis_window()` baseline, exactly like the two
  hand-coded sensors already do. Cross-episode memory is real future work,
  not dropped — just deliberately out of scope here, to keep this
  extraction small and low-risk. Revisit if/when the profiler's
  per-episode-only precision turns out to be the bottleneck.
- **Family 2's doctrine prose stays untouched.** The capability catalog
  ships this round as a proven schema with ProFTPD as its one populated
  entry (back-filled from the existing hand-written doctrine, not the other
  way around) — it does NOT replace or template-generate Family 2's
  already-reviewed, already-live-tested prose in `src/agents.py`.
  Doctrine-generation actually reading FROM the catalog starts at Family 3,
  when there's a second real entry to prove the generation code against.
  This directly serves the doc's own "no regression" goal (controller call,
  not escalated — the alternative risked rewriting live-tested red prose
  for no immediate benefit).
- **Shared blue baseline helper stays a thin wrapper, not a normalizer.**
  Each existing sensor keeps its own validity-check callback (uid0's
  sentinel check, webroot's and proc's structural checks) passed into the
  shared capture/diff helper — the helper does not impose one validity
  shape on all three. This preserves Family 1's current baseline-trust
  semantics exactly as already tested (controller call — the alternative
  would have quietly changed when Family 1's sensor considers its baseline
  trustworthy, which is explicitly out of scope for a refactor).

## What's left to the builder

- Exact method names/signatures for the shared capture/diff helper in
  `src/executor.py` (read `investigate_privileged_accounts` and
  `investigate_webshells`'s current baseline logic first — the helper's
  shape should fall out of what's actually common between them, not be
  designed from scratch).
- Exact scope of the new catch-all profiler's baseline (processes +
  listening ports + users are the obvious candidates, mirroring what the
  two existing sensors already capture in different combinations — final
  call deferred to the implementation plan, informed by rereading both
  sensors).
- Exact shape of the capability-catalog data structure (a list of dicts
  keyed by service-fingerprint pattern is the obvious default; the plan can
  pick a different shape if one falls out more naturally while reading
  Family 2's existing doctrine text in `src/agents.py`).
- Whether the catch-all profiler sets `flag_access_detected` on its own
  (an independent breach signal) or is attribution/awareness-only like
  Family 2's FTP-session sensor — this is a real open question the plan
  should resolve explicitly, with a stated reason, since it changes
  scoring behavior.

---

**For agentic workers:** this design doc pairs with an implementation plan
written via `superpowers:writing-plans`, executed via
`superpowers:subagent-driven-development` — same process as Families 1–2.
