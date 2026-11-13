# PurpleLoop — Family 5 (Post-Exploitation): SSH-Key Persistence (Design)

Date: 2026-11-12
Status: design, pending approval

---

## Intent / why

Family 5 in the breadth-families design
(`docs/superpowers/specs/2026-11-05-purpleloop-linux-breadth-families-design.md`)
is "post-exploitation: persistence, exfil, log-tamper." Exfil (T2, payroll-DB
dump) and log-tamper (`RED_EVASION_ADDENDUM`) already exist. Persistence does
not — nothing in the codebase lets red survive being remediated, and
`scripted_reset` explicitly defers persistence cleanup "once the earned game
actually plants them" (`src/arena.py:189`).

This round builds that missing piece, and picked the version worth building:
**blue's only compromised-account response, `remediate_account`
(`usermod -L` + `pkill`), only locks *password* authentication.** Confirmed
live against `.12`: `sshd_config` has `PubkeyAuthentication yes` and no PAM
rule (`pam_nologin` aside) that blocks a locked account from key-based login.
A planted SSH key in `~/.ssh/authorized_keys` survives `remediate_account`
untouched. That's not generic "persistence flavor" — it's a concrete
arms-race escalation: red gets a real answer to blue's existing response,
the same shape as the docker/sudo revoke-reflex arc from 2026-10-23.

Also bundled: `RED_EVASION_ADDENDUM` (log-tampering doctrine) is stale — it
tells red "you have root (NOPASSWD sudo)," a holdover from the pre-earned
handed-`vagrant` era. Under the current earned-foothold model that's simply
false until red has actually escalated. Fixing it is small, in the same
doctrine file, and otherwise sits broken indefinitely.

## Goals

- Red can plant a real SSH-key backdoor into the account it controls
  (foothold or root), as supplied tradecraft (same precedent as the docker
  breakout command, the Dirty COW PoC, and every prior family's msf
  invocation) — discovery of *when/whether* to do it stays red's call, the
  mechanism is doctrine like every prior family.
- Blue gets a coupled, window-bound sensor that detects a planted key
  without false-flagging a pre-existing one, using the existing
  `_capture_baseline`/`_diff_baseline` engine (same discipline as
  `investigate_webshells`/`investigate_box_anomalies`).
- Blue gets a response, `remove_persistence(user)`, that strips the planted
  key back to baseline — same reversible-action convention as
  `remove_privileged_account`/`revoke_escalation`.
- `scripted_reset` cleans up any planted key between episodes — closes the
  deferred note in `arena.py`.
- `RED_EVASION_ADDENDUM` no longer asserts red has NOPASSWD sudo it may not
  have.

## Resolved after builder check

A builder check on this doc surfaced three gaps. Two were decisions only
the user could make (real scope tradeoffs); one was mine to settle.

- **Red reconnecting via the planted key after a lock (user decided:
  plant→detect→remove only).** Red's simulated SSH transport
  (`SSH_MASTER_EXPECT`, `_SSH_CONFIG_TEMPLATE`) is hardcoded
  password-only — no pubkey/IdentityFile plumbing exists anywhere in
  `ToolExecutor`. This round proves the mechanism is planted, detected,
  and removed; it does **not** require red to actually regain access
  through the key after `remediate_account`'s lock takes mechanical
  effect — that would need new reconnection plumbing (a new tool or a
  key-auth fallback in `connect()`), explicitly **out of scope** this
  round. The real-world correctness claim (a genuine attacker's key
  would survive the lock) still grounds why this is worth building; live
  exploitation of that fact is a future round's work once red has
  key-auth capability.
- **Sensor baseline coverage (user decided: snapshot `/home/*/.ssh` +
  `/root/.ssh` at window-open, no `/etc/passwd` read).** The precedent
  sensors this design cites (`_list_webroot`, `_list_proc_signatures`,
  etc.) are account-agnostic; `authorized_keys` is per-home-directory,
  and blue doesn't know which account red will land on until it happens.
  Resolution: enumerate existing home directories directly (`ls /home` +
  always include `/root`) rather than reading `/etc/passwd` — this needs
  no `dojo_exploit_ok` gating (unlike `investigate_box_anomalies`'s
  `getent passwd` path, gated on the `"passwd"` keyword match), so the
  sensor runs against the real, non-dojo target, matching this design's
  own live-validation goal. A brand-new account created mid-episode
  (not present at window-open) is an honest gap, not silently masked —
  `_diff_baseline`'s existing "no baseline, no diff" behavior already
  reports this correctly as `baseline_unavailable` for that one account,
  same as every other baseline-diff sensor's known limitation.
- **`RED_EVASION_ADDENDUM`'s "foothold-level" cleanup clause (my call:
  dropped).** I had asked the doctrine to name a log-cleanup command
  shape for an unprivileged foothold account too, "since evasion is
  useful even before full root." The builder check correctly flagged
  this as not executable: `auth.log` is `root:adm 0640`, so a non-root,
  non-sudo account cannot write it regardless of identity — writing
  doctrine that always fails with "Permission denied" is worse than not
  writing it. Dropped; the fix stays scoped to what it originally was:
  gate the log-cleanup technique on confirmed root (via `id`/`whoami`
  evidence of real escalation), nothing broader.

## Non-goals

- Cron-based persistence. The breadth design's table names "cron/key
  persistence" together, but one mechanism per round is this project's
  standing discipline (ProFTPD-not-Tomcat, Drupal-not-phpMyAdmin, etc.).
  Cron is a legitimate follow-on, not this round.
- A new scoring tier. This is a detection/defense surface on top of
  whatever tier red already holds (foothold or root) — not a new win
  condition. No `TIER_PERSIST` gets added to `referee.py`.
- A deterministic auto-revoke-style reflex. The docker-breakout reflex was
  added only after live evidence the model could not win that 1-turn race
  through steering alone (2026-10-23 session). Give blue normal steering
  first here; a reflex is a future escalation if live runs show the same
  failure mode, not a default.
- Multiple simultaneous planted keys / key rotation / red re-planting after
  removal in the same turn. One plant, one detect, one remove — the
  minimum that proves the mechanism.

## Anti-goals (would make this a failure even if it "works")

- Seeding/hinting red (the project's standing rule). The doctrine supplies
  the *mechanism* (how to generate and append a key), never asserts that
  blue *will* remediate this episode or that persistence is "needed" —
  red's own judgment decides when to use it, same as every prior
  tradecraft block.
- A sensor that false-positives on the account's own real, pre-existing
  key (blue's own control connection, or a box-provisioned key) — must be
  window-bound like every other baseline-diff sensor in the engine.
- A response that locks out the legitimate account owner's own key or
  deletes the authorized_keys file outright instead of surgically removing
  the planted line(s).

## Constraints

- Reuses the existing baseline-diff engine (`_capture_baseline`/
  `_diff_baseline`, `mark_analysis_window()`) — no new guardrail exception
  needed (unlike Dirty COW): `authorized_keys`/`ssh-keygen`/`.ssh` are not in
  `FORBIDDEN_KEYWORDS`.
- Red's per-call SSH (no persistent shell state between calls) means the
  keypair must be generated and appended in commands that each stand alone
  — same discipline every prior red doctrine block already follows.
- Target account's home directory path varies by account (`/home/<user>`
  for a foothold account, `/root` if red has escalated to root) — the
  sensor and the response must both resolve the right path per-account, not
  assume one.
- `remove_persistence`, like its siblings, must refuse protected/defender
  accounts and reject option-like usernames (the `-` leading-character
  injection hole fixed project-wide on 2026-11-05 applies here too).

## What's decided (the how, as decided)

- **Red's doctrine command shape:** on Kali, `ssh-keygen -t ed25519 -f
  /tmp/pl_key -N ""` (no passphrase — the backdoor must work unattended),
  then on the target (via whichever channel red already has —
  `execute_command` if it has a foothold, same per-call-SSH discipline as
  every other doctrine block): `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo
  "<pubkey>" >> ~/.ssh/authorized_keys && chmod 600
  ~/.ssh/authorized_keys`. The builder confirms the exact append-vs-overwrite
  semantics are safe (append only, never truncate) before finalizing the
  doctrine text.
- **Sensor name:** `investigate_persistence` (new, sibling to
  `investigate_cron`, not a merge into it — different artifact type, same
  separation-of-concerns precedent as keeping `investigate_ftp_sessions`
  and `investigate_web_requests` separate). Captures a baseline of each
  relevant account's `authorized_keys` content (by line, keyed by account)
  at `mark_analysis_window()`; a diff showing a line present live but absent
  from baseline is the breach signal — mirrors `investigate_webshells`'s
  file-diff shape exactly.
- **Honest-scoring check:** red's side gets its own verify-not-assert check
  (mirrors `_check_red_rogue_root_creation`'s discipline) — credit only on
  confirmed evidence the key append actually landed (e.g. a readback of
  `~/.ssh/authorized_keys` showing the new line, or the command's own
  success marker), never merely on "ran ssh-keygen." This does NOT set any
  `red_tiers` entry (no new tier, per Non-goals) — it's a new
  `SimulationState` field (e.g. `persistence_planted_turn`) the builder
  names, parallel to how tiers are tracked but outside the `TIERS` tuple.
- **`remove_persistence(user)`:** resolves the account's home dir (`/root`
  for root, `/home/<user>` otherwise), strips exactly the lines present live
  but absent from the sensor's baseline (never truncates the whole file,
  same discipline as the ProFTPD/webroot sensors' "surgical, not
  destructive" rule already established project-wide), reversible is N/A
  here (deleting a planted key is itself the fix, nothing to restore at
  disconnect — unlike `remediate_account`'s lock/unlock).
- **`RED_EVASION_ADDENDUM` fix:** replace "You have root (NOPASSWD sudo)"
  with a conditional framing — the log-cleanup technique is only available
  once red actually holds root (verified via its own `id`/`whoami` output,
  not assumed). Scoped to root only — see "Resolved after builder check"
  below for why a foothold-level variant was dropped.

## What's left to the builder

- Exact `SimulationState` field name/shape for the new persistence-planted
  signal, and where it surfaces in the episode report / `ep_NNN.json`
  (mirror how other non-tier signals like `suspicious_users` already
  surface).
- Test fixtures: synthetic `authorized_keys` before/after content for the
  sensor's unit tests (follow the project's "test against realistic
  captured/plausible shapes" precedent).
- Whether `investigate_persistence` needs its own `BLUE_TOOL_PRIORITY`
  wiring slot or extends an existing rotation list — follow whatever the
  engine's existing registration pattern for a new sensor already is
  (`investigate_box_anomalies`'s Task 3 wiring from the engine-extraction
  round is the direct precedent).
- Live validation: one gated episode, watching specifically whether red
  plants a key after being remediated (or proactively) and whether
  `investigate_persistence` catches it — same "opportunistic, may not
  land this episode" honesty as every prior family's live-run framing.
