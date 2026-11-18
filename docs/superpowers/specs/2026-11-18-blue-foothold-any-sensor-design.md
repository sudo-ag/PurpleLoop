# Blue closes the surface on ANY foothold, not just SSH logins — design

Date: 2026-11-18
Status: proposed (short design, awaiting approval)

## Intent / why

The earned-foothold fix (committed `362cec5`) made blue *confirm* a stealthy
login. But the live episode right after exposed the next gate: with a confirmed
attacker, blue still **never closed a vector** — it only documented. Root cause
(diagnosed, not guessed): blue's whole response path (IDENTIFY → HARDEN →
`remediate_escalation_surface`) gates on `_attacker_account()`, which reads
**only** `investigate_logs.suspicious_users`. Red took the Drupal web-RCE path
as `www-data` (no auth-log login), so `_attacker_account()` was `None`, blue
dropped to ATTRIBUTE, and the surface-close directive never fired — even though
blue's process/webshell sensors had clearly identified the `www-data` breach.

This is the gate blocking the close→pivot loop from firing live for the path red
actually prefers.

## Goal

In observe mode, when blue has a confirmed attacker AND a landed foothold
detected by **any** sensor (auth login, critical process under a service
account, or a confirmed webshell), blue is directed to close the escalation
surface (`remediate_escalation_surface`) — not just document.

## Non-goals / anti-goals

- **Not** routing a service account (`www-data`) into `revoke_escalation` /
  `remediate_account`. You don't lock the web server's account; that playbook is
  SSH-account-shaped and stays gated on an auth-log account. (This is approach
  A's trap, explicitly rejected.)
- **Not** teaching blue to kill the webshell process yet. Closing the surface +
  containing is enough to force a pivot; per-foothold-type response playbooks are
  the later typed-foothold model (approach C), out of scope here.
- No new scoring tier. No change to non-observe behavior (blue still ends by
  containing there).

## Approaches considered

- **A — widen `_attacker_account()` to return service accounts.** One-function
  change, but feeds `www-data` into `revoke_escalation`/`remediate_account` —
  semantically wrong (locks the web server's account). Rejected.
- **B — decouple the surface-close from the account (CHOSEN).**
  `remediate_escalation_surface` is account-agnostic; the HARDEN directive only
  checks that a foothold *exists*, never uses the account name. So gate HARDEN on
  a new `_has_foothold()` (true for any sensor's foothold) while leaving
  IDENTIFY's account-revoke gated on an auth-log account. Surgical, correct,
  unblocks the web-RCE path.
- **C — full typed-foothold model** (per-type response playbooks). The eventual
  north-star; far larger (touches `triage_phase`, every directive, likely
  scoring). B is a clean first step toward it. Deferred.

## The how (decided)

Three edits in `src/agents.py`:

1. **New `_has_foothold(self) -> bool`.** True if any of:
   - `_attacker_account()` is not `None` (existing auth-log foothold), OR
   - any `investigate_processes` output has a `critical_processes` entry whose
     `user` is neither empty nor blue's control account
     (`self.executor.user`) — a service/non-root process compromise, OR
   - any `investigate_webshells` output with `assessment == "BREACH"`, or a
     non-empty `new_files`, or `flag_access_detected` true.

2. **HARDEN gate** (agents.py:1831): swap `self._attacker_account()` →
   `self._has_foothold()`. (IDENTIFY and RESPOND keep `_attacker_account()`.)

3. **HARDEN directive text** (agents.py:1833–1840): generalize the opening so it
   reads correctly whether or not a revoke happened. The current text assumes
   "You cut the account's group-based escalation" — true only for the SSH path.
   New opening states a foothold has landed and to close its escalation surface
   in one move; the `remediate_escalation_surface` instruction is unchanged.

## What's left to the builder

- Exact `_has_foothold()` membership for edge cases (e.g. a root-owned critical
  process — treat as a foothold too, since it means red already escalated;
  exclude only the control account). Builder's call, documented inline.
- Wording of the generalized directive.

## Verification

- Unit (`tests/`): `_has_foothold()` → true for a `www-data` critical process,
  true for a webshell BREACH, true for an auth account, **false** for a
  recon-only port scan (no critical process / account).
- `tool_guidance(observe=True, confirmed=[ip], contained=False)` with a web-RCE
  foothold (no account) → emits `remediate_escalation_surface`.
- Regression: SSH-account foothold still goes IDENTIFY→revoke→HARDEN unchanged;
  recon-only still never HARDENs; full suite green.
- Live (optional, after merge): earned+observe episode where red takes the
  web-RCE path → blue now fires the surface close (the step the last run missed).
