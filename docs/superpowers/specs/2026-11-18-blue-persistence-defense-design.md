# Blue hunts and evicts a planted SSH-key backdoor — design

Date: 2026-11-18
Status: implemented (unit-green + live direct-probe validated on `.12`)

## Intent / why

The persistence scenario (slice #1, merged `7f35359`) made the engagement turn on
whether red's planted SSH key *survives*: red wins by planting a durable key, and
blue wins **only** by `remove_persistence` (a password lock does not evict a
pubkey — the pedagogical crux). But the merge wired only the red side and the
win-eval. In the live persistence episode blue never hunted or evicted the key, so
red won uncontested — the cat-and-mouse was one-sided.

Root cause: nothing steers blue toward persistence. `investigate_persistence`
sits low in the LLM-driven breadth rotation, so blue rarely runs it; and even when
it surfaces a planted key, nothing directs the `remove_persistence` eviction. The
guidance machine (`BlueAgent.tool_guidance`) had no persistence branch at all.

## Goal

Make the loop two-sided: once a foothold has landed, steer blue to *hunt* the key
with `investigate_persistence`; once that surfaces a planted key, steer the
`remove_persistence` *eviction* on the right account — so a planted backdoor
produces a **blue** win instead of an uncontested red one.

## Non-goals / anti-goals

- **Not** objective-gated. The trigger is signal-driven (a landed foothold, a
  detected key), not `--objective persistence`. A planted key is always a breach,
  so blue should defend it under any objective — this matches how the
  foothold-hunt arc actually fires and the north-star ("generalize, don't tune to
  the dojo"). No `objective` arg is plumbed to `BlueAgent`.
- **Not** auto-running sensors: blue stays the decider; we fix the guidance.
- No change to red, the arena/orchestrator wiring, the win-eval, or scoring —
  those already landed with slice #1.
- Does **not** fix the upstream "blue only registers a foothold once red acts on
  it" gap (deferred approach C): the hunt is gated on `_has_foothold()`, so it
  inherits that limitation. Separate item.

## Approaches considered

- **A — signal-driven guidance branches (CHOSEN).** Two branches in
  `tool_guidance`: a persistence-HUNT (foothold landed, sensor not yet run) and an
  EVICT (key detected, not yet removed). Smallest change, no plumbing, fires under
  any objective, mirrors the foothold-hunt pattern.
- **B — objective-gated.** Pass `objective` to `BlueAgent`, fire only under
  `--objective persistence`. Literal reading of the handoff, but couples blue to
  the scenario string — against the north-star. Rejected.

## The how (decided)

In `src/agents.py`, all within `BlueAgent`:

1. **`_removed_persistence(self) -> bool`** — `"remove_persistence" in
   self._tools_used()` (mirror of `_closed_surface`).

2. **`_planted_key_account(self) -> Optional[str]`** — scans `self.history` for an
   `investigate_persistence` result and returns the account from its `new_keys`
   (entries are `"<account>:<key-line>"`, so `entry.split(":", 1)[0]`); the most
   recent breach wins, `None` if no key has surfaced. Mirrors the history-scan
   idiom of `_escape_detected`.

3. **EVICT branch**, placed **after the IDENTIFY block, before HARDEN**. Fires when
   `_planted_key_account()` is truthy and `not _removed_persistence()`. Fires in
   **both** modes (unlike the observe-gated HARDEN): containing the source IP does
   not remove a key already on disk, so it must be stripped regardless. Directs
   `remove_persistence user="<account>"`.

4. **Persistence-HUNT branch**, placed **after the HARDEN block, before RESPOND**.
   Observe-gated (like HARDEN / the foothold-hunt). Fires when `observe and
   _has_foothold() and "investigate_persistence" not in _tools_used()`. Directs
   `investigate_persistence`. HARDEN (surface close) runs first; once the hunt
   surfaces a key, EVICT owns the next relevant turn.

The sequence this produces: foothold lands → HARDEN closes the surface → HUNT runs
`investigate_persistence` → key detected → EVICT runs `remove_persistence`.

## Verification

- Unit (`tests/test_persistence_defense.py`): hunt fires on a foothold; no hunt
  without a foothold; a detected key steers eviction on the right account; eviction
  fires in non-observe too; no re-eviction once removed; `_planted_key_account`
  parsing. Full suite green, zero fallout in foothold-hunt / blue-triage.
- Live direct probe on `.12` (decoupled from LLM variance, since the in-loop
  episode produced neither a planted key nor a registered foothold): plant a key
  after blue's baseline → `investigate_persistence` returns BREACH on the right
  account → `tool_guidance` fires the EVICT steer naming that account →
  `remove_persistence` strips the key off the real box → baseline restored. All
  four confirmed.
