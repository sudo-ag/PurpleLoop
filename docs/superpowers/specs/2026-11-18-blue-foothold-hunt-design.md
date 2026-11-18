# Blue hunts the foothold after confirming a scanner — design

Date: 2026-11-18
Status: proposed (short design, awaiting approval)

## Intent / why

The any-sensor HARDEN fix (merged `816bd40`) lets blue close the surface once it
*holds* foothold evidence. But the live episode after it showed blue never got
that evidence: red took a web-RCE foothold (T1, `www-data`), blue confirmed the
attacker IP from the port scan, but **never ran `investigate_webshells`** — the
sensor that reveals a web-RCE foothold (new process tree vs baseline). So
`_has_foothold()` stayed False, blue dropped to ATTRIBUTE (document), and the
close→pivot loop never started.

Root cause: after confirming a scanner, blue has no evidence of a *landed*
foothold yet, so `triage_phase` returns ATTRIBUTE and the guidance says "keep
documenting." Nothing directs blue to actively *hunt* the foothold with the
sensors that hold its evidence. Blue's own breadth rotation is LLM-driven and
simply didn't land on `investigate_webshells`.

## Goal

When blue has a confirmed attacker but no foothold evidence yet (in observe
mode), direct it to hunt the foothold with the persistent foothold-revealing
sensors (`investigate_webshells`, `investigate_file_access`, `investigate_processes`)
— least-recently-used first — instead of settling into document-mode. Once a
hunt sensor surfaces the foothold, `_has_foothold()` flips True and the existing
HARDEN directive fires next turn.

## Non-goals / anti-goals

- **Not** auto-running sensors (approach B): blue stays the decider; we fix the
  guidance, not remove the choice.
- **Not** making the process snapshot continuous (approach C): a separate
  robustness item, logged as a follow-up.
- No change to non-observe behavior (confirmed → RESPOND/contain there), to the
  TRIAGE/MONITOR paths, or to scoring.

## Approaches considered

- **A — doctrine/triage HUNT nudge (CHOSEN).** A guidance branch that fires when
  confirmed-but-no-foothold, directing the foothold sensors. Smallest change,
  fits the existing triage-guidance pattern, keeps blue deciding.
- **B — auto-run a foothold sweep.** Reliable but removes agency; against the
  project's "agent reasons and generalizes" principle. Rejected.
- **C — reliable process capture** (continuous/pid-watch). Real but narrower
  robustness fix; doesn't help if blue never runs the right sensor. Deferred.

## The how (decided)

In `src/agents.py`:

1. **New constant `BLUE_FOOTHOLD_HUNT = ["investigate_webshells",
   "investigate_file_access", "investigate_processes"]`** — the sensors whose
   evidence reveals a landed foothold (webshell process/file baseline-diff; flag
   atime; live ps). Ordered webshells-first (holds the web-RCE evidence blue
   skipped).

2. **New helper `_foothold_hunt_exhausted(self) -> bool`** — True when every
   sensor in `BLUE_FOOTHOLD_HUNT` is in `self._tools_used()`.

3. **New HUNT guidance branch in `tool_guidance`**, placed immediately before the
   `ATTRIBUTE` block. Condition:
   `phase == "ATTRIBUTE" and observe and not self._has_foothold()
    and not self._foothold_hunt_exhausted()`.
   It directs the least-recently-used `BLUE_FOOTHOLD_HUNT` sensor not yet run
   (same LRU idiom as TRIAGE/MONITOR), with text: the scanner is confirmed but no
   foothold is pinned yet — hunt it with `<sensor>` before concluding. When the
   hunt is exhausted and still nothing, it falls through to ATTRIBUTE unchanged.

## What's left to the builder

- Exact HUNT guidance wording.
- Whether `investigate_processes` stays in the hunt list given it's the weak
  snapshot sensor — keep it (it's harmless and occasionally catches a live
  command), builder's call documented inline.

## Verification

- Unit: with a confirmed attacker, observe mode, no foothold, and
  `investigate_webshells` not yet run, `tool_guidance` names `investigate_webshells`
  (not the ATTRIBUTE document text).
- Unit: once all `BLUE_FOOTHOLD_HUNT` sensors have run with still no foothold,
  `tool_guidance` returns the ATTRIBUTE document text (hunt exhausted, no loop).
- Unit: when `_has_foothold()` is already True, HUNT does not fire (HARDEN owns
  it) — regression guard.
- Regression: full suite green; TRIAGE/MONITOR/IDENTIFY/RESPOND unchanged.
- Live (optional, after merge): earned+observe episode where red takes a web-RCE
  foothold → blue now runs `investigate_webshells`, finds it, and fires the
  surface close.
