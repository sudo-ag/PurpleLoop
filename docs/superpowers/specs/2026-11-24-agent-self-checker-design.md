# Design: Agent Environment Self-Checker (detect + relabel)

Date: 2026-11-24
Status: APPROVED (2026-11-24) — detect + relabel, active-probe detection, dispatch-level guard
Spec input: `docs/windows-failure-map-2026-11-24.md`

## Intent / why

The first WinRM episode showed blue's Linux sensors going **silently blind** on
Windows — each returned CLEAN/empty, so blue concluded the box was clean. A
false-clean is worse than a loud failure. This project makes blue **discover its
environment** and honestly report that its sensors don't apply, instead of
all-clear. It's the north-star "drop them anywhere" move: the agent adapts from
what it finds, not from what we told it.

## Goals

1. The executor **detects the target OS** by active probe (not by being told),
   cached once per episode.
2. A new blue tool `investigate_environment` surfaces the detected OS/shell;
   blue is steered to run it first.
3. Linux-only sensors return `{"status": "not_applicable", "detected_os": ...}`
   on a non-Linux target — via **one dispatch-level guard**, not 14 edited
   methods — so blue's verdict reflects "can't assess Windows yet," not CLEAN.
4. Linux behavior is **unchanged** (detected_os == "linux" → every sensor runs
   as today). Full suite stays green (601 at start).

## Non-goals

- Porting any sensor to Windows (that's the next project).
- Making `TargetProfile.os` the source of truth — detection is by probe;
  the profile is at most a cross-check/fallback.
- Earned Windows foothold, red-side changes, multi-box.

## Anti-goals

- Editing each `investigate_*` body (not DRY — one guard instead).
- Any change to blue's verdict logic beyond the relabel + the env-check steer.
- Regressing the Linux path or the suite.

## Approaches

**Detection — A. read `TargetProfile.os` (rejected as source).** Cheap but
*told*; blind on an unconfigured box. Kept only as a fallback if the probe is
inconclusive.
**Detection — B. active probe (chosen).** Run `uname -s` via the executor:
`Linux`/`Darwin` → that OS; anything else (Windows `uname` → `WINRM_ERR` /
"not recognized") → `windows`. Only linux/windows targets exist, so one probe
disambiguates. Discovered, works with no profile.

**Relabel — A. per-sensor guard (rejected).** Edit 14 methods; repetitive,
error-prone. **B. dispatch-level guard (chosen).** One check where blue's tool
calls are routed to executor `investigate_*` methods: if the called sensor is in
`LINUX_ONLY_SENSORS` and `detected_os != "linux"`, return the not_applicable
dict without running it.

## The how (decided)

- `ToolExecutor.detected_os` — lazy: first access runs `_detect_os()`
  (`uname -s` via `execute`), caches `"linux"` / `"windows"`. Reset with the
  analysis window (per episode).
- `ToolExecutor.investigate_environment()` → `{"tool": "investigate_environment",
  "detected_os": ..., "probe": <raw>, "summary": ...}`.
- `agents.py`: register `investigate_environment` in blue's tool list; the blue
  tool-steering hook (~`:1020`) nudges it as the first move when it hasn't run;
  the dispatch guard (where blue tool calls invoke executor methods) returns
  not_applicable for a `LINUX_ONLY_SENSORS` member on a non-linux target.
- `LINUX_ONLY_SENSORS` = every `investigate_*` except `investigate_environment`
  (all shell Linux commands today).

## Verification

- Unit: `_detect_os` → "windows" when probe lacks "Linux"; "linux" when it has
  it. Dispatch guard returns not_applicable for a linux-only sensor when
  detected_os="windows", and runs normally when "linux". `investigate_environment`
  returns the detected os.
- Regression: full suite green; a Linux (mock/`.12`) run behaves identically.
- Live: re-run the `.17` WinRM episode — sensors now report not_applicable and
  blue's narrative reflects "Windows, Linux sensors don't apply," not CLEAN.

## Left to the builder

- Exact probe string and parse.
- The precise dispatch point in `agents.py` for the guard, and how the steer
  marks "environment already checked."
