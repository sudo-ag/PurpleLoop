# Design: Windows WinRM Transport — the first "place anywhere" brick

Date: 2026-11-24
Status: APPROVED (2026-11-24) — B-lite plumbing (wire TargetProfile with os+transport) + pywinrm dependency

> **UPDATE (2026-11-24, during execution):** Task 1's live gate found the
> transport must be **jump-routed**, not direct. macOS Local Network entitlement
> blocks venv Python from *all* LAN hosts (confirmed: `.11:22`/`.12:22`/`.17:5985`
> all `Errno 65`, while system `ssh`/`curl` work — the exact reason `executor.py`
> shells out to the system `ssh` binary). So the WinRM call runs **on the Kali
> jump `.11`** (native ARM, reaches `.17:5985`) via the existing entitled
> ssh-to-jump channel. `pywinrm` lives on `.11` (pip, provisioned), NOT in the Mac
> venv. Transport confirmed: `ntlm`, `.11`→`.17` whoami = `desktop-mp2vnf8\vagrant`.
> `_run_winrm` ships a tiny runner to `.11` and invokes it over SSH.

## Intent / why

PurpleLoop's agents are the portable product; the box is the dojo. Today the
agents only reach *one kind* of box: the executor speaks SSH + bash, and every
blue sensor shells out a Linux command. To get the agents toward "drop them
anywhere," we start shedding the dojo-tuned assumptions — and the first and most
fundamental is the **transport**: how the executor reaches a target at all.

We have a Windows box on the UTM network (`192.168.64.17`, Vagrant,
`vagrant`/`vagrant`) exposing **WinRM (5985), SMB, RDP, RPC — and no SSH**. That
is exactly how a real Windows box (incl. WRCCDC competition boxes) exposes
itself. So WinRM is not a dojo shortcut; it's the honest Windows transport, and
building it is the first real "Windows capability" brick.

This brick does **not** try to make the agents *good* on Windows. It makes them
*reach* Windows, then runs one episode and captures the **failure map** — which
sensors error, what red does with no bash — which is the real input to the later
sensor-porting project.

## Goals

1. The executor can run an arbitrary command on `.17` via WinRM, authenticated
   with a handed credential, and return its stdout/stderr. Proven by a test.
2. Transport is **selectable per target**: SSH (default) or WinRM, chosen from the
   target's profile. The agent brain and the sensor call sites are unchanged —
   they still call `executor.execute(cmd)`.
3. One **observed episode** runs against `.17` and produces a documented failure
   map (sensor-by-sensor: errored / empty / usable).
4. The existing Linux SSH path is **byte-for-byte unchanged**; all 593 tests stay
   green.

## Non-goals (explicitly out of this brick)

- Porting any blue sensor to Windows (Event Logs / `Get-Process` / registry). The
  point is to watch them fail.
- Earned Windows foothold / credential cracking. We use a **handed** cred.
- Multi-box topology, pivoting, host-to-host correlation.
- Red Windows attack doctrine / Windows persistence vectors.
- WinRM over HTTPS (5986), Kerberos, or domain auth. Local account over 5985.
- **Agent environment self-detection** (the agent probing "what OS/shell am I on?"
  and adapting its own commands). Deliberately deferred — see Next project.

## Next project (captured, not built here)

**Agent self-checker / environment detection.** The agent discovers what it's
operating on (OS, shell, available tooling) and adapts, instead of being told via
`TargetProfile`/`env_notes`. This is the north-star move that lets us stop
hand-configuring boxes ("drop them anywhere"). Its **spec is this brick's failure
map** — we design the checker from the measured list of what breaks on Windows,
not from a guess. Sequencing: this brick (measure the flail) → self-checker
(adapt from the measurement) → sensor generalization. Keeping the checker out of
this brick preserves the one clean measurement it exists to produce.

## Anti-goals (failure even if it "works")

- Installing OpenSSH on `.17` to dodge WinRM. That re-tunes the box to the tool
  and destroys the thing that makes it representative. SSH stays available for
  boxes that *have* it; we do not add it to Windows.
- Touching the agents' prompts/doctrine. If the brick needs a prompt change to
  function, the transport abstraction is wrong.
- Regressing the Linux path or the test suite.

## Constraints

- **New dependency: `pywinrm`** (pure-python WinRM client). Needs the user's
  explicit OK (CLAUDE.md: ask before adding deps / touching the lockfile). It
  pulls `requests` (already a dep) + `requests_ntlm`/`pyyaml`.
- **Credentials never hit the repo.** `vagrant/vagrant` is a local sandbox cred;
  it lives in an env var / local profile, not a committed file. `.17` creds are
  read the same way the Linux `--pwd` is today.
- macOS / Apple Silicon host; `.17` is an emulated x86 Windows guest.
- WinRM default on Vagrant Windows boxes: HTTP 5985, Negotiate/NTLM, basic often
  enabled. The builder confirms the exact auth transport against the live box.

## Approaches (transport selection)

The transport swap has one clean insertion point: `execute_remote()`. The open
question is **how the executor learns which transport to use** — and that pulls
in the half-wired `TargetProfile`.

**A. Minimal — `transport` kwarg, defer TargetProfile.**
Add `transport: str = "ssh"` to `ToolExecutor.__init__`; `execute_remote`
branches to `_run_winrm()` when `transport == "winrm"`. The arena points at
Windows via a new CLI flag (e.g. `--target-os windows`). `TargetProfile` stays
unwired.
*Trades:* smallest diff, fastest to the failure map. But it adds yet another
loose arg to an already-loose plumbing chain and leaves the "place anywhere"
seam (`TargetProfile`) still vestigial — we'd re-do this wiring for box #3.

**B. Proper — wire `TargetProfile` as the single source of per-box truth.**
Extend `TargetProfile` with `os`, `transport`, and a cred reference; construct it
in `run_episodes`; thread it into `build_agents` → `ToolExecutor`. The executor
reads transport/os from the profile.
*Trades:* more wiring now (touches run_episodes, build_agents, executor, and the
test callers), but it's the generalization seam the whole vision needs, and the
next box (Windows #2, Linux #2, a comp box) becomes "add a profile," not "add a
flag." Higher up-front cost, far lower marginal cost per future box.

**C. (rejected) Separate `WindowsExecutor` class.**
`ToolExecutor` is 1000+ lines fusing transport *and* all the blue sensors. A
parallel class either duplicates the sensor baggage or forces a premature base
class. Rejected: the sensors are shared; only the transport differs.

**Recommendation: B-lite.** Do B's `TargetProfile` wiring, but keep the extension
minimal — add exactly `os` and `transport` (+ cred passed as today), construct one
profile per run, and have `build_agents` read transport from it. Skip any profile
field a future project doesn't need yet. This pays down the vestigial-seam debt
*in the direction the vision is already going*, without gold-plating the profile.
The extra cost over A is ~one constructor + threading through two functions whose
signatures we already touched this week for the model split.

> **Decision for the user (theirs):** A (fastest, re-do later) vs **B-lite
> (recommended)** vs full B. This changes how much plumbing the brick includes.

## The how (decided parts)

- **Insertion point:** `execute_remote()` dispatches on transport. SSH path
  untouched. `_run_winrm(command)` is the new sibling of `_run_session`.
- **`_run_winrm`:** via `pywinrm` (`Session`/`Protocol`). Runs the command string
  as given (cmd or PowerShell — builder picks the shell that best mirrors what a
  foothold shell would be; likely `run_ps` so Windows-native commands are at
  least expressible). Returns stdout, or stderr prefixed as an error, matching
  `execute_remote`'s existing string contract. No bash→PowerShell translation —
  blue's Linux commands are *meant* to fail here (the failure map).
- **`connect()` / jump / ControlMaster:** no-ops for WinRM (stateless HTTP;
  pywinrm handles its own session). `_master_alive` short-circuits true.
- **`_check_forbidden`:** keep the existing Linux guards; they're harmless on
  Windows (no false hits) for this brick. A Windows-specific guard list is a
  later concern.
- **Credential:** handed via the profile/env (`vagrant`/`vagrant` for `.17`).
  `set_target_credential` (earned, uses `id -un`) is **not** on this path and is
  left untouched; Windows earned-cred is a later project.
- **Observed episode:** blue runs with the handed cred (require_foothold=False);
  red is **handed** the same cred for this one episode so it actually acts on the
  box and we watch its bash fail (more informative than red stuck at
  no-foothold). This is a run-config choice, not code.

## Verification

- Unit: `_run_winrm` runs a command and returns output — mocked pywinrm
  Session (no live box in CI). Asserts transport dispatch: `transport="winrm"`
  routes to `_run_winrm`, `"ssh"` routes to the SSH path.
- Live smoke (manual, not CI): `execute("whoami")` / `execute("Get-Process")`
  against `.17` returns real output. **This is the first implementation step** —
  if `vagrant/vagrant` over 5985 won't auth, the approach is revisited before
  anything else is built.
- Regression: full suite stays 593 green; the Linux live path unchanged.
- The failure map from the observed episode is written up (sensor-by-sensor).

## Left to the builder

- Exact `pywinrm` API shape and the auth transport that works against this
  Vagrant box (Negotiate vs NTLM vs basic over 5985).
- Output normalization: WinRM returns structured stdout/stderr + return code;
  map to the single-string contract `execute_remote` callers expect.
- Whether the command runs via `run_cmd` or `run_ps` for the smoke step.
- Minimal `TargetProfile` field types and where the run constructs it.
