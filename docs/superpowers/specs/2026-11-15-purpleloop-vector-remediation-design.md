# PurpleLoop — Vector-Specific Remediation (the paintball arms race)

Design doc. Status: draft for approval. Date: 2026-11-15.
Finding (c) from the 2026-11-15 learning-loop diagnostic.

## Intent / why

Today blue's only ways to stop red are **blunt neutralizers** — ban the
attacker IP (`contain_attacker`) or lock the foothold account
(`remediate_account`). Both end red's access entirely, so the arms race the
diagnostics produced is *detect-faster ↔ evade-detection*: red isn't forced to
find a **new vulnerability**, it's just locked out or pushed toward stealth.

The goal is the **vector-exhaustion** loop the project owner described as
paintball: when blue stops red, red is **marked** (blue scores the stop) but
**not banned** — it returns to base and must try a **different vector**. Red
should *recognise* its path was closed ("that didn't work, what next?") and
pivot, keeping the loop live, until red runs out of vectors (blue wins the box)
or finds one blue hasn't learned to close.

This is the **active-assessor / remediator** end-state from the vision doc:
blue closes the specific hole, not the attacker.

## Goals

- Blue can **close a specific vulnerability** red is using (not ban the attacker)
  via one **general** capability keyed on sensor findings — portable to any host.
- When blue closes red's current vector, **red stays connected**, detects the
  path is dead, and **pivots to a different vector** within the same episode.
- Blue closing a vector before red reaches the objective scores as a **stop**;
  "blue hardened the box until red ran out of vectors" reads as a blue win.
- The hardening doctrine blue learns is **portable** (built on finding (b)): a
  lesson is "harden world-writable service dirs," not "chmod /opt/sinatra."

## Non-goals

- Persisting hardening in the box across episodes (the box MUST reset to its
  vulnerable baseline each episode — the dojo stays attackable; the arms race
  lives in blue's knowledge, re-applied each episode, not in box state).
- Service-level vectors (Drupal RCE → disable the service) in v1 — their fixes
  are messier and less general; escalation-type vectors first.
- Replacing `contain_attacker` / `remediate_account` — they stay for the
  real-deployment "hard stop" mode; vector-closing is the new, additional,
  paintball-mode response.
- Changing the no-seeding rule or red's offense tooling.

## Anti-goals (would make this a failure even if it "works")

- A per-vector hardcoded fix table that only works on Metasploitable3 (violates
  the Swiss-army-knife north-star).
- A loop that looks built but doesn't loop because red thrashes instead of
  pivoting — this is the known top risk and the reason for the phased build.
- Blue's hardening leaking into the next episode's baseline, silently draining
  the dojo of vectors.

## Constraints

- **Reset must revert hardening.** `scripted_reset` currently does NO file-mode
  restoration, so a blue `chmod` would persist. Reset must restore the
  vulnerable baseline for every path blue can harden (same spirit as its
  existing `/etc/passwd` baseline restore). Dojo-side config, not agent logic.
- **Fixes are read-bounded + reversible + fail-safe**, like the existing
  response tools; each must pass `FORBIDDEN_KEYWORDS` and refuse to touch the
  defender/host (no chmod of `/`, `/etc`, control-account paths).
- **General, finding-driven.** The fix is chosen by finding *category* +
  *path* from the escalation sensor, never by a box-specific name.
- **No new hard dependency**; reuse the ② case engine (blue already identifies
  the vector) and the escalation sensor (already emits path-carrying findings).

## Approaches considered

1. **Reactive close + cross-episode pivot.** Blue gets `remediate_finding`;
   closes the vector it has a finding for; the pivot is carried only by the
   between-episode learning loop. Smallest, but the pivot is slow (one vector
   per episode) and never shows the within-episode paintball feel.
2. **Proactive assessor.** Blue pre-hardens known-dangerous findings at episode
   start before red arrives. Powerful, but a bigger first bite and it hides the
   reactive close/pivot dynamic we most want to prove.
3. **Full within-episode arms race (CHOSEN).** Reactive close + red pivots to a
   new vector mid-episode + blue closes that too, several rounds per episode.
   Richest, closest to live paintball. Gated on red's mid-episode pivot being
   reliable — which the diagnostics show is shaky.

**Chosen: Approach 3, built in two de-risked phases** (owner's call). Approach 3
strictly contains Approach 1, so Phase A builds the foundation and *proves the
pivot fires live* before Phase B layers on the multi-round loop. Approach 2
(proactive assessor) is a later follow-on, not a prerequisite.

**v1 scope confirmed (owner):** the paintball loop runs at the **privilege-
escalation stage** — red keeps its foothold; blue closes the *privesc* vector
red is using (writable / SUID), forcing red to a different privesc path. Closing
the *foothold* vector (SSH brute, web RCE — a non-`chmod` fix set) is a later
extension, not v1. Foothold neutralisation stays with the existing
`remediate_account`.

## The design

### Phase A — foundation (build + prove the pivot)

1. **`remediate_finding(finding)` — general vector-closer (new blue tool).**
   - Input: one escalation-sensor finding (`{category, item, ...}`).
   - Category → portable fix (v1 scope):
     - `writable` → `chmod go-w <item>` (strip non-owner write).
     - `suid` → `chmod u-s <item>` (strip the SUID bit).
     - `sudo` / group-based escalation → reuse existing `revoke_escalation`.
     - other categories (`scheduled`, `capability`) → report `unsupported`
       (fail-safe, no action) in v1.
   - **No ban.** Reversible. Refuses defender/host paths (`/`, `/etc`, the
     control account's home, anything owned by the control user). Fail-safe:
     a fix that errors returns `status: error`, never a false "closed."
   - Idempotent: re-closing an already-closed finding is a no-op success.

2. **Reactive close wiring.** Blue, having identified the vector via the ②
   case engine (its leads already carry the finding), calls `remediate_finding`
   on it. Doctrine line: when a lead points at a closeable finding and the
   attacker is active, close the finding rather than (or before) banning.

3. **Red feedback + pivot doctrine.** Red must *notice* the close. Its exploit
   on the hardened path now fails where it worked (e.g. write → `Permission
   denied`, SUID gone). One red doctrine line: "a path that worked before but
   now fails the same way is a sign the defender hardened it — abandon that
   vector and try a *different* one; do not retry the dead path."

4. **Scoring — the "vector closed" stop.** Add a per-vector `stops` record to
   `SimulationState` (the finding/path + turn blue closed it). Referee: a close
   that lands before red reaches the objective via that vector counts as a
   **stop** (prevention-class, like contain). Existing tier/dwell outcome is
   unchanged; the scoreboard gains a "vectors stopped" line.

5. **Reset extension.** `scripted_reset` restores the vulnerable baseline for
   every hardenable path (re-add write bits / SUID bits the dojo intends),
   mirroring its `/etc/passwd` baseline pattern. Captured-once clean baseline of
   the target modes, re-applied each reset.

6. **Phase-A gate (live).** Run a diagnostic and confirm: blue closes a vector,
   red's next move on it fails, and **red pivots to a different vector** at least
   once. PASS → Phase B. FAIL → fix the pivot (feedback clarity / doctrine)
   before building further.

### Phase B — the within-episode arms race (after the gate passes)

7. **Multiple rounds per episode.** Nothing structural stops red from pivoting
   and blue from closing again within the turn budget; Phase B hardens that it
   *works repeatedly*: blue closes B after it closed A, red pivots to C, etc.,
   until the objective, vector exhaustion, or `max_turns`.

8. **Episode outcome for the loop.** "Red exhausted all vectors blue could close
   before reaching the objective" = blue win (prevention). "Red reached the
   objective via a vector blue could not close" = red win, with blue credited
   for the vectors it did stop. Dwell/tiers still reported.

9. **Phase-B gate (live).** A diagnostic shows ≥2 close→pivot rounds in a single
   episode and the scoreboard reflecting them.

## What's left to the builder

- Exact `remediate_finding` result schema (align with the other response tools'
  shape: `{tool, status, target, reversible, ...}`).
- Precise refusal set for defender/host-owned paths (reuse any existing
  path-safety helper in `executor.py`).
- Where the hardenable-path baseline for reset is captured (a one-time snapshot
  vs a static known-vector list) — prefer snapshot to stay box-agnostic.
- Scoreboard/verdict wording for stops and the exhaustion win.
- Whether `scheduled`/`capability` closers are added in v1 or deferred (default:
  deferred, reported `unsupported`).

## Verification

- Unit (TDD): category→fix mapping; defender-path refusal; fail-safe on error;
  idempotent re-close; reset re-vulnerabilises a hardened path; scoring records
  a stop and the exhaustion win.
- Live: the two phase gates above (pivot fires; multi-round loop runs).
