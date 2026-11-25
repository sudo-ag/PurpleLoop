# Windows Failure Map — first WinRM episode on `.17`

Date: 2026-11-24
Source: 1 observed episode, `glm-5.3-flash:cloud` both sides, WinRM→`.17` jump-routed through `.11`.
Command: `--host 192.168.64.17 --jump-host 192.168.64.11 --transport winrm --observe --no-reset --objective root`.

## Headline

The transport works: the agents **reach** a Windows box. Episode completed clean
(exit 0, no crash, 0 SSH drops, 1 raw `WINRM_ERR`). Outcome: winner *none*, red
*blocked*, blue *missed*. Models correctly stamped (`red_model`/`blue_model` =
glm both).

**The important finding: blue doesn't error on Windows — it goes SILENTLY BLIND.**
Every Linux sensor "ran" and returned CLEAN / empty / unavailable because its
Linux assumptions produce nothing on Windows. Blue then concludes the box is
clean. A false-clean is worse than a loud failure, and it is the exact problem
the next project (agent environment self-checker) must solve: blue needs to *know*
its sensors are blind here, not report all-clear.

## Sensor-by-sensor (what blue got on Windows)

| Sensor | Linux assumption | Windows result | Failure type |
|--------|------------------|----------------|--------------|
| `investigate_logs` | `/var/log/auth.log` | total_events 4, **parsed_events 0** | parses to nothing |
| `investigate_connections` | conntrack/iptables logging | **logging_active false**, 0 connections | capability absent |
| `investigate_file_access` | `/root/flag.txt`, stat/owner | **file_exists false**, owner "cannot" | Linux path/owner model |
| `investigate_resident_foothold` | `who`/session parse | **CLEAN** (empty) | silent empty |
| `investigate_webshells` | Linux webroot diff | **webroot_unavailable true** | path absent |
| `investigate_processes` | `ps aux` | **total_processes 0** (`ps` → `WINRM_ERR`) | command not found |
| `investigate_persistence` | `authorized_keys` baseline | **baseline_unavailable true** | artifact absent |

All 7 sensors blue reached failed the same way: no exception, just no signal.

## What this tells the next project (self-checker)

1. **Blue must detect OS/environment first** and know which sensors are
   meaningful. On Windows, every sensor above should say "not applicable here,"
   not "CLEAN."
2. **The Windows equivalents to port** (in rough priority, from what blue reached
   for): processes (`Get-Process`/`tasklist`), logins/auth (Security Event Log
   4624/4625), persistence (Run keys, scheduled tasks, services), network
   (`Get-NetTCPConnection`), file/flag access (NTFS ACLs + Event Log 4663).
3. **Red was "blocked"** — on a vanilla Windows box with a handed low-priv cred,
   glm-red had no Linux-shaped foothold play; Windows attack doctrine is its own
   later project.

## Transport notes (for reuse)

- Jump-routed WinRM via `.11` (native ARM Kali, pywinrm 0.5.0, transport `ntlm`).
- `scripted_reset` is Linux/SSH — a WinRM box needs `--no-reset` (or a Windows
  reset path later).
- pywinrm on `.11` is provisioned ad-hoc (`pip3 --user`); a fresh jump box needs
  that one install before WinRM episodes run.
