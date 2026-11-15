"""Pure parsers/classifiers for blue's escalation-paths posture sensor.

Each function turns the raw stdout of one read-only enumeration command into a
list of flagged `finding` dicts. "Known-good" is package provenance first (a
privileged binary owned by no package, or whose package hash deviated, is a
flag) — no distro allowlist, so this generalizes to any Debian/RPM host. The
tool only flags facts; blue chains them into privesc paths via the case engine.
"""
import re
from typing import Dict, List, Set

# Binaries that trivially spawn a shell when SUID/privileged (GTFOBins-style).
# Small, curated, distro-agnostic — a basename match is a flag on its own.
GTFOBINS: frozenset = frozenset({
    "find", "vim", "vi", "nmap", "bash", "sh", "less", "more", "man", "awk",
    "nano", "cp", "mv", "tar", "zip", "perl", "python", "python2", "python3",
    "ruby", "env", "ed", "ftp", "gdb", "make", "nc", "ncat", "socat", "tee",
    "dd", "sed", "wget", "curl", "lua", "node", "php", "rsync", "scp", "start-stop-daemon",
})

_DANGEROUS_CAPS = ("cap_setuid", "cap_setgid", "cap_dac_override",
                   "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace", "cap_chown")


def finding(category: str, item: str, principal: str, why: str, detail: str = "") -> Dict[str, str]:
    return {"category": category, "item": item, "principal": principal, "why": why, "detail": detail}


def parse_suid(find_output: str) -> List[str]:
    """The SUID/SGID file paths from `find` output (one path per line)."""
    return [ln.strip() for ln in find_output.splitlines() if ln.strip().startswith("/")]


def parse_owned_paths(dpkg_search_output: str) -> Set[str]:
    """Paths `dpkg -S` reports as package-owned. Lines like 'pkg: /path' yield the
    path; 'no path found matching /x' lines (no ': /') are skipped -> unowned."""
    owned: Set[str] = set()
    for ln in dpkg_search_output.splitlines():
        i = ln.find(": /")
        if i != -1:
            owned.add(ln[i + 2:].strip())
    return owned


def flag_suid(suid_paths: List[str], owned: Set[str], gtfobins: frozenset,
              check_provenance: bool = True) -> List[Dict[str, str]]:
    """Flag a SUID path when it can spawn a shell (GTFOBins basename) or is owned
    by no package. A normal, package-owned, non-GTFOBins binary is boring -> dropped.
    When provenance couldn't be read (`check_provenance=False`), only the GTFOBins
    check runs, so a missing package DB never false-flags every SUID as unowned."""
    out: List[Dict[str, str]] = []
    for path in suid_paths:
        base = path.rsplit("/", 1)[-1]
        if base in gtfobins:
            out.append(finding("suid", path, "any", "gtfobins-shellable",
                               f"SUID {base} can spawn a shell"))
        elif check_provenance and path not in owned:
            out.append(finding("suid", path, "any", "unowned-suid",
                               "SUID binary owned by no package"))
    return out


def parse_writable(find_output: str) -> List[Dict[str, str]]:
    """Writable paths (the `find` call already filtered to world/group-writable).
    Each carries its path so blue can match it to a scheduled-job lead."""
    out: List[Dict[str, str]] = []
    for ln in find_output.splitlines():
        p = ln.strip()
        if p.startswith("/"):
            out.append(finding("writable", p, "non-root", "world-or-group-writable",
                               "writable by a non-root principal"))
    return out


def parse_scheduled(cron_output: str, systemd_timer_output: str) -> List[Dict[str, str]]:
    """Root-run scheduled jobs. The finding's `item` is the executed file path —
    the SAME path a writable finding carries — so blue can chain the two."""
    out: List[Dict[str, str]] = []
    for ln in cron_output.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if parts[0].startswith("@"):
            # @reboot/@daily root /path ...
            if len(parts) >= 3 and parts[1] == "root" and parts[2].startswith("/"):
                out.append(finding("scheduled", parts[2], "root", "runs-as-root-scheduled", ln))
        elif len(parts) >= 7 and parts[5] == "root" and parts[6].startswith("/"):
            # 5 time fields, user, command...
            out.append(finding("scheduled", parts[6], "root", "runs-as-root-scheduled", ln))
    for ln in systemd_timer_output.splitlines():
        ln = ln.strip()
        if not ln.startswith("ExecStart="):
            continue
        rest = ln[len("ExecStart="):].strip()
        # real `systemctl show` format is "{ path=/x ; argv[]=... }"; also accept "/x --flag"
        m = re.search(r"path=(\S+)", rest)
        path = m.group(1) if m else (rest.split()[0] if rest else "")
        if path.startswith("/"):
            out.append(finding("scheduled", path, "root", "runs-as-root-scheduled", ln))
    return out


def parse_capabilities(getcap_output: str) -> List[Dict[str, str]]:
    """Files carrying a privilege-relevant capability (cap_setuid etc.), not every cap."""
    out: List[Dict[str, str]] = []
    for ln in getcap_output.splitlines():
        if " = " not in ln:
            continue
        path, caps = ln.split(" = ", 1)
        if any(c in caps for c in _DANGEROUS_CAPS):
            out.append(finding("capability", path.strip(), "any", "dangerous-capability", caps.strip()))
    return out


def parse_package_integrity(dpkg_verify_output: str) -> List[Dict[str, str]]:
    """Each `dpkg -V` line whose flag column carries a '5' (md5 mismatch) is a
    file that deviated from its package's known-good hash."""
    out: List[Dict[str, str]] = []
    for ln in dpkg_verify_output.splitlines():
        parts = ln.split()
        if not parts:
            continue
        flags = parts[0]
        if "5" in flags:
            out.append(finding("package_integrity", parts[-1], "root", "hash-delta",
                               "file deviates from its package's known-good hash"))
        elif "M" in flags:
            out.append(finding("package_integrity", parts[-1], "root", "mode-change",
                               "file mode deviates from its package (possible added SUID)"))
    return out
