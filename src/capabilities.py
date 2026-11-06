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
]
