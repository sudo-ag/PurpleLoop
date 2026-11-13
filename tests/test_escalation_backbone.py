"""Escalation deviation backbone: SUID provenance, package integrity, GTFOBins."""
from src.escalation import (
    GTFOBINS,
    parse_suid,
    parse_owned_paths,
    flag_suid,
    parse_package_integrity,
)


def test_parse_suid_extracts_paths():
    out = "/usr/bin/passwd\n/usr/bin/sudo\n/opt/weird/backdoor\n"
    assert parse_suid(out) == ["/usr/bin/passwd", "/usr/bin/sudo", "/opt/weird/backdoor"]


def test_flag_suid_skips_normal_owned_binary():
    owned = {"/usr/bin/passwd"}
    assert flag_suid(["/usr/bin/passwd"], owned, GTFOBINS) == []


def test_flag_suid_flags_unowned_binary():
    res = flag_suid(["/opt/weird/backdoor"], owned=set(), gtfobins=GTFOBINS)
    assert len(res) == 1
    assert res[0]["why"] == "unowned-suid" and res[0]["item"] == "/opt/weird/backdoor"


def test_flag_suid_flags_gtfobins_shellable_even_if_owned():
    owned = {"/usr/bin/find"}
    res = flag_suid(["/usr/bin/find"], owned, GTFOBINS)  # find IS a GTFOBins shell-spawner
    assert res and res[0]["why"] == "gtfobins-shellable"


def test_gtfobins_contains_known_shell_spawners():
    assert {"find", "vim", "nmap", "bash"} <= GTFOBINS


def test_parse_package_integrity_flags_hash_delta_only():
    # dpkg -V: leading cols, "5" = md5 mismatch; "c" marks a conffile (not a delta here)
    out = "??5??????   /usr/bin/tampered\n??????????  c /etc/some.conf\n"
    res = parse_package_integrity(out)
    assert len(res) == 1
    assert res[0]["item"] == "/usr/bin/tampered" and res[0]["why"] == "hash-delta"


def test_parse_owned_paths_reads_dpkg_search():
    out = "coreutils: /usr/bin/ls\ndpkg-query: no path found matching /opt/x\n"
    owned = parse_owned_paths(out)
    assert "/usr/bin/ls" in owned and "/opt/x" not in owned
