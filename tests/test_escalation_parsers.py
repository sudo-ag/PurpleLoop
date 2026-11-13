"""Writable / scheduled / capability parsers — path-carrying leads for chaining."""
from src.escalation import parse_writable, parse_scheduled, parse_capabilities


def test_parse_writable_carries_path_and_category():
    out = "/opt/backup/run.sh\n/tmp/x\n"  # find already filtered to writable paths
    res = parse_writable(out)
    assert any(f["item"] == "/opt/backup/run.sh" and f["category"] == "writable" for f in res)


def test_parse_scheduled_extracts_executed_path_for_chaining():
    cron = "*/5 * * * * root /opt/backup/run.sh\n"
    res = parse_scheduled(cron, "")
    assert len(res) == 1
    assert res[0]["item"] == "/opt/backup/run.sh"
    assert res[0]["principal"] == "root" and res[0]["category"] == "scheduled"


def test_scheduled_and_writable_share_the_item_path_so_blue_can_chain():
    path = "/opt/backup/run.sh"
    w = parse_writable(path + "\n")
    s = parse_scheduled("*/5 * * * * root " + path + "\n", "")
    assert w[0]["item"] == s[0]["item"] == path


def test_parse_scheduled_reads_systemd_execstart():
    unit = "ExecStart=/opt/maint/clean.sh --flag\n"
    res = parse_scheduled("", unit)
    assert any(f["item"] == "/opt/maint/clean.sh" for f in res)


def test_parse_capabilities_flags_setuid_capability_only():
    out = "/usr/bin/odd = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n"
    res = parse_capabilities(out)
    items = {f["item"] for f in res}
    assert "/usr/bin/odd" in items and "/usr/bin/ping" not in items
