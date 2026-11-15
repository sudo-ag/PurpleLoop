"""Fix-pass from the final review: guard-safe provenance (C1/C2), partial-clean
(I1), per-category cap (I2), real systemd/@reboot parsing (I3/I4), mode-change (I6)."""
from src.escalation import parse_scheduled, parse_package_integrity
from src.executor import ToolExecutor

END = "__PL_END__"


def _ex(outputs):
    ex = ToolExecutor(host="mock", user="u", pwd="p")
    ex.execute_calls = []

    def fake(cmd, *a, **k):
        ex.execute_calls.append(cmd)
        for key, val in outputs.items():
            if key in cmd:
                return val
        return END
    ex.execute = fake  # type: ignore[method-assign]
    return ex


# --- parser fixes ---------------------------------------------------------

def test_systemd_execstart_struct_format_is_parsed():  # I3
    unit = "ExecStart={ path=/opt/maint/clean.sh ; argv[]=/opt/maint/clean.sh --f ; ignore=no }\n"
    res = parse_scheduled("", unit)
    assert any(f["item"] == "/opt/maint/clean.sh" for f in res)


def test_cron_at_reboot_root_line_is_parsed():  # I4
    res = parse_scheduled("@reboot root /opt/boot/init.sh\n", "")
    assert any(f["item"] == "/opt/boot/init.sh" and f["principal"] == "root" for f in res)


def test_package_integrity_flags_mode_change_too():  # I6
    out = "??5??????   /usr/bin/a\n??M??????   /usr/bin/b\n"
    whys = {f["item"]: f["why"] for f in parse_package_integrity(out)}
    assert whys.get("/usr/bin/a") == "hash-delta"
    assert whys.get("/usr/bin/b") == "mode-change"


# --- sensor fixes ---------------------------------------------------------

def test_passwd_suid_is_kept_out_of_the_provenance_command():  # C1
    ex = _ex({"4000": "/usr/bin/passwd\n/opt/x\n" + END})  # passwd would trip FORBIDDEN_KEYWORDS
    ex.investigate_escalation_paths()
    prov_cmds = [c for c in ex.execute_calls if "dpkg -S" in c]
    assert prov_cmds and not any("passwd" in c for c in prov_cmds)


def test_provenance_command_is_guarded_against_missing_dpkg():  # C2
    # Without `command -v dpkg`, a missing dpkg returns "" (not __PL_ABSENT__),
    # so provenance reads as "ran, nothing owned" and every SUID false-flags.
    ex = _ex({"4000": "/opt/x\n" + END})
    ex.investigate_escalation_paths()
    prov = [c for c in ex.execute_calls if "dpkg -S" in c]
    assert prov and "command -v dpkg" in prov[0]


def test_per_category_findings_are_capped():  # I2
    many = "\n".join(f"/opt/w/f{i}" for i in range(300)) + "\n" + END
    res = _ex({"0002": many}).investigate_escalation_paths()
    assert len(res["categories"]["writable"]["findings"]) <= 100


def test_scheduled_partial_failure_is_not_false_clean():  # I1
    ex = _ex({"systemctl": ""})  # systemd source fails (no sentinel) -> unavailable
    res = ex.investigate_escalation_paths()
    assert res["categories"]["scheduled"]["status"] == "unavailable"
