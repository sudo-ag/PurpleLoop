"""Task 1: remediate_finding — general, reversible vector-closer.

Closes an escalation-sensor finding's privesc hole (chmod go-w / strip SUID)
WITHOUT banning the attacker, records the path's original mode+owner for reset
to revert, and fails safe.
"""
from unittest.mock import MagicMock
from src.executor import ToolExecutor


def _executor():
    return ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)


def test_writable_finding_is_chmod_go_w():
    ex = _executor()
    # stat(original) -> apply(chown+chmod) -> stat(verify)
    ex.execute = MagicMock(side_effect=["775 lando_calrissian devs", "PL_OK", "755 root root"])
    r = ex.remediate_finding({"category": "writable", "item": "/opt/sinatra"})
    assert r["status"] == "closed"
    applied = ex.execute.call_args_list[1].args[0]
    assert "chmod go-w /opt/sinatra" in applied
    assert ex.hardenings == [
        {"path": "/opt/sinatra", "original_mode": "775", "original_owner": "lando_calrissian", "original_group": "devs"}
    ]


def test_suid_finding_strips_suid_bit():
    ex = _executor()
    ex.execute = MagicMock(side_effect=["4755 root root", "PL_OK", "755"])
    r = ex.remediate_finding({"category": "suid", "item": "/usr/bin/odd"})
    assert r["status"] == "closed"
    applied = ex.execute.call_args_list[1].args[0]
    assert "chmod u-s /usr/bin/odd" in applied


def test_owner_writable_requires_chown():
    # A path red's own account owns: chmod go-w alone leaves owner write, so the
    # writable fix must also chown root. Verify re-stat shows root ownership.
    ex = _executor()
    ex.execute = MagicMock(side_effect=["775 lando_calrissian devs", "PL_OK", "755 root root"])
    r = ex.remediate_finding({"category": "writable", "item": "/opt/app"})
    assert r["status"] == "closed"
    applied = ex.execute.call_args_list[1].args[0]
    assert "chown root" in applied


def test_protected_path_is_refused():
    ex = _executor()
    ex.execute = MagicMock()
    r = ex.remediate_finding({"category": "writable", "item": "/etc"})
    assert r["status"] == "refused"
    ex.execute.assert_not_called()
    assert ex.hardenings == []


def test_unsupported_category():
    ex = _executor()
    ex.execute = MagicMock()
    r = ex.remediate_finding({"category": "scheduled", "item": "/x"})
    assert r["status"] == "unsupported"
    ex.execute.assert_not_called()


def test_failed_chmod_is_error_not_closed():
    # Verify re-stat still shows a non-root owner / writable bits -> fix failed.
    ex = _executor()
    ex.execute = MagicMock(side_effect=["775 lando_calrissian devs", "PL_OK", "775 lando_calrissian devs"])
    r = ex.remediate_finding({"category": "writable", "item": "/opt/app"})
    assert r["status"] == "error"
    assert ex.hardenings == []


def test_idempotent_reclose():
    # Already root-owned, no group/other write -> already closed, no action, no
    # hardenings entry (nothing to revert).
    ex = _executor()
    ex.execute = MagicMock(side_effect=["755 root root"])
    r = ex.remediate_finding({"category": "writable", "item": "/opt/app"})
    assert r["status"] == "closed"
    assert ex.hardenings == []


def test_malformed_finding_is_error():
    ex = _executor()
    ex.execute = MagicMock()
    r = ex.remediate_finding({"category": "writable"})  # no item
    assert r["status"] == "error"
    ex.execute.assert_not_called()
