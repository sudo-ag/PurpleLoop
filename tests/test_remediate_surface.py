"""Phase B: remediate_escalation_surface closes the WHOLE writable/SUID surface
in one call, so whatever vector red reaches for is already shut."""
from unittest.mock import MagicMock
from src.executor import ToolExecutor


def _executor():
    return ToolExecutor(host="192.168.64.10", user="vagrant", pwd="vagrant", timeout=30)


def test_surface_closes_all_writable_and_suid():
    ex = _executor()
    ex.investigate_escalation_paths = MagicMock(return_value={"categories": {
        "writable": {"status": "findings", "findings": [{"item": "/opt/sinatra"}, {"item": "/var/www"}]},
        "suid": {"status": "findings", "findings": [{"item": "/usr/bin/odd"}]},
        "scheduled": {"status": "unavailable", "findings": []},
    }})
    ex.remediate_finding = MagicMock(
        side_effect=lambda f: {"status": "closed", "target": f["item"], "category": f["category"]})
    r = ex.remediate_escalation_surface()
    assert r["tool"] == "remediate_escalation_surface"
    assert {c["item"] for c in r["closed"]} == {"/opt/sinatra", "/var/www", "/usr/bin/odd"}
    # every writable + suid finding was handed to remediate_finding
    assert ex.remediate_finding.call_count == 3


def test_surface_reports_skipped_not_closed():
    ex = _executor()
    ex.investigate_escalation_paths = MagicMock(return_value={"categories": {
        "writable": {"status": "findings", "findings": [{"item": "/etc"}]}}})
    ex.remediate_finding = MagicMock(
        return_value={"status": "refused", "target": "/etc", "category": "writable"})
    r = ex.remediate_escalation_surface()
    assert r["closed"] == []
    assert r["skipped"] and r["skipped"][0]["status"] == "refused"


def test_surface_empty_when_no_findings():
    ex = _executor()
    ex.investigate_escalation_paths = MagicMock(return_value={"categories": {
        "writable": {"status": "clean", "findings": []},
        "suid": {"status": "clean", "findings": []}}})
    ex.remediate_finding = MagicMock()
    r = ex.remediate_escalation_surface()
    assert r["closed"] == []
    ex.remediate_finding.assert_not_called()
