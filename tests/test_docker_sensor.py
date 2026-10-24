"""Docker posture sensor (investigate_docker) — MITRE T1611 container escape.

Fixtures mirror REAL `docker inspect` records captured from the target box:
the breakout residue (`/:/mnt` bind, `cat /mnt/root/flag.txt`) and the benign
baseline service container (`7_of_diamonds`, bridge net, no mounts).
"""
import json
from src.executor import ToolExecutor
from src.mock_executor import MockExecutor


def _ex() -> ToolExecutor:
    return ToolExecutor(host="mock", user="u", pwd="p")  # __init__ does not connect


def _rec(name, *, binds=None, mounts=None, privileged=False, net="default",
         pid="", ipc="shareable", userns="", path="/bin/sh", args=None, state="exited",
         started_at="2026-10-15T22:53:20.5Z"):
    return {
        "Name": f"/{name}", "Config": {"Image": "ubuntu"}, "Image": "sha256:x",
        "State": {"Status": state, "StartedAt": started_at}, "Path": path, "Args": args or [],
        "HostConfig": {"Binds": binds, "Privileged": privileged, "PidMode": pid,
                       "NetworkMode": net, "IpcMode": ipc, "UsernsMode": userns},
        "Mounts": mounts or [],
    }


OBJ = "/root/flag.txt"
BREAKOUT = _rec("pl_x", binds=["/:/mnt"], mounts=[{"Source": "/", "Destination": "/mnt"}],
                path="cat", args=["/mnt/root/flag.txt"])
BASELINE = _rec("7_of_diamonds", binds=None, mounts=[], net="bridge",
                path="/bin/bash", state="running")


# --- parser: the two real shapes ------------------------------------------

def test_host_root_bind_reaching_objective_is_a_breach():
    out = _ex()._parse_docker([BREAKOUT], OBJ)
    assert out["flag_access_detected"] is True
    assert out["assessment"] == "BREACH"
    assert out["escape_capable_count"] == 1
    c = out["containers"][0]
    assert c["reaches_objective"] and c["escape_capable"]
    assert "cat /mnt/root/flag.txt" in c["command"]


def test_baseline_service_container_is_not_flagged():
    out = _ex()._parse_docker([BASELINE], OBJ)
    assert out["assessment"] == "CLEAN"
    assert out["flag_access_detected"] is False
    assert out["containers"] == []


def test_breakout_alongside_baseline_reports_only_the_breakout():
    out = _ex()._parse_docker([BASELINE, BREAKOUT], OBJ)
    assert out["escape_capable_count"] == 1
    assert out["containers"][0]["name"] == "pl_x"
    assert out["flag_access_detected"] is True


# --- parser: posture without reaching the objective -> SUSPICIOUS, no credit

def test_privileged_container_is_escape_capable_but_not_a_breach():
    rec = _rec("priv", mounts=[], privileged=True)
    out = _ex()._parse_docker([rec], OBJ)
    assert out["assessment"] == "SUSPICIOUS"
    assert out["flag_access_detected"] is False
    assert out["containers"][0]["privileged"] is True


def test_host_namespace_is_escape_capable():
    rec = _rec("hostnet", mounts=[], net="host", pid="host")
    out = _ex()._parse_docker([rec], OBJ)
    assert out["assessment"] == "SUSPICIOUS"
    assert out["containers"][0]["host_namespaces"] == ["net", "pid"]


def test_non_root_bind_that_still_covers_the_objective_is_a_breach():
    rec = _rec("rootbind", mounts=[{"Source": "/root", "Destination": "/x"}])
    out = _ex()._parse_docker([rec], OBJ)
    assert out["flag_access_detected"] is True


def test_benign_bind_not_reaching_objective_is_ignored():
    rec = _rec("logs", mounts=[{"Source": "/var/log", "Destination": "/logs"}])
    out = _ex()._parse_docker([rec], OBJ)
    assert out["assessment"] == "CLEAN"
    assert out["containers"] == []


def test_empty_and_no_docker_are_clean():
    assert _ex()._parse_docker([], OBJ)["assessment"] == "CLEAN"


def test_host_path_reaches():
    assert ToolExecutor._host_path_reaches("/", OBJ)
    assert ToolExecutor._host_path_reaches("/root", OBJ)
    assert ToolExecutor._host_path_reaches("/root/flag.txt", OBJ)
    assert not ToolExecutor._host_path_reaches("/var/log", OBJ)
    assert not ToolExecutor._host_path_reaches("/roo", OBJ)  # prefix, not a dir boundary


# --- window binding: stale residue is posture, not this episode's breach ---

def test_stale_container_started_before_window_is_not_credited():
    started = ToolExecutor._docker_ts_epoch(BREAKOUT["State"]["StartedAt"])
    out = _ex()._parse_docker([BREAKOUT], OBJ, since_epoch=started + 1000)
    assert out["assessment"] == "SUSPICIOUS"       # posture present
    assert out["flag_access_detected"] is False    # but no win credit
    assert out["containers"][0]["in_window"] is False


def test_in_window_breakout_is_a_breach():
    started = ToolExecutor._docker_ts_epoch(BREAKOUT["State"]["StartedAt"])
    out = _ex()._parse_docker([BREAKOUT], OBJ, since_epoch=started - 1000)
    assert out["flag_access_detected"] is True
    assert out["containers"][0]["in_window"] is True


def test_no_window_fails_open_to_breach():
    out = _ex()._parse_docker([BREAKOUT], OBJ, since_epoch=None)
    assert out["flag_access_detected"] is True


def test_docker_ts_epoch():
    assert ToolExecutor._docker_ts_epoch("2026-10-15T22:53:20.5Z") > 0
    assert ToolExecutor._docker_ts_epoch("0001-01-01T00:00:00Z") is None
    assert ToolExecutor._docker_ts_epoch("") is None


# --- daemon-log backstop: catches a --rm breakout gone from ps -a ----------

# A real line captured from the target's /var/log/upstart/docker.log.
LOG_LINE = ('time="2026-10-24T04:38:27.7Z" level=warning msg="Falling back to '
            'default propagation for bind source in daemon root" '
            'container=096391e6596560cf3a56a40d8d45676011d9e59fe source=/')


def test_daemon_log_recovers_a_destroyed_breakout():
    ep = ToolExecutor._docker_ts_epoch("2026-10-24T04:38:27.7Z")
    ghosts = _ex()._parse_docker_log(LOG_LINE, OBJ, since_epoch=ep - 100)
    assert len(ghosts) == 1
    g = ghosts[0]
    assert g["reaches_objective"] and g["in_window"] and g["from_daemon_log"]
    assert _ex()._assemble_docker_finding(ghosts)["flag_access_detected"] is True


def test_daemon_log_out_of_window_is_not_credited():
    ep = ToolExecutor._docker_ts_epoch("2026-10-24T04:38:27.7Z")
    ghosts = _ex()._parse_docker_log(LOG_LINE, OBJ, since_epoch=ep + 100)
    assert ghosts[0]["in_window"] is False
    assert _ex()._assemble_docker_finding(ghosts)["flag_access_detected"] is False


def test_daemon_log_dedupes_containers_already_in_ps_a():
    seen = {"096391e6596560cf3a56a40d8d45676011d9e59feaf8a93a2401da0cb2e24798"}
    assert _ex()._parse_docker_log(LOG_LINE, OBJ, since_epoch=None, seen_ids=seen) == []


def test_daemon_log_ignores_non_root_source():
    line = LOG_LINE.replace("source=/", "source=/var/lib/docker")
    assert _ex()._parse_docker_log(line, OBJ, since_epoch=None) == []


# --- mock + the win contract ----------------------------------------------

def test_mock_returns_a_breakout_breach():
    out = MockExecutor().investigate_docker(OBJ)
    assert out["tool"] == "investigate_docker"
    assert out["flag_access_detected"] is True


def test_docker_breach_wins_via_check_blue_victory():
    # No orchestrator change needed: _check_blue_victory already credits a tool
    # output carrying flag_access_detected=True.
    from src.orchestrator import Orchestrator
    orch = Orchestrator.__new__(Orchestrator)
    finding = json.dumps(MockExecutor().investigate_docker(OBJ))
    assert orch._check_blue_victory(finding) is True
