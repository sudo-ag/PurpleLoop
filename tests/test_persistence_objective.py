"""Red's persistence objective: planting a surviving SSH-key backdoor IS the
goal. See docs/superpowers/specs/2026-11-18-persistence-scenario-design.md.
"""
from src.agents import RedAgent
from src.mock_executor import MockExecutor
from src.trajectory import Turn


def _red(objective="root"):
    return RedAgent(executor=MockExecutor(), model="x", objective=objective)


def _planted_turn():
    out = "...\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdef0123456789abcdef root@attacker\n..."
    return Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, out)


def test_persistence_objective_met_once_planted():
    r = _red("persistence")
    assert r.objective_met() is False
    r.history = [_planted_turn()]
    assert r.objective_met() is True


def test_persistence_objective_not_met_without_plant():
    r = _red("persistence")
    r.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, "uid=0(root)")]
    assert r.objective_met() is False


def test_persistence_steers_on_target_access_without_ssh_cred():
    # Red reached the box via web-RCE (no use_credential, so has_foothold is
    # False) — a root uid readback. The persistence directive must still fire.
    r = _red("persistence")
    r.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}},
                      "uid=0(root) gid=0(root) groups=0(root)")]
    assert r.has_foothold is False
    g = r.phase_guidance()
    assert "persistence" in g.lower() and "plant" in g.lower()


def test_root_objective_still_uses_flag_check():
    r = _red("root")
    r.history = [_planted_turn()]  # planted but no flag read
    assert r.objective_met() is False
    r.history = [Turn(0, "", {"function": {"name": "execute_command", "arguments": {}}}, "flag{abc}")]
    assert r.objective_met() is True
