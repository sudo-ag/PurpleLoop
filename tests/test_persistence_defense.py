"""Blue hunts a planted SSH-key backdoor once a foothold lands, then evicts it.

The persistence objective is decided by whether red's planted key SURVIVES, and a
password lock / IP ban does not evict a pubkey — so blue wins only by running
remove_persistence. This steering is signal-driven (fires on the foothold and the
detected key), not gated on --objective. Mirror of the foothold-hunt arc.
"""
import json

from src.agents import BlueAgent
from src.mock_executor import MockExecutor
from src.trajectory import Turn


def _blue():
    b = BlueAgent(executor=MockExecutor(), model="x")
    b.executor.control_source_ip = "192.168.64.1"
    b.executor.user = "vagrant"
    return b


def _used_turn(name, output=None):
    out = json.dumps(output if output is not None else {"tool": name})
    return Turn(0, "", {"function": {"name": name, "arguments": {}}}, out)


def _foothold_turn():
    return _used_turn("investigate_processes",
                      {"tool": "investigate_processes",
                       "critical_processes": [{"user": "www-data", "critical": True}]})


def _persistence_breach(account="root"):
    return _used_turn("investigate_persistence",
                      {"tool": "investigate_persistence", "assessment": "BREACH",
                       "new_keys": [f"{account}:ssh-ed25519 AAAA...attacker"]})


def test_foothold_landed_hunts_persistence():
    b = _blue()
    b.history = [_foothold_turn()]
    g = b.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "investigate_persistence" in g


def test_no_hunt_without_a_foothold():
    b = _blue()
    g = b.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "investigate_persistence" not in g


def _persistence_clean():
    return _used_turn("investigate_persistence",
                      {"tool": "investigate_persistence", "assessment": "CLEAN",
                       "new_keys": []})


def test_hunt_re_fires_after_a_clean_early_check():
    # Blue swept persistence once before red planted (came back clean), but the
    # foothold is still live and no key has surfaced -- blue MUST keep sweeping,
    # or a key planted after that first check is never caught. A one-shot hunt
    # (fires only if investigate_persistence was never called) blinds blue the
    # moment it checks too early.
    b = _blue()
    b.history = [_foothold_turn(), _persistence_clean()]
    g = b.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "PLANTED BACKDOOR" in g  # the HUNT branch, not generic monitoring


def test_detected_key_steers_eviction_on_the_right_account():
    b = _blue()
    b.history = [_foothold_turn(), _persistence_breach("root")]
    g = b.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert "remove_persistence" in g
    assert 'user="root"' in g


def test_eviction_fires_in_non_observe_too():
    b = _blue()
    b.history = [_persistence_breach("vagrantdev")]
    g = b.tool_guidance(observe=False, confirmed_attackers=["192.168.64.11"], contained=False)
    assert "remove_persistence" in g
    assert 'user="vagrantdev"' in g


def test_no_re_eviction_once_removed():
    b = _blue()
    b.history = [_foothold_turn(), _persistence_breach("root"), _used_turn("remove_persistence")]
    g = b.tool_guidance(observe=True, confirmed_attackers=[], contained=False)
    assert 'remove_persistence` user=' not in g  # EVICT steer gone; tool may still appear in a tool list


def test_planted_key_account_reads_latest_breach_else_none():
    b = _blue()
    assert b._planted_key_account() is None
    b.history = [_persistence_breach("root")]
    assert b._planted_key_account() == "root"
