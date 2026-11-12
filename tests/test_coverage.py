"""Coverage matrix: a (tool,name,args,output)->vector classifier over
already-recorded episode timelines, reusing existing stateless orchestrator
checks wherever one already exists for a vector."""
import json

from src.coverage import (
    VECTORS,
    _as_tool_call,
    classify_episode,
    aggregate,
)
from src.orchestrator import TIER_FOOTHOLD, TIER_EXFIL, TIER_ROOT


def _vec(name: str) -> dict:
    return next(v for v in VECTORS if v["name"] == name)


def test_as_tool_call_wraps_flattened_entry():
    entry = {"name": "use_credential", "args": {"username": "x", "password": "y"}}
    assert _as_tool_call(entry) == {
        "function": {"name": "use_credential", "arguments": {"username": "x", "password": "y"}}
    }


# --- ssh_brute: reuses _check_red_foothold / _check_blue_foothold_detect ---

def test_ssh_brute_red_reach_fires_on_use_credential_success():
    out = json.dumps({"tool": "use_credential", "status": "success", "user": "lando_calrissian"})
    entry = {"role": "red", "name": "use_credential", "args": {}, "output": out}
    assert _vec("ssh_brute")["red_reach"](entry) is True


def test_ssh_brute_red_reach_does_not_fire_on_error_output():
    entry = {"role": "red", "name": "execute_command", "args": {},
             "output": "bash: permission denied"}
    assert _vec("ssh_brute")["red_reach"](entry) is False


# --- dirtycow: reuses _check_red_rogue_root_creation, loose (no baseline) --

def test_dirtycow_red_reach_fires_without_any_baseline_setup():
    # No baseline is ever captured anywhere in this test -- proves the
    # fresh-throwaway-orchestrator construction resolves the baseline lookup
    # to None and the check's own _is_new treats "no baseline" as permissive.
    entry = {"role": "red", "name": "execute_command", "args": {},
             "output": "uid=0(firefart) gid=0(root) groups=0(root)"}
    assert _vec("dirtycow")["red_reach"](entry) is True


# --- docker_breakout: new rule, no existing orchestrator check to reuse ---

def test_docker_breakout_red_reach_fires_on_mount_and_flag():
    entry = {
        "role": "red", "name": "execute_command",
        "args": {"command": "docker run -v /:/mnt --rm alpine cat /mnt/root/flag.txt"},
        "output": "FLAG{purple_loop_victory}",
    }
    assert _vec("docker_breakout")["red_reach"](entry) is True


def test_docker_breakout_red_reach_does_not_fire_without_flag_in_output():
    entry = {
        "role": "red", "name": "execute_command",
        "args": {"command": "docker run -v /:/mnt --rm alpine cat /mnt/root/flag.txt"},
        "output": "permission denied",
    }
    assert _vec("docker_breakout")["red_reach"](entry) is False


def test_docker_breakout_red_reach_does_not_fire_without_mount_flag():
    entry = {
        "role": "red", "name": "execute_command",
        "args": {"command": "docker run --rm alpine id"},
        "output": "FLAG{purple_loop_victory}",
    }
    assert _vec("docker_breakout")["red_reach"](entry) is False


# --- proftpd_modcopy / drupal_drupalgeddon2 share one blue_detect object ---

def test_proftpd_and_drupal_share_the_same_blue_detect_function_object():
    assert _vec("proftpd_modcopy")["blue_detect"] is _vec("drupal_drupalgeddon2")["blue_detect"]


def test_shared_blue_detect_fires_on_investigate_webshells_breach():
    out = json.dumps({"tool": "investigate_webshells", "new_files": ["shell.php"],
                       "flag_access_detected": True, "assessment": "BREACH"})
    entry = {"role": "blue", "name": "investigate_webshells", "args": {}, "output": out}
    assert _vec("proftpd_modcopy")["blue_detect"](entry) is True
    assert _vec("drupal_drupalgeddon2")["blue_detect"](entry) is True


# --- not_attempted vectors: always False, never fabricated -----------------

def test_not_attempted_vectors_never_fire():
    plausible_entries = [
        {"role": "red", "name": "execute_command", "args": {"command": "smbclient //x/public"},
         "output": "uid=0(root) FLAG{x} ssh-ed25519 AAAA"},
        {"role": "blue", "name": "investigate_webshells", "args": {},
         "output": json.dumps({"assessment": "BREACH", "flag_access_detected": True})},
    ]
    for name in ("writable_sinatra_privesc", "sambacry", "phpmyadmin_preg_replace"):
        v = _vec(name)
        assert v["status"] == "not_attempted"
        for entry in plausible_entries:
            assert v["red_reach"](entry) is False
            assert v["blue_detect"](entry) is False


def test_not_attempted_vectors_share_the_same_never_function():
    a, b, c = (_vec(n) for n in ("writable_sinatra_privesc", "sambacry", "phpmyadmin_preg_replace"))
    assert a["red_reach"] is b["red_reach"] is c["red_reach"]
    assert a["blue_detect"] is b["blue_detect"] is c["blue_detect"]


# --- classify_episode -------------------------------------------------------

def _ep(timeline, tiers):
    return {"timeline": timeline, "tiers": tiers}


def test_classify_episode_tiered_vector_reached_detected_defended():
    red_out = json.dumps({"tool": "use_credential", "status": "success", "user": "x"})
    blue_out = json.dumps({"assessment": "CLEAN"})  # foothold detect doesn't need this shape
    ep = _ep(
        timeline=[
            {"turn": 0, "role": "red", "name": "use_credential", "args": {}, "output": red_out},
        ],
        tiers=[{"tier": TIER_FOOTHOLD, "name": "foothold", "reached_turn": 0,
                "detect_turn": 1, "dwell": 1, "defended": True}],
    )
    result = classify_episode(ep)
    assert result["ssh_brute"]["reached"] is True


def test_classify_episode_no_tier_vector_prevented_is_always_none():
    out = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZhbWlseTVwbGFudGVka2V5dGVzdHZhbHVl pl_key"
    ep = _ep(
        timeline=[{"turn": 0, "role": "red", "name": "execute_command", "args": {}, "output": out}],
        tiers=[],
    )
    result = classify_episode(ep)
    assert result["ssh_key_persistence"]["reached"] is True
    assert result["ssh_key_persistence"]["prevented"] is None


def test_classify_episode_returns_every_vector():
    ep = _ep(timeline=[], tiers=[])
    result = classify_episode(ep)
    assert set(result.keys()) == {v["name"] for v in VECTORS}


# --- aggregate ---------------------------------------------------------------

def test_aggregate_true_in_any_episode_and_defended_at_least_once():
    ep1 = {"ssh_brute": {"reached": True, "detected": True, "prevented": True}}
    ep2 = {"ssh_brute": {"reached": False, "detected": False, "prevented": None}}
    agg = aggregate([ep1, ep2])
    assert agg["ssh_brute"] == {"reached": True, "detected": True, "prevented": True}


def test_aggregate_prevented_false_when_judged_but_never_defended():
    ep1 = {"ssh_brute": {"reached": True, "detected": True, "prevented": False}}
    ep2 = {"ssh_brute": {"reached": False, "detected": False, "prevented": None}}
    agg = aggregate([ep1, ep2])
    assert agg["ssh_brute"]["prevented"] is False


def test_aggregate_prevented_none_when_never_judged():
    ep1 = {"ssh_brute": {"reached": False, "detected": False, "prevented": None}}
    agg = aggregate([ep1])
    assert agg["ssh_brute"]["prevented"] is None
