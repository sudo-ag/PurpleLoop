"""
Purpleloop operations — start / watch / report.

Hermes uses this module as the primary runtime entrypoint. `main.py` still
owns the simulation itself, but `src.ops` prepares the environment, launches
the process, watches progress, and reads the final report.

The dashboard is disabled by default. Pass dashboard=True or `--dashboard`
when the FastAPI UI is needed; otherwise watch progress through
`simulation.log` and `battle_report.md`.

Quick shell equivalents:
  uv run python -m src.ops start --host mock
  uv run python -m src.ops run --host mock --max-minutes 30
  uv run python -m src.ops report

Usage from Hermes:
  "start a mock simulation"             -> start_simulation(host=MOCK_HOST)
  "read the latest battle report"       -> read_report()
  "watch until the sim ends, then read the report"
                                        -> watch_until_done(max_wait_minutes=..., interval_s=...)
  "restart with model llama3.1"         -> start_simulation(host=MOCK_HOST, model="llama3.1")
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:8000")
MOCK_HOST = "mock"
DEFAULT_MODEL = os.getenv("MODEL", "llama3.2:latest")
MAX_EVENT_LOG = 80


def _session() -> requests.Session:
    s = requests.Session()
    s.headers["Accept"] = "application/json"
    return s


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

def start_simulation(
    host: str = MOCK_HOST,
    model: str = DEFAULT_MODEL,
    user: str = "vagrant",
    pwd: str = "vagrant",
    max_turns: int = 20,
    dashboard_url: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    dashboard: bool = False,
    background: bool = True,
) -> Dict[str, Any]:
    """
    Launch a purpleloop simulation.

    By default it runs in the background so the caller isn't blocked;
    set background=False to run in the foreground (e.g. a one-shot
    Hermes command that waits for the whole sim). The env dict is
    merged on top of the current environment.
    """
    url = dashboard_url or DASHBOARD_URL
    # Parse http://host:port into the env vars main.py's run_dashboard() reads.
    _dashboard_host = "localhost"
    _dashboard_port = "8000"
    if "://" in url:
        _, rest = url.split("://", 1)
        if "/" in rest:
            rest = rest.split("/", 1)[0]
        if ":" in rest:
            _dashboard_host, _dashboard_port = rest.rsplit(":", 1)
        else:
            _dashboard_host = rest

    child_env = dict(os.environ)
    if env:
        child_env.update(env)
    child_env["TARGET_HOST"] = host
    child_env["TARGET_USER"] = user
    child_env["TARGET_PWD"] = pwd
    child_env["MODEL"] = model
    child_env["DASHBOARD_URL"] = url
    child_env["DASHBOARD_HOST"] = _dashboard_host
    child_env["DASHBOARD_PORT"] = _dashboard_port
    child_env["DISABLE_DASHBOARD"] = "0" if dashboard else "1"

    python = os.environ.get("VIRTUAL_ENV")
    if python:
        exe = os.path.join(python, "bin", "python")
    else:
        exe = sys.executable

    main_file = REPO / "main.py"
    cmd = [exe, str(main_file)]

    info = {
        "host": host,
        "model": model,
        "cmd": " ".join(cmd),
        "dashboard_url": url,
        "dashboard_enabled": dashboard,
        "background": background,
    }

    if background:
        log_path = REPO / "simulation.log"
        with open(log_path, "a") as log:
            log.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] starting: {info['cmd']}\n")
        proc = subprocess.Popen(
            cmd,
            cwd=str(REPO),
            env=child_env,
            stdout=open(log_path, "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        info["pid"] = proc.pid
        info["log"] = str(log_path)
        if dashboard:
            # Give the dashboard a moment to come up
            for _ in range(10):
                try:
                    _session().get(url + "/state", timeout=1.0)
                    break
                except Exception:
                    time.sleep(0.5)
        return info
    else:
        proc = subprocess.run(cmd, cwd=str(REPO), env=child_env)
        info["exit_code"] = proc.returncode
        return info


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_state(url: Optional[str] = None) -> Dict[str, Any]:
    """Latest turn snapshot plus recent event log from the dashboard."""
    u = url or DASHBOARD_URL
    r = _session().get(u + "/state", timeout=3.0)
    r.raise_for_status()
    return r.json()


def get_state_or_none(url: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """get_state() that returns None instead of crashing when the dashboard is unreachable."""
    u = url or DASHBOARD_URL
    try:
        r = _session().get(u + "/state", timeout=3.0)
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _latest_event(state: Dict[str, Any]) -> Dict[str, Any]:
    latest = state.get("latest", {})
    log = state.get("event_log", [])
    out = {"latest_event_type": latest.get("event_type"), "latest_data": latest.get("data")}
    if log:
        last = log[-1]
        out["last_event"] = {"event_type": last.get("event_type"), "data": last.get("data")}
        out["event_log_len"] = len(log)
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

REPORT_PATH = REPO / "battle_report.md"


def _dashboard_disabled() -> bool:
    """True when the simulation was started without a dashboard (DISABLE_DASHBOARD=1)."""
    return os.getenv("DISABLE_DASHBOARD", "1").lower() in ("1", "true", "yes", "on")


def report_exists() -> bool:
    return REPORT_PATH.exists()


def read_report(max_chars: int = 4000) -> str:
    """Read battle_report.md, trimmed to a readable window."""
    if not report_exists():
        return "No battle_report.md yet."
    text = REPORT_PATH.read_text(encoding="utf-8")
    if len(text) <= max_chars:
        return text
    head = text[: max_chars // 2]
    tail = text[-max_chars // 2:]
    return f"{head}\n\n[...{len(text) - max_chars} chars omitted...]\n\n{tail}"


def _watch_without_dashboard(
    max_wait_minutes: float, interval_s: float, log: bool
) -> Dict[str, Any]:
    """Poll simulation.log for turn progress when no dashboard is running."""
    log_path = REPO / "simulation.log"
    deadline = time.time() + max_wait_minutes * 60.0
    last_turn: Optional[int] = None
    winner: Optional[str] = None
    try:
        while time.time() < deadline:
            if log_path.exists():
                text = log_path.read_text(encoding="utf-8")
                # Extract the last "Turn N" line from the log
                turns = re.findall(r"Turn (\d+)", text)
                if turns:
                    last_turn = int(turns[-1])
                if "Winner:" in text or "winner:" in text.lower():
                    m = re.search(r"(?:Winner|winner):\s*(\w+)", text, re.IGNORECASE)
                    if m:
                        winner = m.group(1).lower()
                        if log:
                            print(f"[{time.strftime('%H:%M:%S')}] turn={last_turn} winner={winner}", flush=True)
                        break
            if log:
                print(f"[{time.strftime('%H:%M:%S')}] turn={last_turn} winner={winner}", flush=True)
            time.sleep(interval_s)
    except KeyboardInterrupt:
        if log:
            print("\n[ops] watch interrupted by user", file=sys.stderr)
    report = read_report() if report_exists() else None
    state = {"turn": last_turn, "winner": winner} if last_turn is not None else {}
    return {"state": state, "report": report, "winner": winner}


# ---------------------------------------------------------------------------
# Watch
# ---------------------------------------------------------------------------

def watch_until_done(
    max_wait_minutes: float = 20.0,
    interval_s: float = 5.0,
    url: Optional[str] = None,
    dashboard: Optional[bool] = None,
    log: bool = True,
) -> Dict[str, Any]:
    """
    Poll /state (if dashboard is up) or simulation.log (if dashboard is
    disabled) until the simulation reports a winner or the timeout passes.
    Returns the final state snapshot and, if available, the battle report text.
    """
    dashboard_enabled = not _dashboard_disabled() if dashboard is None else dashboard
    if not dashboard_enabled:
        return _watch_without_dashboard(max_wait_minutes, interval_s, log)

    u = url or DASHBOARD_URL
    deadline = time.time() + max_wait_minutes * 60.0
    last_state: Dict[str, Any] = {}
    first_fetch = True
    try:
        while time.time() < deadline:
            try:
                state = get_state(u)
                first_fetch = False
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                if log:
                    if report_exists():
                        print("[ops] dashboard not reachable — simulation already finished; reading report", file=sys.stderr)
                        break
                    print(f"[ops] /state fetch failed: {exc}", file=sys.stderr)
                time.sleep(interval_s)
                continue

            last_state = state
            ev = _latest_event(state)

            if log:
                data = ev.get("last_event", {}).get("data", {})
                winner = data.get("winner")
                turn = data.get("turn")
                line = f"[{time.strftime('%H:%M:%S')}] turn={turn} winner={winner}"
                print(line, flush=True)

            if winner := (ev.get("last_event", {}).get("data", {}).get("winner")):
                if log:
                    print(f"[ops] simulation ended — winner: {winner}", flush=True)
                deadline_for_report = time.time() + 15.0
                while time.time() < deadline_for_report and not report_exists():
                    time.sleep(min(interval_s, 0.5))
                break

            time.sleep(interval_s)
    except KeyboardInterrupt:
        if log:
            print("\n[ops] watch interrupted by user", file=sys.stderr)
    report = read_report() if report_exists() else None
    return {"state": last_state, "report": report, "winner": _winner_from_state(last_state)}


def _winner_from_state(state: Dict[str, Any]) -> Optional[str]:
    if not isinstance(state, dict):
        return None
    data = (state.get("latest") or {}).get("data", {})
    return data.get("winner")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="purpleloop ops (start / status / report)")
    sub = parser.add_subparsers(dest="cmd")

    p_start = sub.add_parser("start", help="Launch a simulation in the background")
    p_start.add_argument("--host", default=MOCK_HOST)
    p_start.add_argument("--model", default=DEFAULT_MODEL)
    p_start.add_argument("--user", default="vagrant")
    p_start.add_argument("--pwd", default="vagrant")
    p_start.add_argument("--dashboard", action="store_true", help="Enable the FastAPI dashboard")

    p_status = sub.add_parser("status", help="Poll dashboard /state once when UI is enabled")
    p_report = sub.add_parser("report", help="Read battle_report.md")
    p_watch = sub.add_parser("watch", help="Poll until the sim ends or times out")
    p_watch.add_argument("--max-minutes", type=float, default=20.0)
    p_watch.add_argument("--interval", type=float, default=5.0)
    p_watch.add_argument("--dashboard", action="store_true", help="Poll the FastAPI dashboard instead of simulation.log")

    p_run = sub.add_parser("run", help="Start a simulation and watch it to completion in one shot")
    p_run.add_argument("--host", default=MOCK_HOST)
    p_run.add_argument("--model", default=DEFAULT_MODEL)
    p_run.add_argument("--user", default="vagrant")
    p_run.add_argument("--pwd", default="vagrant")
    p_run.add_argument("--max-minutes", type=float, default=20.0)
    p_run.add_argument("--interval", type=float, default=2.0)
    p_run.add_argument("--dashboard", action="store_true", help="Enable and watch the FastAPI dashboard")

    args = parser.parse_args()

    if args.cmd == "start":
        info = start_simulation(args.host, args.model, args.user, args.pwd, dashboard=args.dashboard)
        print(json.dumps(info, indent=2))
    elif args.cmd == "status":
        state = get_state_or_none()
        if state is None:
            if report_exists():
                print("dashboard unreachable — simulation already finished")
                print("winner:", _winner_from_state(read_report()))
                print(read_report(max_chars=1200))
            else:
                print("dashboard unreachable — no simulation running (no dashboard on", DASHBOARD_URL, "and no battle_report.md)")
        else:
            print(json.dumps(state, indent=2))
    elif args.cmd == "report":
        print(read_report())
    elif args.cmd == "watch":
        out = watch_until_done(args.max_minutes, args.interval, dashboard=args.dashboard)
        print("--- final state ---")
        print(json.dumps(out["state"], indent=2))
        if out["report"]:
            print("--- report ---")
            print(out["report"])
        print("--- winner ---")
        print(out["winner"] or "none")
    elif args.cmd == "run":
        info = start_simulation(args.host, args.model, args.user, args.pwd, dashboard=args.dashboard)
        print(json.dumps(info, indent=2))
        out = watch_until_done(args.max_minutes, args.interval, dashboard=info["dashboard_enabled"])
        print("--- final state ---")
        print(json.dumps(out["state"], indent=2))
        if out["report"]:
            print("--- report ---")
            print(out["report"])
        print("--- winner ---")
        print(out["winner"] or "none")
    else:
        parser.print_help()
