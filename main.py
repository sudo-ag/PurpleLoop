import multiprocessing
import time
import os
import sys
from src.dashboard import app as dashboard_app
import uvicorn
from src.arena import build_agents
from src.orchestrator import Orchestrator

def run_dashboard() -> None:
    port = int(os.environ.get("DASHBOARD_PORT", os.environ.get("PORT", "8000")))
    host = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
    uvicorn.run(dashboard_app, host=host, port=port, log_level="error")

def dashboard_enabled() -> bool:
    if os.getenv("ENABLE_DASHBOARD") == "1":
        return True
    return os.getenv("DISABLE_DASHBOARD", "1").lower() not in ("1", "true", "yes", "on")

def main() -> None:
    # The target is the box blue defends and red attacks (Metasploitable3).
    host = os.getenv("TARGET_HOST", "192.168.64.12")
    user = os.getenv("TARGET_USER", "vagrant")
    pwd = os.getenv("TARGET_PWD", "vagrant")
    # Red attacks the target FROM its own box (Kali) via this jump host, so the
    # target sees the attacker's IP, not the controller's. Unset RED_JUMP_HOST to
    # fall back to a single-box run (red connects directly, like blue).
    jump_host = os.getenv("RED_JUMP_HOST", "192.168.64.11")
    jump_user = os.getenv("RED_JUMP_USER", "kali")
    jump_pwd = os.getenv("RED_JUMP_PWD", "kali")
    model = os.getenv("MODEL", "llama3.2:latest")
    # Opt-in: red cleans its tracks (log tampering) after reading the flag.
    red_evasion = os.getenv("RED_EVASION", "0").lower() in ("1", "true", "yes", "on")
    # Opt-in: red starts with no target creds and must brute-force them from its
    # attacker box (Kali) first. Requires a jump host (red's attacker box).
    red_earned = os.getenv("RED_EARNED", "0").lower() in ("1", "true", "yes", "on")

    if host != "mock" and jump_host:
        print(f"Starting simulation: red attacks {user}@{host} via jump "
              f"{jump_user}@{jump_host}; blue defends {host} directly. Model {model}.")
    else:
        print(f"Starting simulation against {host} as {user} using model {model}...")

    dashboard_process = None
    use_dashboard = dashboard_enabled()
    if use_dashboard:
        # Start Dashboard in a separate process
        dashboard_process = multiprocessing.Process(target=run_dashboard, daemon=True)
        dashboard_process.start()
        # Give dashboard a moment to start
        time.sleep(2)

    try:
        # Build red/blue via the same builder the arena uses, so the earned flow
        # stays in sync: earned red starts with NO target credential and must
        # prove one via use_credential (require_foothold); handed red keeps the
        # configured cred. Blue defends the target directly.
        red, blue = build_agents(
            host=host, model=model, user=user, pwd=pwd,
            jump_host=jump_host, jump_user=jump_user, jump_pwd=jump_pwd,
            evade=red_evasion, earned=red_earned, observe=False,
        )

        # Initialize Orchestrator
        dashboard_url = os.environ.get("DASHBOARD_URL", "http://localhost:8000") if use_dashboard else None
        orchestrator = Orchestrator(
            red_agent=red,
            blue_agent=blue,
            dashboard_url=dashboard_url,
        )

        # Run Simulation
        if dashboard_url:
            print(f"Simulation started. Check {dashboard_url} for live updates.")
        else:
            print("Simulation started. Dashboard disabled.")
        winner = orchestrator.run_simulation(max_turns=20)

        # Save the battle report
        report_content = orchestrator.generate_report()
        report_filename = "battle_report.md"
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        print(f"\nBattle report saved to {report_filename}")

        if winner:
            print(f"\nSimulation ended. Winner: {winner.upper()}")
        else:
            print("\nSimulation ended. No winner determined.")

    except Exception as e:
        print(f"Simulation failed: {e}")
    finally:
        # Clean up
        if dashboard_process:
            dashboard_process.terminate()
            dashboard_process.join()

if __name__ == "__main__":
    main()
