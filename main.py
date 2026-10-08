import multiprocessing
import time
import os
import sys
from src.dashboard import app as dashboard_app
import uvicorn
from src.executor import ToolExecutor
from src.mock_executor import MockExecutor
from src.agents import Agent
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
    # Credentials - defaults for Metasploitable 3
    host = os.getenv("TARGET_HOST", "192.168.64.10")
    user = os.getenv("TARGET_USER", "vagrant")
    pwd = os.getenv("TARGET_PWD", "vagrant")
    model = os.getenv("MODEL", "llama3.2:latest")

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
        # Initialize Executor
        if host == "mock":
            executor = MockExecutor()
        else:
            executor = ToolExecutor(host=host, user=user, pwd=pwd)

        # Initialize Agents
        red = Agent(role="red", executor=executor, model=model)
        blue = Agent(role="blue", executor=executor, model=model)

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
