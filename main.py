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

def run_dashboard():
    # Use a different port if 8000 is taken
    uvicorn.run(dashboard_app, host="0.0.0.0", port=8000, log_level="error")

def main():
    # Credentials - defaults for Metasploitable 3
    host = os.getenv("TARGET_HOST", "192.168.64.10")
    user = os.getenv("TARGET_USER", "vagrant")
    pwd = os.getenv("TARGET_PWD", "vagrant")
    model = os.getenv("MODEL", "llama3.2:latest")

    print(f"Starting simulation against {host} as {user} using model {model}...")

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
        orchestrator = Orchestrator(
            red_agent=red,
            blue_agent=blue,
            dashboard_url="http://localhost:8000"
        )

        # Run Simulation
        print("Simulation started. Check http://localhost:8000 for live updates.")
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
        dashboard_process.terminate()
        dashboard_process.join()

if __name__ == "__main__":
    main()
