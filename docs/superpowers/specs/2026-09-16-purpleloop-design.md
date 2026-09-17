# PurpleLoop Design Specification
Date: 2026-09-16
Status: Draft

## 1. Objective
Create an agentic "cat-and-mouse" simulation for security research. A Red agent attempts to compromise a vulnerable target box to capture a flag, while a Blue agent monitors the system in real-time and applies hardening measures to prevent the compromise. The goal is to develop a Blue agent that learns from Red's attacks to become "unstoppable."

## 2. High-Level Architecture

### 2.1 Components
- **Red Agent:** The attacker. Focuses on reconnaissance, exploitation, and flag capture.
- **Blue Agent:** The defender. Focuses on monitoring, detection, and real-time mitigation.
- **Target Box:** A vulnerable VM (MVP: custom box) acting as the shared state.
- **Tool Executor:** A Python-based bridge that executes commands on the Target Box via SSH and returns results to the agents.
- **Loop Orchestrator:** A Python script that manages turns, handles the interaction loop, and monitors win/loss conditions.

### 2.2 System Diagram (Conceptual)
`Red Agent` <--> `Tool Executor` <--> `Target Box` <--> `Tool Executor` <--> `Blue Agent`

## 3. Interaction Model

### 3.1 The "Chaos" Loop
The simulation operates in real-time. Agents do not communicate with each other directly; they interact solely through the state of the Target Box.
- **Red** modifies the box (e.g., creates a shell, modifies a file).
- **Blue** observes these modifications (e.g., via logs, `netstat`).
- **Blue** reacts by modifying the box (e.g., blocking an IP, killing a process).

### 3.2 Turn-Based Execution
To prevent LLM race conditions and manage API costs, the Loop Orchestrator uses a round-robin approach:
1. **Red's Turn:** Red performs up to $X$ actions.
2. **Blue's Turn:** Blue performs up to $Y$ actions.
3. **Verification:** The Orchestrator checks for victory conditions.

## 4. Toolsets

### 4.1 Red Agent (The Sword)
| Category | Tools | Purpose |
| :--- | :--- | :--- |
| Recon | `nmap`, `gobuster` | Port scanning and directory enumeration |
| Exploit | `msfconsole` wrapper, `python` scripts | Triggering vulnerabilities |
| Post-Ex | `cat`, `find`, `sudo -l`, `nc` | Flag capture and privilege escalation |

### 4.2 Blue Agent (The Shield)
| Category | Tools | Purpose |
| :--- | :--- | :--- |
| Detection | `tail -f /var/log/syslog`, `netstat`, `ps aux` | Identifying attacker activity |
| Mitigation | `iptables`, `systemctl stop`, `chmod`, `passwd` | Closing holes and blocking attackers |
| Forensics | `grep`, `lsof` | Analyzing attack patterns |

### 4.3 Tool Executor Guardrails
- **Logging:** All commands and outputs are logged to a file for research analysis.
- **Safety:** A blacklist of "nuclear" commands (e.g., `rm -rf /`) is enforced.
- **Timeouts:** Commands are wrapped in timeouts to prevent the loop from hanging.

## 5. Win/Loss Conditions

- **Red Victory:** Red reads the content of the designated flag file (e.g., `/root/flag.txt`).
- **Blue Victory:** The Orchestrator determines Red is unable to make progress or is completely locked out for a set number of turns.
- **Draw:** The simulation reaches a maximum turn limit without a flag capture.

## 6. Visual Dashboard (The "War Room")
To provide visibility into the simulation, a real-time dashboard will be implemented.
- **Agent Feeds:** Side-by-side logs showing the "Thought" $\rightarrow$ "Action" $\rightarrow$ "Result" loop for both Red and Blue agents.
- **Battle Log:** A chronological timeline of all commands executed on the Target Box.
- **Status Indicators:** Visual cues for current turn (Red vs Blue), connection status to the Target Box, and victory progress (e.g., a progress bar toward the flag).
- **Implementation:** A simple web-based dashboard (e.g., using Flask/FastAPI + Socket.io) that streams data from the Loop Orchestrator.

## 7. MVP Implementation Stack
- **Language:** Python 3.11+
- **LLM Framework:** `ollama` (qwen2.5-coder or similar)
- **Remote Access:** `paramiko` for SSH-based tool execution.
- **OS:** Linux (Target Box)
- **Visualization:** FastAPI + Jinja2/WebSockets for the War Room dashboard.
