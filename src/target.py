"""Target environment description, handed to an agent as data.

Keeps box-specific facts out of the agent's core doctrine: the agent's prompt
stays generic tradecraft, and what varies per environment (where to connect,
what the objective is, where blue's sensors look) rides in here. `env_notes`
is an optional slot for TRAINING-only technique hints — never answers (which
account/service is privileged), which the agent must discover (no-seeding).
"""
from dataclasses import dataclass


@dataclass
class TargetProfile:
    host: str
    flag_path: str = "/root/flag.txt"
    objective: str = "root"          # "foothold" | "exfil" | "root"
    env_notes: str = ""              # technique hints for training; empty for real targets
