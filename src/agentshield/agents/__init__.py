"""The agents under test."""

from .base import Episode, Scenario, Task, Tool, run_episode
from .devassist import SCENARIO as DEVASSIST
from .email import SCENARIO as EMAIL
from .triage import SCENARIO as TRIAGE

SCENARIOS = {s.name: s for s in (TRIAGE, EMAIL, DEVASSIST)}

__all__ = ["SCENARIOS", "Episode", "Scenario", "Task", "Tool", "run_episode"]
