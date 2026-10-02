"""AgentShield: a defense layer and evaluation harness for prompt injection in tool-using LLM agents."""

from .defense.detector import HeuristicDetector, load_detector
from .defense.shield import Shield
from .guard import ToolGuard

__version__ = "0.2.0"

__all__ = ["HeuristicDetector", "Shield", "ToolGuard", "load_detector", "__version__"]
