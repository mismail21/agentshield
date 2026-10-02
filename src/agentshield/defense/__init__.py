"""Defense layer: detector, spotlighting, tool policy, output checks."""

from .detector import HeuristicDetector, TfidfDetector, load_detector
from .shield import COMPONENTS, Shield

__all__ = ["COMPONENTS", "HeuristicDetector", "Shield", "TfidfDetector", "load_detector"]
