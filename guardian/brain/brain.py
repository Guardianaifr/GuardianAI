"""Compatibility entrypoint for BrainController naming."""

from __future__ import annotations

try:
    from guardian.brain.orchestrator import CyberBrain
except ImportError:
    try:
        from .orchestrator import CyberBrain
    except ImportError:
        from brain.orchestrator import CyberBrain


class BrainController(CyberBrain):
    """Alias for CyberBrain to preserve legacy/plan naming."""

