"""Compatibility entrypoint for BrainController naming."""

from __future__ import annotations

from brain.orchestrator import CyberBrain


class BrainController(CyberBrain):
    """Alias for CyberBrain to preserve legacy/plan naming."""

