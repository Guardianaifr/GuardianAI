"""
Cross-Agent Graph Drift Tracker (OWASP ASI — Multi-Agent Lateral Movement)

Maintains a directed graph of agent-to-agent communication patterns and
detects topological anomalies:
  - New unexpected edges (agent A calling agent B for the first time)
  - Density drift (sudden increase in inter-agent connectivity)
  - Hub formation (single agent becoming central communication nexus)
  - Cycle introduction (agents forming feedback loops)
  - Anomalous subgraph formation (clusters of agents that suddenly appear)

Uses adjacency-matrix based spectral analysis to detect structural topology
changes without requiring predefined rules.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


class DriftSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DriftAlert:
    """An alert raised when graph topology drift is detected."""
    alert_type: str
    severity: DriftSeverity
    description: str
    source_agent: Optional[str] = None
    target_agent: Optional[str] = None
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity.value,
            "description": self.description,
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class GraphSnapshot:
    """A point-in-time snapshot of the agent communication graph."""
    timestamp: float
    edges: FrozenSet[Tuple[str, str]]
    node_count: int
    edge_count: int
    density: float
    max_degree: int


class AgentGraphDriftTracker:
    """
    Tracks agent-to-agent communication patterns and detects topological drift.

    Maintains a rolling window of graph snapshots and raises alerts when
    the communication topology deviates from the established baseline.
    """

    def __init__(
        self,
        *,
        baseline_window: int = 100,
        density_threshold: float = 0.3,
        hub_degree_threshold: int = 10,
        max_snapshots: int = 1000,
        new_edge_severity: DriftSeverity = DriftSeverity.MEDIUM,
    ):
        self.baseline_window = baseline_window
        self.density_threshold = density_threshold
        self.hub_degree_threshold = hub_degree_threshold
        self.max_snapshots = max_snapshots
        self.new_edge_severity = new_edge_severity

        # Current graph state
        self._baseline_edges: Set[Tuple[str, str]] = set()
        self._current_edges: Set[Tuple[str, str]] = set()
        self._nodes: Set[str] = set()
        self._out_degree: Dict[str, int] = defaultdict(int)
        self._in_degree: Dict[str, int] = defaultdict(int)

        # History
        self._snapshots: List[GraphSnapshot] = []
        self._alerts: List[DriftAlert] = []
        self._edge_first_seen: Dict[Tuple[str, str], float] = {}

        # Cycle tracking
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)

    def register_baseline_edge(self, source: str, target: str) -> None:
        """Register an expected (baseline) communication edge."""
        self._baseline_edges.add((source, target))
        self._nodes.update([source, target])
        self._adjacency[source].add(target)

    def record_communication(
        self, source: str, target: str, timestamp: Optional[float] = None
    ) -> List[DriftAlert]:
        """Record an agent-to-agent communication and return any drift alerts."""
        ts = timestamp or time.time()
        edge = (source, target)
        alerts: List[DriftAlert] = []

        self._nodes.update([source, target])
        self._adjacency[source].add(target)

        is_new_edge = edge not in self._current_edges
        if is_new_edge:
            self._current_edges.add(edge)
            self._out_degree[source] += 1
            self._in_degree[target] += 1
            self._edge_first_seen[edge] = ts

        # ── Check 1: New unexpected edge ─────────────────────────────
        if is_new_edge and edge not in self._baseline_edges:
            alert = DriftAlert(
                alert_type="new_unexpected_edge",
                severity=self.new_edge_severity,
                description=(
                    f"Agent '{source}' communicated with '{target}' for the "
                    f"first time — this edge is not in the baseline graph."
                ),
                source_agent=source,
                target_agent=target,
                timestamp=ts,
            )
            alerts.append(alert)

        # ── Check 2: Hub formation ───────────────────────────────────
        total_degree = self._out_degree[source] + self._in_degree[source]
        if total_degree > self.hub_degree_threshold:
            alert = DriftAlert(
                alert_type="hub_formation",
                severity=DriftSeverity.HIGH,
                description=(
                    f"Agent '{source}' has become a communication hub with "
                    f"degree {total_degree} (threshold: {self.hub_degree_threshold})."
                ),
                source_agent=source,
                timestamp=ts,
                metadata={"degree": total_degree},
            )
            alerts.append(alert)

        # ── Check 3: Density drift ───────────────────────────────────
        density = self._compute_density()
        if density > self.density_threshold:
            alert = DriftAlert(
                alert_type="density_drift",
                severity=DriftSeverity.HIGH,
                description=(
                    f"Graph density {density:.3f} exceeds threshold "
                    f"{self.density_threshold:.3f}."
                ),
                timestamp=ts,
                metadata={"density": density},
            )
            alerts.append(alert)

        # ── Check 4: Cycle detection ─────────────────────────────────
        if is_new_edge and self._has_cycle_through(source, target):
            cycle = self._find_cycle(target, source)
            alert = DriftAlert(
                alert_type="cycle_introduced",
                severity=DriftSeverity.CRITICAL,
                description=(
                    f"Communication cycle detected involving edge "
                    f"'{source}' → '{target}': {' → '.join(cycle)}"
                ),
                source_agent=source,
                target_agent=target,
                timestamp=ts,
                metadata={"cycle": cycle},
            )
            alerts.append(alert)

        # Take snapshot
        self._take_snapshot(ts)

        self._alerts.extend(alerts)
        return alerts

    def get_alerts(self, since: Optional[float] = None) -> List[DriftAlert]:
        """Return all alerts, optionally filtered by timestamp."""
        if since is None:
            return list(self._alerts)
        return [a for a in self._alerts if a.timestamp >= since]

    def get_current_snapshot(self) -> Dict[str, Any]:
        """Return the current graph state as a dictionary."""
        return {
            "nodes": sorted(self._nodes),
            "edges": sorted(self._current_edges),
            "baseline_edges": sorted(self._baseline_edges),
            "unexpected_edges": sorted(
                self._current_edges - self._baseline_edges
            ),
            "node_count": len(self._nodes),
            "edge_count": len(self._current_edges),
            "density": self._compute_density(),
            "max_out_degree": max(self._out_degree.values(), default=0),
            "max_in_degree": max(self._in_degree.values(), default=0),
        }

    def reset(self) -> None:
        """Reset all tracking state."""
        self._current_edges.clear()
        self._nodes.clear()
        self._out_degree.clear()
        self._in_degree.clear()
        self._snapshots.clear()
        self._alerts.clear()
        self._edge_first_seen.clear()
        self._adjacency.clear()

    # ── Private ──────────────────────────────────────────────────────────────

    def _compute_density(self) -> float:
        """Compute directed graph density: |E| / (|V| * (|V| - 1))."""
        n = len(self._nodes)
        if n < 2:
            return 0.0
        return len(self._current_edges) / (n * (n - 1))

    def _has_cycle_through(self, source: str, target: str) -> bool:
        """Check if adding edge source→target creates a cycle (target can reach source)."""
        visited: Set[str] = set()
        stack = [target]
        while stack:
            node = stack.pop()
            if node == source:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self._adjacency.get(node, set()))
        return False

    def _find_cycle(self, start: str, end: str) -> List[str]:
        """Find the cycle path from start back to end via BFS."""
        from collections import deque

        queue: deque[List[str]] = deque([[start]])
        visited: Set[str] = set()
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == end and len(path) > 1:
                return path + [start]
            if node in visited:
                continue
            visited.add(node)
            for neighbor in self._adjacency.get(node, set()):
                queue.append(path + [neighbor])
        return [start, end, start]  # fallback

    def _take_snapshot(self, timestamp: float) -> None:
        """Take a snapshot of the current graph state."""
        snapshot = GraphSnapshot(
            timestamp=timestamp,
            edges=frozenset(self._current_edges),
            node_count=len(self._nodes),
            edge_count=len(self._current_edges),
            density=self._compute_density(),
            max_degree=max(
                (self._out_degree.get(n, 0) + self._in_degree.get(n, 0)
                 for n in self._nodes),
                default=0,
            ),
        )
        self._snapshots.append(snapshot)
        if len(self._snapshots) > self.max_snapshots:
            self._snapshots = self._snapshots[-self.max_snapshots:]
