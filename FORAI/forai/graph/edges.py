"""
Graph edge types for forensic relationships.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class EdgeType(Enum):
    """Forensic graph edge types."""
    # Causal edges
    SPAWNED_BY = "spawned_by"
    WROTE_TO = "wrote_to"
    READ_FROM = "read_from"
    CONNECTED_TO = "connected_to"
    MODIFIED = "modified"
    OWNED_BY = "owned_by"
    RUNS_AS = "runs_as"
    
    # Temporal edges
    PRECEDES = "precedes"
    COINCIDES_WITH = "coincides_with"
    ANOMALOUS_DELTA = "anomalous_delta"


@dataclass
class Edge:
    """Graph edge connecting two nodes."""
    edge_id: str
    edge_type: EdgeType
    source_id: str
    target_id: str
    timestamp: float
    time_delta: float = 0.0
    is_anomalous: bool = False
    anomaly_score: float = 0.0
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.edge_id:
            self.edge_id = f"{self.source_id}->{self.target_id}:{self.edge_type.value}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.edge_id,
            "type": self.edge_type.value,
            "source": self.source_id,
            "target": self.target_id,
            "timestamp": self.timestamp,
            "time_delta": self.time_delta,
            "is_anomalous": self.is_anomalous,
            "anomaly_score": self.anomaly_score,
            "confidence": self.confidence,
            "properties": self.properties
        }


# Causal pattern definitions for plausibility scoring
CAUSAL_PATTERNS = {
    # (source_type, target_type, edge_type) -> plausibility
    ("process", "process", "spawned_by"): 1.0,
    ("process", "file", "wrote_to"): 1.0,
    ("process", "file", "read_from"): 1.0,
    ("process", "network", "connected_to"): 1.0,
    ("process", "registry", "modified"): 1.0,
    ("service", "process", "spawned_by"): 0.9,
    ("user", "process", "owned_by"): 0.8,
    ("service", "user", "runs_as"): 0.9,
}

IMPLAUSIBLE_PATTERNS = {
    # Patterns that indicate anomalies
    ("file", "process", "spawned_by"),
    ("network", "file", "wrote_to"),
    ("registry", "process", "spawned_by"),
}


def is_causal_edge(edge_type: EdgeType) -> bool:
    """Check if edge type represents causation."""
    return edge_type in {
        EdgeType.SPAWNED_BY,
        EdgeType.WROTE_TO,
        EdgeType.READ_FROM,
        EdgeType.CONNECTED_TO,
        EdgeType.MODIFIED,
        EdgeType.OWNED_BY,
        EdgeType.RUNS_AS,
    }


def is_temporal_edge(edge_type: EdgeType) -> bool:
    """Check if edge type represents temporal relationship."""
    return edge_type in {
        EdgeType.PRECEDES,
        EdgeType.COINCIDES_WITH,
        EdgeType.ANOMALOUS_DELTA,
    }
