"""
FORAI - Forensic AI Analysis Tool

A modular forensic analysis tool featuring:
- Deterministic extraction layer (KAPE, Plaso)
- Temporal knowledge graph
- World model for anomaly detection
- RL agent for investigation navigation
- Graph-grounded LLM explanations
- Defensible reporting with full provenance

(c) 2025 Shane D. Shook - All Rights Reserved
"""

__version__ = "2.0.0"

from .config import Config, get_config, set_config
from .db.evidence import Evidence, EvidenceDB
from .extraction.extractors import ForensicExtractor, QuestionAnswer, STANDARD_QUESTIONS
from .graph.graph import ForensicGraph
from .graph.nodes import NodeType, Node, ProcessNode, FileNode, NetworkNode, RegistryNode, UserNode
from .graph.edges import EdgeType, Edge

__all__ = [
    "Config", "get_config", "set_config",
    "Evidence", "EvidenceDB",
    "ForensicExtractor", "QuestionAnswer", "STANDARD_QUESTIONS",
    "ForensicGraph",
    "NodeType", "Node", "ProcessNode", "FileNode", "NetworkNode", "RegistryNode", "UserNode",
    "EdgeType", "Edge",
]
