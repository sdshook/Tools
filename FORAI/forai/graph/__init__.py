"""Graph module - Temporal Knowledge Graph backends."""

from .nodes import Node, NodeType, ProcessNode, FileNode, NetworkNode, RegistryNode, UserNode, ServiceNode
from .edges import Edge, EdgeType, is_causal_edge
from .graph import ForensicGraph
from .builder import build_graph_from_evidence

# Factory for backend selection
def create_graph(db_path, case_id, backend="auto"):
    """
    Create graph with specified backend.
    
    Args:
        db_path: Path to database
        case_id: Case identifier  
        backend: "kuzu", "sqlite", or "auto"
    """
    if backend == "kuzu":
        from .kuzu_graph import KuzuGraph
        return KuzuGraph(db_path, case_id)
    elif backend == "sqlite":
        return ForensicGraph(db_path, case_id)
    else:  # auto - try kuzu, fall back to sqlite
        try:
            from .kuzu_graph import KuzuGraph
            return KuzuGraph(db_path, case_id)
        except ImportError:
            return ForensicGraph(db_path, case_id)

__all__ = [
    "Node", "NodeType", "ProcessNode", "FileNode", "NetworkNode", 
    "RegistryNode", "UserNode", "ServiceNode",
    "Edge", "EdgeType", "is_causal_edge",
    "ForensicGraph", "build_graph_from_evidence", "create_graph"
]
