"""
Build graph from evidence database.
"""

from typing import List
import re

from ..db.evidence import Evidence, EvidenceDB
from .nodes import Node, NodeType, ProcessNode, FileNode, NetworkNode, RegistryNode, UserNode
from .edges import Edge, EdgeType
from .graph import ForensicGraph


def build_graph_from_evidence(db: EvidenceDB, graph: ForensicGraph, 
                              case_id: str, limit: int = 10000) -> int:
    """
    Build temporal knowledge graph from evidence database.
    
    Args:
        db: Evidence database
        graph: Target graph
        case_id: Case identifier
        limit: Maximum evidence items to process
        
    Returns:
        Number of nodes created
    """
    node_count = 0
    
    # Get all evidence
    evidence_list = db.get_evidence(case_id, limit=limit)
    
    for e in evidence_list:
        node = _evidence_to_node(e)
        if node:
            graph.add_node(node)
            node_count += 1
    
    return node_count


def _evidence_to_node(evidence: Evidence) -> Node:
    """Convert evidence to appropriate node type."""
    artifact = evidence.artifact_type.lower()
    data = evidence.data
    
    # Process nodes
    if any(k in artifact for k in ["prefetch", "amcache", "process"]):
        return ProcessNode(
            node_id=f"proc_{evidence.id}",
            timestamp=evidence.timestamp,
            properties={"source": evidence.source_file},
            name=data.get("filename", data.get("name", evidence.summary[:50])),
            command_line=data.get("command_line", ""),
            pid=data.get("pid", 0)
        )
    
    # File nodes
    if any(k in artifact for k in ["mft", "file", "usnjrnl", "lnk"]):
        return FileNode(
            node_id=f"file_{evidence.id}",
            timestamp=evidence.timestamp,
            properties={"source": evidence.source_file},
            path=data.get("path", data.get("filename", evidence.summary[:100])),
            file_hash=data.get("hash", data.get("sha256", "")),
            size=data.get("size", 0)
        )
    
    # Network nodes
    if any(k in artifact for k in ["network", "dns", "connection"]):
        return NetworkNode(
            node_id=f"net_{evidence.id}",
            timestamp=evidence.timestamp,
            properties={"source": evidence.source_file},
            remote_ip=data.get("remote_ip", data.get("ip", "")),
            remote_port=data.get("remote_port", data.get("port", 0)),
            protocol=data.get("protocol", "TCP")
        )
    
    # Registry nodes
    if "registry" in artifact or "reg" in artifact:
        return RegistryNode(
            node_id=f"reg_{evidence.id}",
            timestamp=evidence.timestamp,
            properties={"source": evidence.source_file},
            key_path=data.get("key_path", data.get("key", evidence.summary[:100])),
            value_name=data.get("value_name", ""),
            value_data=str(data.get("value_data", ""))[:200]
        )
    
    # User nodes
    if any(k in artifact for k in ["user", "sam", "logon", "security"]):
        username = data.get("username", data.get("user", ""))
        if username:
            return UserNode(
                node_id=f"user_{username}_{evidence.id}",
                timestamp=evidence.timestamp,
                properties={"source": evidence.source_file},
                username=username,
                sid=data.get("sid", ""),
                is_admin=data.get("is_admin", False)
            )
    
    # Default to generic node
    return Node(
        node_id=f"evt_{evidence.id}",
        node_type=NodeType.FILE,  # Default
        timestamp=evidence.timestamp,
        properties={
            "source": evidence.source_file,
            "artifact_type": evidence.artifact_type,
            "summary": evidence.summary[:200]
        }
    )
