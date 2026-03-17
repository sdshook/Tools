"""
Temporal Knowledge Graph for forensic analysis.
"""

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from .nodes import Node, NodeType
from .edges import Edge, EdgeType, is_causal_edge


class ForensicGraph:
    """
    Temporal Knowledge Graph for forensic artifacts.
    
    Stores nodes (Process, File, Network, Registry, User, Service)
    and edges (causal + temporal relationships) with anomaly scoring.
    """
    
    # Temporal thresholds (milliseconds)
    COINCIDENCE_THRESHOLD = 1000      # 1 second
    PRECEDES_MAX_DELTA = 60000        # 1 minute
    ANOMALOUS_GAP_THRESHOLD = 300000  # 5 minutes
    
    def __init__(self, db_path: Path, case_id: str):
        self.db_path = db_path
        self.case_id = case_id
        self._init_db()
    
    def _init_db(self):
        """Initialize graph tables."""
        from ..db.schema import GRAPH_SCHEMA
        with self._connect() as conn:
            conn.executescript(GRAPH_SCHEMA)
    
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def add_node(self, node: Node) -> str:
        """Add node to graph."""
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO nodes 
                (node_id, case_id, node_type, timestamp, properties, confidence, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                node.node_id,
                self.case_id,
                node.node_type.value,
                node.timestamp,
                json.dumps(node.properties),
                node.confidence,
                node.hash
            ))
        return node.node_id
    
    def add_edge(self, edge: Edge) -> str:
        """Add edge to graph."""
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO edges
                (edge_id, case_id, edge_type, source_id, target_id, timestamp,
                 time_delta, is_anomalous, anomaly_score, properties)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                edge.edge_id,
                self.case_id,
                edge.edge_type.value,
                edge.source_id,
                edge.target_id,
                edge.timestamp,
                edge.time_delta,
                1 if edge.is_anomalous else 0,
                edge.anomaly_score,
                json.dumps(edge.properties)
            ))
        return edge.edge_id
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID."""
        with self._connect() as conn:
            row = conn.execute("""
                SELECT * FROM nodes WHERE node_id = ? AND case_id = ?
            """, (node_id, self.case_id)).fetchone()
            
            if row:
                return Node(
                    node_id=row["node_id"],
                    node_type=NodeType(row["node_type"]),
                    timestamp=row["timestamp"],
                    properties=json.loads(row["properties"]) if row["properties"] else {},
                    confidence=row["confidence"],
                    hash=row["hash"]
                )
        return None
    
    def get_neighbors(self, node_id: str, 
                     edge_types: Optional[List[EdgeType]] = None,
                     direction: str = "both") -> List[Tuple[str, Edge]]:
        """
        Get neighboring nodes.
        
        Args:
            node_id: Source node
            edge_types: Filter by edge types
            direction: "outgoing", "incoming", or "both"
            
        Returns:
            List of (neighbor_id, edge) tuples
        """
        neighbors = []
        
        with self._connect() as conn:
            if direction in ("outgoing", "both"):
                query = "SELECT * FROM edges WHERE source_id = ? AND case_id = ?"
                params = [node_id, self.case_id]
                
                if edge_types:
                    placeholders = ",".join("?" * len(edge_types))
                    query += f" AND edge_type IN ({placeholders})"
                    params.extend(e.value for e in edge_types)
                
                for row in conn.execute(query, params):
                    edge = self._row_to_edge(row)
                    neighbors.append((row["target_id"], edge))
            
            if direction in ("incoming", "both"):
                query = "SELECT * FROM edges WHERE target_id = ? AND case_id = ?"
                params = [node_id, self.case_id]
                
                if edge_types:
                    placeholders = ",".join("?" * len(edge_types))
                    query += f" AND edge_type IN ({placeholders})"
                    params.extend(e.value for e in edge_types)
                
                for row in conn.execute(query, params):
                    edge = self._row_to_edge(row)
                    neighbors.append((row["source_id"], edge))
        
        return neighbors
    
    def _row_to_edge(self, row) -> Edge:
        return Edge(
            edge_id=row["edge_id"],
            edge_type=EdgeType(row["edge_type"]),
            source_id=row["source_id"],
            target_id=row["target_id"],
            timestamp=row["timestamp"],
            time_delta=row["time_delta"],
            is_anomalous=bool(row["is_anomalous"]),
            anomaly_score=row["anomaly_score"],
            properties=json.loads(row["properties"]) if row["properties"] else {}
        )
    
    def get_subgraph(self, center_id: str, depth: int = 2, 
                    max_nodes: int = 50) -> Dict[str, Any]:
        """
        Extract subgraph around a node.
        
        Returns:
            Dict with "nodes", "edges", "center"
        """
        visited_nodes: Set[str] = set()
        visited_edges: Set[str] = set()
        nodes: List[Dict] = []
        edges: List[Dict] = []
        
        queue = [(center_id, 0)]
        
        while queue and len(visited_nodes) < max_nodes:
            node_id, current_depth = queue.pop(0)
            
            if node_id in visited_nodes:
                continue
            
            visited_nodes.add(node_id)
            node = self.get_node(node_id)
            if node:
                nodes.append(node.to_dict())
            
            if current_depth < depth:
                for neighbor_id, edge in self.get_neighbors(node_id):
                    if edge.edge_id not in visited_edges:
                        visited_edges.add(edge.edge_id)
                        edges.append(edge.to_dict())
                    
                    if neighbor_id not in visited_nodes:
                        queue.append((neighbor_id, current_depth + 1))
        
        return {"nodes": nodes, "edges": edges, "center": center_id}
    
    def infer_temporal_edges(self):
        """Infer temporal edges (precedes, coincides_with) from timestamps."""
        with self._connect() as conn:
            # Get all nodes ordered by timestamp
            nodes = conn.execute("""
                SELECT node_id, node_type, timestamp FROM nodes 
                WHERE case_id = ? ORDER BY timestamp
            """, (self.case_id,)).fetchall()
            
            for i, row in enumerate(nodes):
                node_id = row["node_id"]
                ts = row["timestamp"]
                
                # Look at next nodes within time window
                for j in range(i + 1, min(i + 50, len(nodes))):
                    other = nodes[j]
                    delta_ms = (other["timestamp"] - ts) * 1000
                    
                    if delta_ms > self.PRECEDES_MAX_DELTA:
                        break
                    
                    if delta_ms <= self.COINCIDENCE_THRESHOLD:
                        edge_type = EdgeType.COINCIDES_WITH
                    else:
                        edge_type = EdgeType.PRECEDES
                    
                    edge = Edge(
                        edge_id="",
                        edge_type=edge_type,
                        source_id=node_id,
                        target_id=other["node_id"],
                        timestamp=ts,
                        time_delta=delta_ms
                    )
                    self.add_edge(edge)
                
                # Check for anomalous gap from previous
                if i > 0:
                    prev_ts = nodes[i-1]["timestamp"]
                    gap_ms = (ts - prev_ts) * 1000
                    
                    if gap_ms > self.ANOMALOUS_GAP_THRESHOLD:
                        edge = Edge(
                            edge_id="",
                            edge_type=EdgeType.ANOMALOUS_DELTA,
                            source_id=nodes[i-1]["node_id"],
                            target_id=node_id,
                            timestamp=ts,
                            time_delta=gap_ms,
                            is_anomalous=True,
                            anomaly_score=min(1.0, gap_ms / (self.ANOMALOUS_GAP_THRESHOLD * 10))
                        )
                        self.add_edge(edge)
    
    def find_causal_chains(self, start_id: str, max_depth: int = 10) -> List[List[str]]:
        """Find causal chains from a starting node."""
        causal_types = [e for e in EdgeType if is_causal_edge(e)]
        chains = []
        
        def dfs(current: str, path: List[str], depth: int):
            if depth >= max_depth:
                if len(path) > 1:
                    chains.append(path.copy())
                return
            
            neighbors = self.get_neighbors(current, edge_types=causal_types, direction="outgoing")
            
            if not neighbors:
                if len(path) > 1:
                    chains.append(path.copy())
                return
            
            for neighbor_id, _ in neighbors:
                if neighbor_id not in path:
                    path.append(neighbor_id)
                    dfs(neighbor_id, path, depth + 1)
                    path.pop()
        
        dfs(start_id, [start_id], 0)
        return chains
    
    def get_anomalous_edges(self, min_score: float = 0.5) -> List[Edge]:
        """Get edges marked as anomalous."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT * FROM edges 
                WHERE case_id = ? AND is_anomalous = 1 AND anomaly_score >= ?
                ORDER BY anomaly_score DESC
            """, (self.case_id, min_score)).fetchall()
            
            return [self._row_to_edge(row) for row in rows]
    
    def get_state_hash(self) -> str:
        """Get hash of current graph state for provenance."""
        with self._connect() as conn:
            node_count = conn.execute(
                "SELECT COUNT(*) FROM nodes WHERE case_id = ?", (self.case_id,)
            ).fetchone()[0]
            
            edge_count = conn.execute(
                "SELECT COUNT(*) FROM edges WHERE case_id = ?", (self.case_id,)
            ).fetchone()[0]
            
            latest = conn.execute(
                "SELECT MAX(timestamp) FROM nodes WHERE case_id = ?", (self.case_id,)
            ).fetchone()[0] or 0
        
        content = f"{self.case_id}:{node_count}:{edge_count}:{latest}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def serialize_for_llm(self, subgraph: Dict[str, Any], max_chars: int = 8000) -> str:
        """Serialize subgraph for LLM context."""
        lines = [f"=== Graph Context (hash: {self.get_state_hash()}) ===\n"]
        
        # Group nodes by type
        nodes_by_type: Dict[str, List] = {}
        for node in subgraph.get("nodes", []):
            t = node.get("type", "unknown")
            nodes_by_type.setdefault(t, []).append(node)
        
        lines.append("NODES:")
        for node_type, nodes in nodes_by_type.items():
            lines.append(f"\n  [{node_type.upper()}]")
            for node in nodes[:10]:
                props = node.get("properties", {})
                ts = datetime.fromtimestamp(node.get("timestamp", 0)).isoformat()
                
                if node_type == "process":
                    lines.append(f"    - {node['id']}: {props.get('name', '?')} @ {ts}")
                elif node_type == "file":
                    lines.append(f"    - {node['id']}: {props.get('path', '?')[:50]} @ {ts}")
                elif node_type == "network":
                    lines.append(f"    - {node['id']}: {props.get('remote_ip', '?')}:{props.get('remote_port', '?')}")
                else:
                    lines.append(f"    - {node['id']} @ {ts}")
        
        edges = subgraph.get("edges", [])
        anomalous = [e for e in edges if e.get("is_anomalous")]
        
        if anomalous:
            lines.append(f"\nANOMALOUS EDGES ({len(anomalous)}):")
            for edge in anomalous[:10]:
                lines.append(f"  - {edge['source']} --{edge['type']}--> {edge['target']} "
                           f"(score: {edge.get('anomaly_score', 0):.2f})")
        
        lines.append(f"\nNORMAL EDGES: {len(edges) - len(anomalous)}")
        
        result = "\n".join(lines)
        if len(result) > max_chars:
            result = result[:max_chars] + "\n[truncated]"
        
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        with self._connect() as conn:
            return {
                "case_id": self.case_id,
                "node_count": conn.execute(
                    "SELECT COUNT(*) FROM nodes WHERE case_id = ?", (self.case_id,)
                ).fetchone()[0],
                "edge_count": conn.execute(
                    "SELECT COUNT(*) FROM edges WHERE case_id = ?", (self.case_id,)
                ).fetchone()[0],
                "anomalous_edges": conn.execute(
                    "SELECT COUNT(*) FROM edges WHERE case_id = ? AND is_anomalous = 1", 
                    (self.case_id,)
                ).fetchone()[0],
                "graph_hash": self.get_state_hash()
            }
