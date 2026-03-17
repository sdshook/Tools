"""
Kuzu native graph database backend for FORAI.

Kuzu is an embedded graph database optimized for analytical queries.
This provides native graph operations instead of SQLite table joins.
"""

import hashlib
import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from .nodes import Node, NodeType
from .edges import Edge, EdgeType, is_causal_edge


class KuzuGraph:
    """
    Temporal Knowledge Graph using Kuzu native graph database.
    
    Provides the same interface as ForensicGraph but with native
    graph traversal operations for better performance on path queries.
    """
    
    COINCIDENCE_THRESHOLD = 1000      # 1 second (ms)
    PRECEDES_MAX_DELTA = 60000        # 1 minute (ms)
    ANOMALOUS_GAP_THRESHOLD = 300000  # 5 minutes (ms)
    
    def __init__(self, db_path: Path, case_id: str):
        self.db_path = db_path
        self.case_id = case_id
        self._db = None
        self._conn = None
        self._init_db()
    
    def _init_db(self):
        """Initialize Kuzu database with schema."""
        try:
            import kuzu
        except ImportError:
            raise ImportError(
                "Kuzu not installed. Install with: pip install kuzu\n"
                "Or use ForensicGraph (SQLite backend) instead."
            )
        
        # Create database directory
        db_dir = self.db_path.parent / f"kuzu_{self.case_id}"
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self._db = kuzu.Database(str(db_dir))
        self._conn = kuzu.Connection(self._db)
        
        # Create node tables for each type
        self._conn.execute("""
            CREATE NODE TABLE IF NOT EXISTS ForensicNode(
                node_id STRING,
                case_id STRING,
                node_type STRING,
                timestamp DOUBLE,
                properties STRING,
                confidence DOUBLE,
                hash STRING,
                PRIMARY KEY(node_id)
            )
        """)
        
        # Create relationship tables for each edge type
        self._conn.execute("""
            CREATE REL TABLE IF NOT EXISTS FORENSIC_EDGE(
                FROM ForensicNode TO ForensicNode,
                edge_id STRING,
                case_id STRING,
                edge_type STRING,
                timestamp DOUBLE,
                time_delta DOUBLE,
                is_anomalous BOOLEAN,
                anomaly_score DOUBLE,
                properties STRING
            )
        """)
    
    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn = None
        if self._db:
            self._db = None
    
    def add_node(self, node: Node) -> str:
        """Add node to graph."""
        # Check if node exists, update if so
        result = self._conn.execute(
            "MATCH (n:ForensicNode {node_id: $id}) RETURN n.node_id",
            {"id": node.node_id}
        )
        
        if result.has_next():
            # Update existing
            self._conn.execute("""
                MATCH (n:ForensicNode {node_id: $id})
                SET n.timestamp = $ts, n.properties = $props, 
                    n.confidence = $conf, n.hash = $hash
            """, {
                "id": node.node_id,
                "ts": node.timestamp,
                "props": json.dumps(node.properties),
                "conf": node.confidence,
                "hash": node.hash
            })
        else:
            # Insert new
            self._conn.execute("""
                CREATE (n:ForensicNode {
                    node_id: $id,
                    case_id: $case,
                    node_type: $type,
                    timestamp: $ts,
                    properties: $props,
                    confidence: $conf,
                    hash: $hash
                })
            """, {
                "id": node.node_id,
                "case": self.case_id,
                "type": node.node_type.value,
                "ts": node.timestamp,
                "props": json.dumps(node.properties),
                "conf": node.confidence,
                "hash": node.hash
            })
        
        return node.node_id
    
    def add_edge(self, edge: Edge) -> str:
        """Add edge to graph."""
        # Generate edge_id if not provided
        if not edge.edge_id:
            edge_id = hashlib.sha256(
                f"{edge.source_id}:{edge.target_id}:{edge.edge_type.value}:{edge.timestamp}".encode()
            ).hexdigest()[:16]
        else:
            edge_id = edge.edge_id
        
        # Ensure both nodes exist
        for node_id in [edge.source_id, edge.target_id]:
            result = self._conn.execute(
                "MATCH (n:ForensicNode {node_id: $id}) RETURN n",
                {"id": node_id}
            )
            if not result.has_next():
                # Create placeholder node
                self._conn.execute("""
                    CREATE (n:ForensicNode {
                        node_id: $id, case_id: $case, node_type: 'unknown',
                        timestamp: 0, properties: '{}', confidence: 0, hash: ''
                    })
                """, {"id": node_id, "case": self.case_id})
        
        # Create edge
        self._conn.execute("""
            MATCH (a:ForensicNode {node_id: $src}), (b:ForensicNode {node_id: $tgt})
            CREATE (a)-[e:FORENSIC_EDGE {
                edge_id: $eid,
                case_id: $case,
                edge_type: $type,
                timestamp: $ts,
                time_delta: $delta,
                is_anomalous: $anom,
                anomaly_score: $score,
                properties: $props
            }]->(b)
        """, {
            "src": edge.source_id,
            "tgt": edge.target_id,
            "eid": edge_id,
            "case": self.case_id,
            "type": edge.edge_type.value,
            "ts": edge.timestamp,
            "delta": edge.time_delta,
            "anom": edge.is_anomalous,
            "score": edge.anomaly_score,
            "props": json.dumps(edge.properties)
        })
        
        return edge_id
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID."""
        result = self._conn.execute("""
            MATCH (n:ForensicNode {node_id: $id, case_id: $case})
            RETURN n.node_id, n.node_type, n.timestamp, n.properties, 
                   n.confidence, n.hash
        """, {"id": node_id, "case": self.case_id})
        
        if result.has_next():
            row = result.get_next()
            return Node(
                node_id=row[0],
                node_type=NodeType(row[1]) if row[1] != 'unknown' else NodeType.PROCESS,
                timestamp=row[2],
                properties=json.loads(row[3]) if row[3] else {},
                confidence=row[4],
                hash=row[5]
            )
        return None
    
    def get_neighbors(self, node_id: str,
                     edge_types: Optional[List[EdgeType]] = None,
                     direction: str = "both") -> List[Tuple[str, Edge]]:
        """Get neighboring nodes using native graph traversal."""
        neighbors = []
        
        # Build edge type filter
        type_filter = ""
        if edge_types:
            types = [f"'{e.value}'" for e in edge_types]
            type_filter = f"AND e.edge_type IN [{', '.join(types)}]"
        
        if direction in ("outgoing", "both"):
            result = self._conn.execute(f"""
                MATCH (a:ForensicNode {{node_id: $id, case_id: $case}})-[e:FORENSIC_EDGE]->(b:ForensicNode)
                WHERE e.case_id = $case {type_filter}
                RETURN b.node_id, e.edge_id, e.edge_type, e.timestamp, e.time_delta,
                       e.is_anomalous, e.anomaly_score, e.properties, a.node_id
            """, {"id": node_id, "case": self.case_id})
            
            while result.has_next():
                row = result.get_next()
                edge = Edge(
                    edge_id=row[1],
                    edge_type=EdgeType(row[2]),
                    source_id=row[8],
                    target_id=row[0],
                    timestamp=row[3],
                    time_delta=row[4],
                    is_anomalous=row[5],
                    anomaly_score=row[6],
                    properties=json.loads(row[7]) if row[7] else {}
                )
                neighbors.append((row[0], edge))
        
        if direction in ("incoming", "both"):
            result = self._conn.execute(f"""
                MATCH (a:ForensicNode)-[e:FORENSIC_EDGE]->(b:ForensicNode {{node_id: $id, case_id: $case}})
                WHERE e.case_id = $case {type_filter}
                RETURN a.node_id, e.edge_id, e.edge_type, e.timestamp, e.time_delta,
                       e.is_anomalous, e.anomaly_score, e.properties, b.node_id
            """, {"id": node_id, "case": self.case_id})
            
            while result.has_next():
                row = result.get_next()
                edge = Edge(
                    edge_id=row[1],
                    edge_type=EdgeType(row[2]),
                    source_id=row[0],
                    target_id=row[8],
                    timestamp=row[3],
                    time_delta=row[4],
                    is_anomalous=row[5],
                    anomaly_score=row[6],
                    properties=json.loads(row[7]) if row[7] else {}
                )
                neighbors.append((row[0], edge))
        
        return neighbors
    
    def get_subgraph(self, center_id: str, depth: int = 2,
                    max_nodes: int = 50) -> Dict[str, Any]:
        """
        Extract subgraph using Kuzu's native path traversal.
        
        This is more efficient than the BFS approach in SQLite.
        """
        # Use recursive pattern matching for subgraph extraction
        result = self._conn.execute(f"""
            MATCH path = (center:ForensicNode {{node_id: $id, case_id: $case}})
                         -[e:FORENSIC_EDGE*1..{depth}]-
                         (neighbor:ForensicNode)
            WHERE neighbor.case_id = $case
            RETURN DISTINCT neighbor.node_id, neighbor.node_type, neighbor.timestamp,
                   neighbor.properties, neighbor.confidence, neighbor.hash
            LIMIT {max_nodes}
        """, {"id": center_id, "case": self.case_id})
        
        nodes = []
        visited_ids = {center_id}
        
        # Add center node
        center = self.get_node(center_id)
        if center:
            nodes.append(center.to_dict())
        
        # Add neighbors
        while result.has_next():
            row = result.get_next()
            if row[0] not in visited_ids:
                visited_ids.add(row[0])
                nodes.append({
                    "id": row[0],
                    "type": row[1],
                    "timestamp": row[2],
                    "properties": json.loads(row[3]) if row[3] else {},
                    "confidence": row[4],
                    "hash": row[5]
                })
        
        # Get edges between visited nodes
        edges = []
        if len(visited_ids) > 1:
            ids_list = list(visited_ids)
            result = self._conn.execute("""
                MATCH (a:ForensicNode)-[e:FORENSIC_EDGE]->(b:ForensicNode)
                WHERE a.node_id IN $ids AND b.node_id IN $ids AND e.case_id = $case
                RETURN e.edge_id, e.edge_type, a.node_id, b.node_id, e.timestamp,
                       e.time_delta, e.is_anomalous, e.anomaly_score, e.properties
            """, {"ids": ids_list, "case": self.case_id})
            
            while result.has_next():
                row = result.get_next()
                edges.append({
                    "id": row[0],
                    "type": row[1],
                    "source": row[2],
                    "target": row[3],
                    "timestamp": row[4],
                    "time_delta": row[5],
                    "is_anomalous": row[6],
                    "anomaly_score": row[7],
                    "properties": json.loads(row[8]) if row[8] else {}
                })
        
        return {"nodes": nodes, "edges": edges, "center": center_id}
    
    def find_causal_chains(self, start_id: str, max_depth: int = 10) -> List[List[str]]:
        """
        Find causal chains using Kuzu's native path queries.
        
        This is significantly faster than recursive DFS in Python.
        """
        causal_types = [e.value for e in EdgeType if is_causal_edge(e)]
        types_str = ", ".join(f"'{t}'" for t in causal_types)
        
        result = self._conn.execute(f"""
            MATCH path = (start:ForensicNode {{node_id: $id, case_id: $case}})
                         -[e:FORENSIC_EDGE*1..{max_depth}]->
                         (end:ForensicNode)
            WHERE ALL(edge IN e WHERE edge.edge_type IN [{types_str}])
            RETURN [node IN nodes(path) | node.node_id] AS chain
        """, {"id": start_id, "case": self.case_id})
        
        chains = []
        while result.has_next():
            row = result.get_next()
            if len(row[0]) > 1:
                chains.append(row[0])
        
        return chains
    
    def infer_temporal_edges(self):
        """Infer temporal edges from timestamps."""
        # Get all nodes ordered by timestamp
        result = self._conn.execute("""
            MATCH (n:ForensicNode {case_id: $case})
            RETURN n.node_id, n.node_type, n.timestamp
            ORDER BY n.timestamp
        """, {"case": self.case_id})
        
        nodes = []
        while result.has_next():
            row = result.get_next()
            nodes.append({"node_id": row[0], "node_type": row[1], "timestamp": row[2]})
        
        for i, node in enumerate(nodes):
            ts = node["timestamp"]
            
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
                    source_id=node["node_id"],
                    target_id=other["node_id"],
                    timestamp=ts,
                    time_delta=delta_ms
                )
                self.add_edge(edge)
            
            # Check for anomalous gap
            if i > 0:
                prev_ts = nodes[i-1]["timestamp"]
                gap_ms = (ts - prev_ts) * 1000
                
                if gap_ms > self.ANOMALOUS_GAP_THRESHOLD:
                    edge = Edge(
                        edge_id="",
                        edge_type=EdgeType.ANOMALOUS_DELTA,
                        source_id=nodes[i-1]["node_id"],
                        target_id=node["node_id"],
                        timestamp=ts,
                        time_delta=gap_ms,
                        is_anomalous=True,
                        anomaly_score=min(1.0, gap_ms / (self.ANOMALOUS_GAP_THRESHOLD * 10))
                    )
                    self.add_edge(edge)
    
    def get_anomalous_edges(self, min_score: float = 0.5) -> List[Edge]:
        """Get edges marked as anomalous."""
        result = self._conn.execute("""
            MATCH (a:ForensicNode)-[e:FORENSIC_EDGE]->(b:ForensicNode)
            WHERE e.case_id = $case AND e.is_anomalous = true AND e.anomaly_score >= $min
            RETURN e.edge_id, e.edge_type, a.node_id, b.node_id, e.timestamp,
                   e.time_delta, e.is_anomalous, e.anomaly_score, e.properties
            ORDER BY e.anomaly_score DESC
        """, {"case": self.case_id, "min": min_score})
        
        edges = []
        while result.has_next():
            row = result.get_next()
            edges.append(Edge(
                edge_id=row[0],
                edge_type=EdgeType(row[1]),
                source_id=row[2],
                target_id=row[3],
                timestamp=row[4],
                time_delta=row[5],
                is_anomalous=row[6],
                anomaly_score=row[7],
                properties=json.loads(row[8]) if row[8] else {}
            ))
        return edges
    
    def get_state_hash(self) -> str:
        """Get hash of current graph state."""
        result = self._conn.execute("""
            MATCH (n:ForensicNode {case_id: $case})
            RETURN COUNT(n) as node_count, MAX(n.timestamp) as latest
        """, {"case": self.case_id})
        
        row = result.get_next() if result.has_next() else [0, 0]
        node_count = row[0] or 0
        latest = row[1] or 0
        
        result = self._conn.execute("""
            MATCH ()-[e:FORENSIC_EDGE {case_id: $case}]->()
            RETURN COUNT(e)
        """, {"case": self.case_id})
        
        edge_count = result.get_next()[0] if result.has_next() else 0
        
        content = f"{self.case_id}:{node_count}:{edge_count}:{latest}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def serialize_for_llm(self, subgraph: Dict[str, Any], max_chars: int = 8000) -> str:
        """Serialize subgraph for LLM context."""
        lines = [f"=== Graph Context (hash: {self.get_state_hash()}) ===\n"]
        
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
        result = self._conn.execute("""
            MATCH (n:ForensicNode {case_id: $case})
            RETURN COUNT(n)
        """, {"case": self.case_id})
        node_count = result.get_next()[0] if result.has_next() else 0
        
        result = self._conn.execute("""
            MATCH ()-[e:FORENSIC_EDGE {case_id: $case}]->()
            RETURN COUNT(e), COUNT(CASE WHEN e.is_anomalous THEN 1 END)
        """, {"case": self.case_id})
        row = result.get_next() if result.has_next() else [0, 0]
        
        return {
            "case_id": self.case_id,
            "node_count": node_count,
            "edge_count": row[0],
            "anomalous_edges": row[1],
            "graph_hash": self.get_state_hash(),
            "backend": "kuzu"
        }


def create_graph(db_path: Path, case_id: str, backend: str = "auto"):
    """
    Factory function to create appropriate graph backend.
    
    Args:
        db_path: Path to database file/directory
        case_id: Case identifier
        backend: "kuzu", "sqlite", or "auto" (try kuzu, fall back to sqlite)
    """
    if backend == "kuzu":
        return KuzuGraph(db_path, case_id)
    elif backend == "sqlite":
        from .graph import ForensicGraph
        return ForensicGraph(db_path, case_id)
    else:  # auto
        try:
            return KuzuGraph(db_path, case_id)
        except ImportError:
            from .graph import ForensicGraph
            return ForensicGraph(db_path, case_id)
