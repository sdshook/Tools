"""
State encoder for world model.
"""

import numpy as np
from typing import Dict, List, Any
from datetime import datetime


class StateEncoder:
    """
    Encodes graph subgraphs into state vectors.
    
    64-dimensional encoding:
    [0-5]:   Node type distribution
    [6-14]:  Edge type distribution  
    [15-20]: Temporal features
    [21-26]: Activity features
    [27-32]: Anomaly indicators
    [33-63]: Reserved
    """
    
    DIM = 64
    
    NODE_TYPES = ["process", "file", "network", "registry", "user", "service"]
    EDGE_TYPES = ["spawned_by", "wrote_to", "read_from", "connected_to", 
                  "modified", "owned_by", "precedes", "coincides_with", "anomalous_delta"]
    
    def __init__(self):
        self.node_idx = {t: i for i, t in enumerate(self.NODE_TYPES)}
        self.edge_idx = {t: i for i, t in enumerate(self.EDGE_TYPES)}
    
    def encode(self, subgraph: Dict[str, Any]) -> np.ndarray:
        """Encode a subgraph into a state vector."""
        vec = np.zeros(self.DIM, dtype=np.float32)
        
        nodes = subgraph.get("nodes", [])
        edges = subgraph.get("edges", [])
        
        if not nodes:
            return vec
        
        # Node type distribution [0-5]
        for node in nodes:
            ntype = node.get("type", "unknown")
            if ntype in self.node_idx:
                vec[self.node_idx[ntype]] += 1
        
        node_sum = vec[:6].sum()
        if node_sum > 0:
            vec[:6] /= node_sum
        
        # Edge type distribution [6-14]
        for edge in edges:
            etype = edge.get("type", "unknown")
            if etype in self.edge_idx:
                vec[6 + self.edge_idx[etype]] += 1
        
        edge_sum = vec[6:15].sum()
        if edge_sum > 0:
            vec[6:15] /= edge_sum
        
        # Temporal features [15-20]
        timestamps = sorted([n.get("timestamp", 0) for n in nodes if n.get("timestamp")])
        if len(timestamps) > 1:
            deltas = np.diff(timestamps)
            vec[15] = np.mean(deltas) / 3600  # Mean gap (hours)
            vec[16] = np.std(deltas) / 3600 if len(deltas) > 1 else 0
            vec[17] = np.min(deltas) / 60  # Min gap (minutes)
            vec[18] = np.max(deltas) / 3600  # Max gap (hours)
            vec[19] = len([d for d in deltas if d < 1.0]) / len(deltas)  # Burst ratio
            vec[20] = (timestamps[-1] - timestamps[0]) / 86400  # Span (days)
        
        # Activity features [21-26]
        vec[21] = len(nodes) / 50  # Node count
        vec[22] = len(edges) / 100  # Edge count
        vec[23] = len(edges) / max(len(nodes), 1)  # Density
        vec[24] = len(set(n.get("type") for n in nodes)) / 6  # Type diversity
        vec[25] = len(set(e.get("type") for e in edges)) / 9  # Edge diversity
        
        # Anomaly indicators [27-32]
        anomalous = [e for e in edges if e.get("is_anomalous")]
        vec[27] = len(anomalous) / max(len(edges), 1)  # Anomaly ratio
        
        if anomalous:
            scores = [e.get("anomaly_score", 0) for e in anomalous]
            vec[28] = np.max(scores)
            vec[29] = np.mean(scores)
        
        # Process/network ratios
        process_nodes = sum(1 for n in nodes if n.get("type") == "process")
        network_edges = sum(1 for e in edges if "network" in str(e.get("type", "")).lower())
        vec[30] = process_nodes / max(len(nodes), 1)
        vec[31] = network_edges / max(len(edges), 1)
        
        return vec
    
    def encode_evidence(self, evidence_list: List[Dict[str, Any]]) -> np.ndarray:
        """Encode a list of evidence items into a state vector."""
        vec = np.zeros(self.DIM, dtype=np.float32)
        
        if not evidence_list:
            return vec
        
        # Artifact type distribution [0-5]
        type_counts = {}
        for e in evidence_list:
            atype = e.get("artifact_type", "unknown")
            type_counts[atype] = type_counts.get(atype, 0) + 1
        
        type_map = {"process": 0, "file": 1, "network": 2, "registry": 3, "user": 4, "service": 5}
        for atype, count in type_counts.items():
            for key, idx in type_map.items():
                if key in atype.lower():
                    vec[idx] += count
                    break
        
        type_sum = vec[:6].sum()
        if type_sum > 0:
            vec[:6] /= type_sum
        
        # Temporal features
        timestamps = sorted([e.get("timestamp", 0) for e in evidence_list if e.get("timestamp")])
        if len(timestamps) > 1:
            deltas = np.diff(timestamps)
            vec[15] = np.mean(deltas) / 3600
            vec[16] = np.std(deltas) / 3600 if len(deltas) > 1 else 0
            vec[17] = np.min(deltas) / 60
            vec[18] = np.max(deltas) / 3600
            vec[20] = (timestamps[-1] - timestamps[0]) / 86400
        
        # Activity features
        vec[21] = len(evidence_list) / 100
        vec[24] = len(type_counts) / 10
        
        # Confidence features
        confidences = [e.get("confidence", 1.0) for e in evidence_list]
        vec[29] = np.mean(confidences) if confidences else 0
        
        return vec
