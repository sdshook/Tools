"""
Bidirectional Hebbian Memory (BDH) for FORAI.
"""

import time
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from ..config import get_config


def l2_norm(x: np.ndarray) -> np.ndarray:
    """L2 normalize a vector."""
    norm = np.linalg.norm(x)
    return x / (norm + 1e-12)


def cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between vectors."""
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-12))


@dataclass
class MemoryTrace:
    """A single memory trace in BDH."""
    trace_id: str
    vector: np.ndarray
    valence: float  # -1 (benign) to +1 (threat)
    label: str  # "threat", "benign", "unknown"
    uses: int = 0
    cumulative_reward: float = 0.0
    created: float = 0.0
    updated: float = 0.0


class BDHMemory:
    """
    Bidirectional Hebbian Memory with temporal sequence modeling.
    
    Features:
    - Reward-gated learning
    - Temporal transition tracking
    - Differential threat similarity
    """
    
    def __init__(self, max_traces: int = 1000, learning_rate: float = 0.015):
        config = get_config()
        self.max_traces = max_traces
        self.learning_rate = learning_rate
        self.embed_dim = config.bhsm_embed_dim
        
        # Memory storage
        self.traces: Dict[str, MemoryTrace] = {}
        self.weights: Dict[str, np.ndarray] = {}  # Hebbian weight matrices
        
        # Temporal sequence modeling
        self.transitions: Dict[str, Dict[str, float]] = {}
        self.last_trace_id: Optional[str] = None
        self.temporal_window: List[Tuple[str, float]] = []
        self.max_window = 20
    
    def add_trace(self, trace_id: str, vector: np.ndarray, 
                  valence: float = 0.0, label: str = "unknown"):
        """Add a memory trace."""
        if len(self.traces) >= self.max_traces * 0.9:
            self._prune()
        
        self.traces[trace_id] = MemoryTrace(
            trace_id=trace_id,
            vector=l2_norm(vector.copy()),
            valence=valence,
            label=label,
            created=time.time(),
            updated=time.time()
        )
        self.weights[trace_id] = np.zeros((self.embed_dim, self.embed_dim), dtype=np.float32)
    
    def _prune(self):
        """Prune lowest-quality traces."""
        if len(self.traces) < self.max_traces * 0.8:
            return
        
        # Score by |valence| * uses
        scores = [
            (abs(t.valence) * (t.uses + 1), tid)
            for tid, t in self.traces.items()
        ]
        scores.sort()
        
        # Remove bottom 10%
        n_remove = max(1, len(scores) // 10)
        for _, tid in scores[:n_remove]:
            del self.traces[tid]
            if tid in self.weights:
                del self.weights[tid]
    
    def get_similar(self, query: np.ndarray, top_k: int = 5) -> List[Tuple[float, MemoryTrace]]:
        """Get most similar traces."""
        query_norm = l2_norm(query)
        results = []
        
        for tid, trace in self.traces.items():
            sim = cosine_sim(query_norm, trace.vector)
            results.append((sim, trace))
        
        results.sort(reverse=True, key=lambda x: x[0])
        return results[:top_k]
    
    def compute_differential(self, query: np.ndarray) -> float:
        """
        Compute differential similarity between threat and benign traces.
        
        Returns: value in [-1, 1]
        Positive = threat-leaning, Negative = benign-leaning
        """
        query_norm = l2_norm(query)
        
        threat_sims = []
        benign_sims = []
        
        for trace in self.traces.values():
            sim = cosine_sim(query_norm, trace.vector)
            
            if trace.valence > 0.1 or trace.label == "threat":
                threat_sims.append(sim)
            elif trace.valence < -0.1 or trace.label == "benign":
                benign_sims.append(sim)
        
        if not threat_sims and not benign_sims:
            return 0.0
        
        # Top-3 average
        avg_threat = np.mean(sorted(threat_sims, reverse=True)[:3]) if threat_sims else 0.0
        avg_benign = np.mean(sorted(benign_sims, reverse=True)[:3]) if benign_sims else 0.0
        
        diff = avg_threat - avg_benign
        return float(np.tanh(diff * 5))  # Amplify for discrimination
    
    def record_transition(self, trace_id: str):
        """Record temporal transition from last trace."""
        timestamp = time.time()
        
        if self.last_trace_id and self.last_trace_id != trace_id:
            if self.last_trace_id not in self.transitions:
                self.transitions[self.last_trace_id] = {}
            
            trans = self.transitions[self.last_trace_id]
            trans[trace_id] = trans.get(trace_id, 0) * 0.95 + 0.1
            
            # Normalize
            total = sum(trans.values())
            if total > 0:
                for k in trans:
                    trans[k] /= total
        
        self.temporal_window.append((trace_id, timestamp))
        if len(self.temporal_window) > self.max_window:
            self.temporal_window = self.temporal_window[-self.max_window:]
        
        self.last_trace_id = trace_id
    
    def compute_temporal_context(self, query: np.ndarray) -> float:
        """Compute temporal context score from recent history."""
        if not self.temporal_window:
            return 0.0
        
        query_norm = l2_norm(query)
        weighted_valence = 0.0
        weight_sum = 0.0
        current_time = time.time()
        
        for trace_id, timestamp in reversed(self.temporal_window):
            if trace_id not in self.traces:
                continue
            
            trace = self.traces[trace_id]
            time_weight = 0.8 ** ((current_time - timestamp) / 60)  # Decay over minutes
            sim_weight = cosine_sim(query_norm, trace.vector)
            weight = time_weight * (0.5 + 0.5 * sim_weight)
            
            weighted_valence += trace.valence * weight
            weight_sum += weight
        
        if weight_sum < 1e-12:
            return 0.0
        
        return np.clip(weighted_valence / weight_sum, -1.0, 1.0)
    
    def compute_escalation(self) -> float:
        """Detect threat escalation in recent sequence."""
        if len(self.temporal_window) < 3:
            return 0.0
        
        valences = []
        for trace_id, _ in self.temporal_window[-10:]:
            if trace_id in self.traces:
                valences.append(self.traces[trace_id].valence)
        
        if len(valences) < 3:
            return 0.0
        
        # Linear regression slope
        x = np.arange(len(valences))
        slope = np.polyfit(x, valences, 1)[0]
        
        return np.clip(slope * 10, -1.0, 1.0)
    
    def reward_update(self, trace_id: str, state_vec: np.ndarray, reward: float):
        """Apply reward-gated Hebbian update."""
        if trace_id not in self.traces:
            return
        
        trace = self.traces[trace_id]
        W = self.weights.get(trace_id)
        if W is None:
            return
        
        # Effective learning rate
        eta = self.learning_rate
        if abs(trace.valence) > 0.8:
            eta *= 0.5  # Reduce for high-valence traces
        
        # Hebbian update
        x = trace.vector
        y = l2_norm(state_vec)
        outer = np.outer(x, y)
        
        if reward > 0:
            self.weights[trace_id] = W + eta * reward * outer
        else:
            self.weights[trace_id] = W - eta * abs(reward) * outer
        
        # Update trace
        trace.valence = np.clip(0.9 * trace.valence + 0.1 * reward, -1.0, 1.0)
        trace.uses += 1
        trace.cumulative_reward += reward
        trace.updated = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return {
            "total_traces": len(self.traces),
            "max_traces": self.max_traces,
            "threat_traces": sum(1 for t in self.traces.values() if t.valence > 0.1),
            "benign_traces": sum(1 for t in self.traces.values() if t.valence < -0.1),
            "avg_valence": np.mean([t.valence for t in self.traces.values()]) if self.traces else 0,
            "temporal_window": len(self.temporal_window),
            "transitions": sum(len(t) for t in self.transitions.values())
        }
