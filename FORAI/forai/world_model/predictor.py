"""
State transition predictor for world model.
"""

import hashlib
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterator, Any
import numpy as np

from .encoder import StateEncoder


class TransitionPredictor:
    """
    Predicts P(next_state | current_state) based on learned transitions.
    """
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
        self._cache: Dict[str, Dict[str, int]] = {}
    
    def _init_db(self):
        """Initialize database."""
        from ..db.schema import WORLD_MODEL_SCHEMA
        with self._connect() as conn:
            conn.executescript(WORLD_MODEL_SCHEMA)
    
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _hash_state(self, state: np.ndarray) -> str:
        """Hash a state vector (quantized)."""
        quantized = np.round(state * 10).astype(int)
        return hashlib.md5(quantized.tobytes()).hexdigest()[:12]
    
    def record_transition(self, from_state: np.ndarray, to_state: np.ndarray, 
                         is_baseline: bool = False):
        """Record an observed transition."""
        from_hash = self._hash_state(from_state)
        to_hash = self._hash_state(to_state)
        
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO state_transitions (from_state_hash, to_state_hash, is_baseline)
                VALUES (?, ?, ?)
                ON CONFLICT(from_state_hash, to_state_hash) DO UPDATE SET
                    count = count + 1
            """, (from_hash, to_hash, 1 if is_baseline else 0))
        
        # Update cache
        if from_hash not in self._cache:
            self._cache[from_hash] = {}
        self._cache[from_hash][to_hash] = self._cache[from_hash].get(to_hash, 0) + 1
    
    def predict_probability(self, from_state: np.ndarray, to_state: np.ndarray) -> float:
        """Predict P(to_state | from_state)."""
        from_hash = self._hash_state(from_state)
        to_hash = self._hash_state(to_state)
        
        # Check cache first
        if from_hash in self._cache:
            trans = self._cache[from_hash]
            total = sum(trans.values())
            if to_hash in trans and total > 0:
                return trans[to_hash] / total
        
        # Fall back to database
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT to_state_hash, count FROM state_transitions
                WHERE from_state_hash = ?
            """, (from_hash,)).fetchall()
            
            if rows:
                total = sum(r[1] for r in rows)
                for row in rows:
                    if row[0] == to_hash:
                        return row[1] / total
        
        return 0.01  # Unknown transition
    
    def get_expected_next(self, from_state: np.ndarray, top_k: int = 5) -> List[Tuple[str, float]]:
        """Get most likely next states."""
        from_hash = self._hash_state(from_state)
        
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT to_state_hash, count FROM state_transitions
                WHERE from_state_hash = ?
                ORDER BY count DESC
                LIMIT ?
            """, (from_hash, top_k)).fetchall()
            
            if rows:
                total = sum(r[1] for r in rows)
                return [(r[0], r[1] / total) for r in rows]
        
        return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get predictor statistics."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*), SUM(count) FROM state_transitions"
            ).fetchone()
            
            baseline = conn.execute(
                "SELECT COUNT(*) FROM state_transitions WHERE is_baseline = 1"
            ).fetchone()[0]
        
        return {
            "unique_transitions": total[0] or 0,
            "total_observations": total[1] or 0,
            "baseline_transitions": baseline,
            "cache_size": len(self._cache)
        }


class AnomalyScorer:
    """
    Scores anomalies based on state deviation and causal plausibility.
    """
    
    def __init__(self, predictor: TransitionPredictor):
        self.predictor = predictor
        self.encoder = StateEncoder()
    
    def score_transition(self, from_state: np.ndarray, to_state: np.ndarray) -> Dict[str, float]:
        """
        Score a state transition for anomaly.
        
        Returns dict with:
        - probability: P(to_state | from_state)
        - deviation: How much this differs from expected
        - anomaly_score: Combined score [0, 1]
        """
        prob = self.predictor.predict_probability(from_state, to_state)
        
        # Get expected probability (max of known transitions)
        expected = self.predictor.get_expected_next(from_state, top_k=1)
        expected_prob = expected[0][1] if expected else 0.5
        
        # Deviation
        deviation = abs(prob - expected_prob)
        
        # Anomaly score
        # Low probability + high deviation = anomalous
        anomaly_score = (1 - prob) * 0.5 + deviation * 0.5
        
        return {
            "probability": prob,
            "expected_probability": expected_prob,
            "deviation": deviation,
            "anomaly_score": anomaly_score,
            "is_anomalous": anomaly_score > 0.5
        }
    
    def score_subgraph(self, subgraph: Dict[str, Any], 
                       history: Optional[List[np.ndarray]] = None) -> Dict[str, float]:
        """
        Score a subgraph for anomaly.
        
        Args:
            subgraph: Graph context
            history: Recent state history
            
        Returns:
            Anomaly scoring dict
        """
        state = self.encoder.encode(subgraph)
        
        scores = {
            "state_anomaly": 0.0,
            "transition_anomaly": 0.0,
            "overall": 0.0
        }
        
        # State-level anomaly indicators
        edges = subgraph.get("edges", [])
        if edges:
            anomalous = [e for e in edges if e.get("is_anomalous")]
            scores["state_anomaly"] = len(anomalous) / len(edges)
        
        # Transition anomaly
        if history and len(history) > 0:
            prev_state = history[-1]
            trans_scores = self.score_transition(prev_state, state)
            scores["transition_anomaly"] = trans_scores["anomaly_score"]
        
        # Overall
        scores["overall"] = scores["state_anomaly"] * 0.4 + scores["transition_anomaly"] * 0.6
        
        return scores
