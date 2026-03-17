"""
Forensic RL Agent for investigation navigation.
"""

import hashlib
import json
import random
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
import numpy as np

from .actions import Action, ActionResult
from .rewards import RewardCalculator
from ..graph.graph import ForensicGraph
from ..world_model.encoder import StateEncoder
from ..world_model.predictor import AnomalyScorer


@dataclass
class AgentState:
    """Agent's current state representation."""
    node_id: str
    subgraph: Dict[str, Any]
    features: np.ndarray
    step: int = 0
    total_reward: float = 0.0
    iocs: List[str] = field(default_factory=list)
    trajectory: List[str] = field(default_factory=list)


@dataclass  
class TrajectoryStep:
    """Single step in investigation trajectory."""
    step: int
    node_id: str
    action: Action
    reward: float
    world_model_score: float
    analyst_feedback: Optional[str]
    timestamp: float


class ForensicAgent:
    """
    RL Agent for navigating forensic evidence graphs.
    
    Uses simple policy gradient learning (can be upgraded to PPO).
    """
    
    def __init__(self, graph: ForensicGraph, db_path: Path,
                 learning_rate: float = 0.001, epsilon: float = 0.1):
        self.graph = graph
        self.db_path = db_path
        self.learning_rate = learning_rate
        self.epsilon = epsilon  # Exploration rate
        
        self.encoder = StateEncoder()
        self.reward_calc = RewardCalculator()
        
        # Policy parameters (simple linear policy)
        self.state_dim = StateEncoder.DIM
        self.action_dim = len(Action)
        self._init_policy()
        
        # Current investigation state
        self.state: Optional[AgentState] = None
        self.trajectory: List[TrajectoryStep] = []
        self.trajectory_id: Optional[str] = None
        
        self._init_db()
    
    def _init_db(self):
        """Initialize trajectory database."""
        from ..db.schema import TRAJECTORY_SCHEMA
        with self._connect() as conn:
            conn.executescript(TRAJECTORY_SCHEMA)
    
    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    
    def _init_policy(self):
        """Initialize policy parameters."""
        self.W = np.random.randn(self.action_dim, self.state_dim) * 0.01
        self.b = np.zeros(self.action_dim)
        self._load_policy()
    
    def _load_policy(self):
        """Load saved policy if exists."""
        policy_path = self.db_path.parent / "policy.npz"
        if policy_path.exists():
            data = np.load(policy_path)
            self.W = data["W"]
            self.b = data["b"]
    
    def _save_policy(self):
        """Save policy parameters."""
        policy_path = self.db_path.parent / "policy.npz"
        np.savez(policy_path, W=self.W, b=self.b)
    
    def _softmax(self, x: np.ndarray) -> np.ndarray:
        exp_x = np.exp(x - np.max(x))
        return exp_x / exp_x.sum()
    
    def start_investigation(self, start_node_id: str) -> AgentState:
        """Start a new investigation from a node."""
        self.reward_calc.reset()
        self.trajectory = []
        self.trajectory_id = hashlib.sha256(
            f"{self.graph.case_id}:{time.time()}:{start_node_id}".encode()
        ).hexdigest()[:12]
        
        # Get initial subgraph
        subgraph = self.graph.get_subgraph(start_node_id, depth=1)
        features = self.encoder.encode(subgraph)
        
        self.state = AgentState(
            node_id=start_node_id,
            subgraph=subgraph,
            features=features,
            trajectory=[start_node_id]
        )
        
        # Log start
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO trajectories (trajectory_id, case_id, start_time)
                VALUES (?, ?, ?)
            """, (self.trajectory_id, self.graph.case_id, time.time()))
        
        return self.state
    
    def get_action_probs(self) -> np.ndarray:
        """Get action probabilities from current state."""
        logits = self.W @ self.state.features + self.b
        return self._softmax(logits)
    
    def select_action(self, explore: bool = True) -> Action:
        """Select action using epsilon-greedy policy."""
        if explore and random.random() < self.epsilon:
            return random.choice(list(Action))
        
        probs = self.get_action_probs()
        return list(Action)[np.argmax(probs)]
    
    def step(self, action: Action, 
             target_node: Optional[str] = None,
             anomaly_scorer: Optional[AnomalyScorer] = None,
             analyst_feedback: Optional[str] = None) -> Tuple[AgentState, float, bool, Dict]:
        """
        Execute an action.
        
        Args:
            action: Action to execute
            target_node: Target node for PIVOT action
            anomaly_scorer: Anomaly scorer for world model scores
            analyst_feedback: Optional analyst feedback
            
        Returns:
            (next_state, reward, done, info)
        """
        if self.state is None:
            raise ValueError("Call start_investigation first")
        
        # Get world model score
        world_model_score = 0.0
        if anomaly_scorer:
            scores = anomaly_scorer.score_subgraph(self.state.subgraph)
            world_model_score = scores["overall"]
        
        # Calculate reward
        reward, reward_components = self.reward_calc.calculate(
            action=action,
            node_id=self.state.node_id,
            world_model_score=world_model_score,
            analyst_feedback=analyst_feedback,
            total_steps=self.state.step
        )
        
        # Execute action
        done = action == Action.FINISH
        new_node_id = self.state.node_id
        
        if action == Action.PIVOT_TO_NODE and target_node:
            new_node_id = target_node
        elif action == Action.FLAG_IOC:
            if self.state.node_id not in self.state.iocs:
                self.state.iocs.append(self.state.node_id)
        
        # Get new subgraph
        depth = 2 if action == Action.EXPAND_SUBGRAPH else 1
        subgraph = self.graph.get_subgraph(new_node_id, depth=depth)
        features = self.encoder.encode(subgraph)
        
        # Record trajectory step
        step = TrajectoryStep(
            step=self.state.step,
            node_id=self.state.node_id,
            action=action,
            reward=reward,
            world_model_score=world_model_score,
            analyst_feedback=analyst_feedback,
            timestamp=time.time()
        )
        self.trajectory.append(step)
        
        # Update state
        self.state = AgentState(
            node_id=new_node_id,
            subgraph=subgraph,
            features=features,
            step=self.state.step + 1,
            total_reward=self.state.total_reward + reward,
            iocs=self.state.iocs,
            trajectory=self.state.trajectory + [new_node_id]
        )
        
        # Log step
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO trajectory_steps 
                (trajectory_id, step, node_id, action, reward, world_model_score, 
                 analyst_feedback, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.trajectory_id,
                step.step,
                step.node_id,
                step.action.name,
                step.reward,
                step.world_model_score,
                step.analyst_feedback,
                step.timestamp
            ))
        
        # If done, finalize
        if done:
            self._finalize_trajectory()
        
        info = {
            "reward_components": reward_components,
            "world_model_score": world_model_score,
            "iocs_flagged": len(self.state.iocs)
        }
        
        return self.state, reward, done, info
    
    def _finalize_trajectory(self):
        """Finalize and save trajectory."""
        with self._connect() as conn:
            conn.execute("""
                UPDATE trajectories 
                SET end_time = ?, total_reward = ?, num_steps = ?
                WHERE trajectory_id = ?
            """, (time.time(), self.state.total_reward, self.state.step, self.trajectory_id))
    
    def update_policy(self, batch_size: int = 32):
        """Update policy using recent trajectory."""
        if len(self.trajectory) < batch_size:
            return
        
        # Simple policy gradient
        for step in self.trajectory[-batch_size:]:
            action_idx = list(Action).index(step.action)
            probs = self._softmax(self.W @ self.encoder.encode({"nodes": [], "edges": []}) + self.b)
            
            # Gradient of log probability
            grad = np.zeros(self.action_dim)
            grad[action_idx] = 1 - probs[action_idx]
            
            # Update (REINFORCE)
            # Note: This is simplified; real implementation would use proper state features
            self.W[action_idx] += self.learning_rate * step.reward * grad[action_idx]
        
        self._save_policy()
        self.epsilon = max(0.01, self.epsilon * 0.99)  # Decay exploration
    
    def get_trajectory_report(self) -> Dict[str, Any]:
        """Get trajectory data for report."""
        return {
            "trajectory_id": self.trajectory_id,
            "case_id": self.graph.case_id,
            "steps": [
                {
                    "step": s.step,
                    "node_id": s.node_id,
                    "action": s.action.name,
                    "reward": s.reward,
                    "world_model_score": s.world_model_score,
                    "analyst_feedback": s.analyst_feedback
                }
                for s in self.trajectory
            ],
            "total_reward": self.state.total_reward if self.state else 0,
            "iocs_flagged": self.state.iocs if self.state else [],
            "policy_hash": hashlib.sha256(self.W.tobytes()).hexdigest()[:12]
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*), AVG(total_reward) FROM trajectories WHERE case_id = ?",
                (self.graph.case_id,)
            ).fetchone()
        
        return {
            "total_investigations": total[0] or 0,
            "avg_reward": total[1] or 0,
            "epsilon": self.epsilon,
            "current_step": self.state.step if self.state else 0
        }
