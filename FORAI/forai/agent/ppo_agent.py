"""
PPO-based Forensic Agent using stable-baselines3.

This provides a more sophisticated RL approach compared to the
simple policy gradient in agent.py. PPO offers:
- Better sample efficiency
- More stable training
- Automatic entropy regularization
"""

import hashlib
import json
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

# Check for stable-baselines3 and gymnasium
HAS_SB3 = False
try:
    import gymnasium as gym
    from gymnasium import spaces
    from stable_baselines3 import PPO
    from stable_baselines3.common.callbacks import BaseCallback
    HAS_SB3 = True
except ImportError:
    gym = None
    spaces = None
    PPO = None
    BaseCallback = object


@dataclass
class PPOAgentState:
    """Agent's current state representation."""
    node_id: str
    subgraph: Dict[str, Any]
    features: np.ndarray
    step: int = 0
    total_reward: float = 0.0
    iocs: List[str] = field(default_factory=list)
    trajectory: List[str] = field(default_factory=list)


@dataclass
class PPOTrajectoryStep:
    """Single step in investigation trajectory."""
    step: int
    node_id: str
    action: Action
    reward: float
    world_model_score: float
    analyst_feedback: Optional[str]
    timestamp: float


class _AnalystFeedbackCallback:
    """Callback for incorporating analyst feedback during training."""
    
    def __init__(self, verbose=0):
        self.verbose = verbose
        self.feedback_queue: List[Tuple[str, float]] = []
    
    def add_feedback(self, feedback: str, reward_modifier: float = 0.0):
        """Add analyst feedback to queue."""
        self.feedback_queue.append((feedback, reward_modifier))
    
    def _on_step(self) -> bool:
        """Called at each step."""
        if self.feedback_queue and hasattr(self, 'training_env'):
            feedback, modifier = self.feedback_queue.pop(0)
            for env in self.training_env.envs:
                if hasattr(env, 'analyst_feedback'):
                    env.analyst_feedback = feedback
        return True


class PPOForensicAgent:
    """
    PPO-based RL Agent for forensic investigation.
    
    Uses stable-baselines3's PPO implementation with:
    - Custom forensic environment
    - World model integration
    - Analyst feedback loop
    - Full trajectory logging
    """
    
    def __init__(self, graph: ForensicGraph, db_path: Path,
                 anomaly_scorer: Optional[AnomalyScorer] = None,
                 learning_rate: float = 3e-4,
                 n_steps: int = 2048,
                 batch_size: int = 64,
                 n_epochs: int = 10,
                 gamma: float = 0.99,
                 gae_lambda: float = 0.95,
                 clip_range: float = 0.2,
                 ent_coef: float = 0.01):
        
        if not HAS_SB3:
            raise ImportError(
                "stable-baselines3 not installed. Install with:\n"
                "pip install 'stable-baselines3[extra]' gymnasium"
            )
        
        self.graph = graph
        self.db_path = db_path
        self.anomaly_scorer = anomaly_scorer
        
        # Create environment
        self.env = _create_forensic_env(graph, anomaly_scorer)
        
        # Create PPO model
        self.model = PPO(
            "MlpPolicy",
            self.env,
            learning_rate=learning_rate,
            n_steps=n_steps,
            batch_size=batch_size,
            n_epochs=n_epochs,
            gamma=gamma,
            gae_lambda=gae_lambda,
            clip_range=clip_range,
            ent_coef=ent_coef,
            verbose=1,
            tensorboard_log=str(db_path.parent / "tensorboard_logs")
        )
        
        # Feedback callback
        self.feedback_callback = _AnalystFeedbackCallback()
        
        # Investigation state
        self.state: Optional[PPOAgentState] = None
        self.trajectory: List[PPOTrajectoryStep] = []
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
    
    def train(self, total_timesteps: int = 10000, 
              progress_bar: bool = True) -> Dict[str, Any]:
        """Train the PPO agent."""
        self.model.learn(
            total_timesteps=total_timesteps,
            progress_bar=progress_bar
        )
        return {
            "timesteps": total_timesteps,
            "policy_type": "PPO",
            "model_path": str(self.db_path.parent / "ppo_model")
        }
    
    def save_model(self, path: Optional[Path] = None):
        """Save trained model."""
        save_path = path or (self.db_path.parent / "ppo_model")
        self.model.save(str(save_path))
    
    def load_model(self, path: Optional[Path] = None):
        """Load trained model."""
        load_path = path or (self.db_path.parent / "ppo_model")
        if Path(str(load_path) + ".zip").exists():
            self.model = PPO.load(str(load_path), env=self.env)
    
    def start_investigation(self, start_node_id: str) -> PPOAgentState:
        """Start a new investigation from a node."""
        self.trajectory = []
        self.trajectory_id = hashlib.sha256(
            f"{self.graph.case_id}:{time.time()}:{start_node_id}".encode()
        ).hexdigest()[:12]
        
        obs, info = self.env.reset(options={"start_node": start_node_id})
        subgraph = self.graph.get_subgraph(start_node_id, depth=1)
        
        self.state = PPOAgentState(
            node_id=start_node_id,
            subgraph=subgraph,
            features=obs,
            trajectory=[start_node_id]
        )
        
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO trajectories (trajectory_id, case_id, start_time)
                VALUES (?, ?, ?)
            """, (self.trajectory_id, self.graph.case_id, time.time()))
        
        return self.state
    
    def select_action(self, deterministic: bool = False) -> Action:
        """Select action using PPO policy."""
        if self.state is None:
            raise ValueError("Call start_investigation first")
        
        action_idx, _ = self.model.predict(
            self.state.features, 
            deterministic=deterministic
        )
        return list(Action)[int(action_idx)]
    
    def step(self, action: Action,
             analyst_feedback: Optional[str] = None) -> Tuple[PPOAgentState, float, bool, Dict]:
        """Execute an action using the environment."""
        if self.state is None:
            raise ValueError("Call start_investigation first")
        
        self.env.analyst_feedback = analyst_feedback
        action_idx = list(Action).index(action)
        obs, reward, terminated, truncated, info = self.env.step(action_idx)
        
        done = terminated or truncated
        
        step_record = PPOTrajectoryStep(
            step=self.state.step,
            node_id=self.state.node_id,
            action=action,
            reward=reward,
            world_model_score=info.get("world_model_score", 0),
            analyst_feedback=analyst_feedback,
            timestamp=time.time()
        )
        self.trajectory.append(step_record)
        
        new_node_id = info.get("node_id", self.state.node_id)
        subgraph = self.graph.get_subgraph(new_node_id, depth=1)
        
        self.state = PPOAgentState(
            node_id=new_node_id,
            subgraph=subgraph,
            features=obs,
            step=self.state.step + 1,
            total_reward=self.state.total_reward + reward,
            iocs=self.env._iocs.copy(),
            trajectory=self.state.trajectory + [new_node_id]
        )
        
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO trajectory_steps 
                (trajectory_id, step, node_id, action, reward, world_model_score, 
                 analyst_feedback, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                self.trajectory_id, step_record.step, step_record.node_id, 
                step_record.action.name, step_record.reward, step_record.world_model_score,
                step_record.analyst_feedback, step_record.timestamp
            ))
        
        if done:
            self._finalize_trajectory()
        
        return self.state, reward, done, info
    
    def _finalize_trajectory(self):
        """Finalize and save trajectory."""
        with self._connect() as conn:
            conn.execute("""
                UPDATE trajectories 
                SET end_time = ?, total_reward = ?, num_steps = ?
                WHERE trajectory_id = ?
            """, (time.time(), self.state.total_reward, self.state.step, self.trajectory_id))
    
    def get_action_probs(self) -> np.ndarray:
        """Get action probabilities from current state."""
        if self.state is None:
            return np.ones(len(Action)) / len(Action)
        
        obs = self.state.features.reshape(1, -1)
        distribution = self.model.policy.get_distribution(
            self.model.policy.obs_to_tensor(obs)[0]
        )
        return distribution.distribution.probs.detach().cpu().numpy()[0]
    
    def get_trajectory_report(self) -> Dict[str, Any]:
        """Get trajectory data for report."""
        return {
            "trajectory_id": self.trajectory_id,
            "case_id": self.graph.case_id,
            "agent_type": "PPO",
            "steps": [
                {
                    "step": s.step, "node_id": s.node_id, "action": s.action.name,
                    "reward": s.reward, "world_model_score": s.world_model_score,
                    "analyst_feedback": s.analyst_feedback
                }
                for s in self.trajectory
            ],
            "total_reward": self.state.total_reward if self.state else 0,
            "iocs_flagged": self.state.iocs if self.state else [],
            "model_info": {
                "learning_rate": self.model.learning_rate,
                "gamma": self.model.gamma
            }
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
            "agent_type": "PPO",
            "current_step": self.state.step if self.state else 0,
            "training_timesteps": self.model.num_timesteps
        }


def _create_forensic_env(graph: ForensicGraph, 
                         anomaly_scorer: Optional[AnomalyScorer] = None,
                         max_steps: int = 100):
    """Create ForensicEnv if gymnasium is available."""
    if not HAS_SB3:
        raise ImportError("gymnasium not available")
    
    class ForensicEnv(gym.Env):
        """Gymnasium environment for forensic investigation."""
        
        metadata = {"render_modes": ["human"]}
        
        def __init__(self):
            super().__init__()
            
            self.graph = graph
            self.anomaly_scorer = anomaly_scorer
            self.max_steps = max_steps
            
            self.encoder = StateEncoder()
            self.reward_calc = RewardCalculator()
            
            self.action_space = spaces.Discrete(len(Action))
            self.observation_space = spaces.Box(
                low=-np.inf, high=np.inf,
                shape=(StateEncoder.DIM,), dtype=np.float32
            )
            
            self._current_node: Optional[str] = None
            self._current_subgraph: Optional[Dict] = None
            self._step_count: int = 0
            self._iocs: List[str] = []
            self._trajectory: List[str] = []
            self._neighbor_nodes: List[str] = []
            self.analyst_feedback: Optional[str] = None
        
        def reset(self, seed=None, options=None):
            """Reset environment to initial state."""
            super().reset(seed=seed)
            
            self.reward_calc.reset()
            self._step_count = 0
            self._iocs = []
            self._trajectory = []
            
            start_node = None
            if options and "start_node" in options:
                start_node = options["start_node"]
            else:
                stats = self.graph.get_stats()
                if stats["node_count"] > 0:
                    with self.graph._connect() as conn:
                        row = conn.execute(
                            "SELECT node_id FROM nodes WHERE case_id = ? LIMIT 1",
                            (self.graph.case_id,)
                        ).fetchone()
                        if row:
                            start_node = row[0]
            
            if not start_node:
                return np.zeros(StateEncoder.DIM, dtype=np.float32), {}
            
            self._current_node = start_node
            self._trajectory.append(start_node)
            self._update_state()
            
            obs = self.encoder.encode(self._current_subgraph).astype(np.float32)
            return obs, {"node_id": self._current_node}
        
        def _update_state(self):
            """Update current subgraph and neighbor list."""
            self._current_subgraph = self.graph.get_subgraph(self._current_node, depth=1)
            self._neighbor_nodes = [
                node["id"] for node in self._current_subgraph.get("nodes", [])
                if node["id"] != self._current_node
            ]
        
        def step(self, action_idx: int):
            """Execute action and return (obs, reward, terminated, truncated, info)."""
            action = list(Action)[action_idx]
            
            world_model_score = 0.0
            if self.anomaly_scorer and self._current_subgraph:
                scores = self.anomaly_scorer.score_subgraph(self._current_subgraph)
                world_model_score = scores["overall"]
            
            reward, reward_components = self.reward_calc.calculate(
                action=action,
                node_id=self._current_node,
                world_model_score=world_model_score,
                analyst_feedback=self.analyst_feedback,
                total_steps=self._step_count
            )
            
            feedback_used = self.analyst_feedback
            self.analyst_feedback = None
            
            terminated = action == Action.FINISH
            old_node = self._current_node
            
            if action == Action.PIVOT_TO_NODE and self._neighbor_nodes:
                self._current_node = self._select_pivot_target()
                self._trajectory.append(self._current_node)
            elif action == Action.FLAG_IOC:
                if self._current_node not in self._iocs:
                    self._iocs.append(self._current_node)
            elif action == Action.EXPAND_SUBGRAPH:
                self._current_subgraph = self.graph.get_subgraph(self._current_node, depth=2)
                self._neighbor_nodes = [
                    node["id"] for node in self._current_subgraph.get("nodes", [])
                    if node["id"] != self._current_node
                ]
            
            self._step_count += 1
            truncated = self._step_count >= self.max_steps
            
            if self._current_node != old_node:
                self._update_state()
            
            obs = self.encoder.encode(self._current_subgraph).astype(np.float32)
            
            info = {
                "node_id": self._current_node,
                "action": action.name,
                "reward_components": reward_components,
                "world_model_score": world_model_score,
                "iocs_flagged": len(self._iocs),
                "analyst_feedback": feedback_used
            }
            
            return obs, reward, terminated, truncated, info
        
        def _select_pivot_target(self) -> str:
            """Select target node for pivot action."""
            if not self._neighbor_nodes:
                return self._current_node
            
            if self.anomaly_scorer:
                best_score = -1
                best_node = self._neighbor_nodes[0]
                
                for node_id in self._neighbor_nodes[:10]:
                    subgraph = self.graph.get_subgraph(node_id, depth=1)
                    scores = self.anomaly_scorer.score_subgraph(subgraph)
                    if scores["overall"] > best_score:
                        best_score = scores["overall"]
                        best_node = node_id
                
                return best_node
            
            return self._neighbor_nodes[np.random.randint(len(self._neighbor_nodes))]
        
        def render(self, mode="human"):
            """Render current state."""
            if mode == "human":
                print(f"Step {self._step_count}: Node={self._current_node}, "
                      f"IOCs={len(self._iocs)}, Neighbors={len(self._neighbor_nodes)}")
    
    return ForensicEnv()


def create_agent(graph: ForensicGraph, db_path: Path,
                 anomaly_scorer: Optional[AnomalyScorer] = None,
                 agent_type: str = "auto", **kwargs):
    """
    Factory function to create appropriate agent.
    
    Args:
        graph: Forensic graph instance
        db_path: Path to database
        anomaly_scorer: Optional anomaly scorer
        agent_type: "ppo", "policy_gradient", or "auto"
    """
    if agent_type == "ppo":
        return PPOForensicAgent(graph, db_path, anomaly_scorer, **kwargs)
    elif agent_type == "policy_gradient":
        from .agent import ForensicAgent
        return ForensicAgent(graph, db_path, **kwargs)
    else:
        try:
            return PPOForensicAgent(graph, db_path, anomaly_scorer, **kwargs)
        except ImportError:
            from .agent import ForensicAgent
            return ForensicAgent(graph, db_path, **kwargs)
