"""
Reward calculation for RL agent.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from .actions import Action


@dataclass
class RewardWeights:
    """Configurable reward weights."""
    anomaly_confirm: float = 1.0
    analyst_approve: float = 2.0
    analyst_reject: float = -1.0
    false_positive: float = -1.0
    causal_chain: float = 1.5
    exploration: float = 0.05
    redundant: float = -0.1
    efficiency: float = 0.1


class RewardCalculator:
    """
    Calculates rewards for agent actions.
    
    Rewards:
    - anomaly_confirmation: World model agrees with IOC flag
    - analyst_approval: Human approves finding
    - causal_chain: Connected evidence chain found
    - efficiency: Fewer steps to find IOCs
    """
    
    def __init__(self, weights: RewardWeights = None):
        self.weights = weights or RewardWeights()
        self._visited: Set[str] = set()
        self._flagged: Set[str] = set()
    
    def calculate(self, action: Action, 
                  node_id: str,
                  world_model_score: float = 0.0,
                  analyst_feedback: Optional[str] = None,
                  causal_chain_length: int = 0,
                  total_steps: int = 0) -> Tuple[float, Dict[str, float]]:
        """
        Calculate reward for an action.
        
        Args:
            action: Action taken
            node_id: Current node ID
            world_model_score: Anomaly score from world model
            analyst_feedback: "approve", "reject", or None
            causal_chain_length: Length of connected evidence chain
            total_steps: Total steps taken so far
            
        Returns:
            (total_reward, component_breakdown)
        """
        components = {}
        
        if action == Action.FLAG_IOC:
            if world_model_score > 0.5:
                components["anomaly_confirm"] = self.weights.anomaly_confirm * world_model_score
            else:
                components["false_positive"] = self.weights.false_positive * (1 - world_model_score)
            
            if node_id in self._flagged:
                components["redundant"] = self.weights.redundant
            else:
                self._flagged.add(node_id)
        
        elif action == Action.PIVOT_TO_NODE:
            if node_id not in self._visited:
                components["exploration"] = self.weights.exploration
                self._visited.add(node_id)
            else:
                components["redundant"] = self.weights.redundant
        
        elif action == Action.MARK_BENIGN:
            if world_model_score < 0.3:
                components["correct_benign"] = 0.3
            else:
                components["missed_anomaly"] = -0.5
        
        elif action == Action.EXPAND_SUBGRAPH:
            components["exploration"] = self.weights.exploration * 0.5
        
        elif action == Action.FINISH:
            if self._flagged:
                efficiency = max(0, 1 - (total_steps / 100))
                components["efficiency"] = self.weights.efficiency * efficiency
        
        # Analyst feedback (overrides other signals)
        if analyst_feedback == "approve":
            components["analyst_approve"] = self.weights.analyst_approve
        elif analyst_feedback == "reject":
            components["analyst_reject"] = self.weights.analyst_reject
        
        # Causal chain bonus
        if causal_chain_length > 2:
            components["causal_chain"] = self.weights.causal_chain * (causal_chain_length / 10)
        
        total = sum(components.values())
        return total, components
    
    def reset(self):
        """Reset for new investigation."""
        self._visited.clear()
        self._flagged.clear()
    
    @property
    def iocs_flagged(self) -> int:
        return len(self._flagged)
    
    @property
    def nodes_visited(self) -> int:
        return len(self._visited)
