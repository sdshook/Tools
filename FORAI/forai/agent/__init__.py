"""Agent module - RL agents for forensic investigation."""

from .actions import Action, ActionResult
from .rewards import RewardCalculator
from .agent import ForensicAgent, AgentState, TrajectoryStep

# Factory for agent selection
def create_agent(graph, db_path, anomaly_scorer=None, agent_type="auto", **kwargs):
    """
    Create agent with specified type.
    
    Args:
        graph: ForensicGraph instance
        db_path: Path to database
        anomaly_scorer: Optional anomaly scorer for world model
        agent_type: "ppo", "policy_gradient", or "auto"
        **kwargs: Additional arguments for agent
        
    Returns:
        ForensicAgent or PPOForensicAgent
    """
    if agent_type == "ppo":
        from .ppo_agent import PPOForensicAgent
        return PPOForensicAgent(graph, db_path, anomaly_scorer, **kwargs)
    elif agent_type == "policy_gradient":
        return ForensicAgent(graph, db_path, **kwargs)
    else:  # auto - try PPO, fall back to policy gradient
        try:
            from .ppo_agent import PPOForensicAgent
            return PPOForensicAgent(graph, db_path, anomaly_scorer, **kwargs)
        except ImportError:
            return ForensicAgent(graph, db_path, **kwargs)

__all__ = [
    "Action", "ActionResult", "RewardCalculator",
    "ForensicAgent", "AgentState", "TrajectoryStep",
    "create_agent"
]
