"""
RL Agent action space for forensic investigation.
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Any, Dict, Optional


class Action(Enum):
    """Actions available to the forensic investigation agent."""
    PIVOT_TO_NODE = auto()      # Move to a connected node
    EXPAND_SUBGRAPH = auto()    # Expand current neighborhood
    FLAG_IOC = auto()           # Mark current node as indicator of compromise
    REQUEST_LLM = auto()        # Ask LLM for explanation
    MARK_BENIGN = auto()        # Mark current pattern as normal
    FINISH = auto()             # End investigation


@dataclass
class ActionResult:
    """Result of executing an action."""
    action: Action
    success: bool
    node_id: Optional[str] = None
    message: str = ""
    data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.data is None:
            self.data = {}


def action_to_string(action: Action) -> str:
    """Convert action to human-readable string."""
    return {
        Action.PIVOT_TO_NODE: "Pivot to node",
        Action.EXPAND_SUBGRAPH: "Expand subgraph",
        Action.FLAG_IOC: "Flag as IOC",
        Action.REQUEST_LLM: "Request LLM explanation",
        Action.MARK_BENIGN: "Mark as benign",
        Action.FINISH: "Finish investigation"
    }.get(action, str(action))
