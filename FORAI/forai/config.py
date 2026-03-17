"""
FORAI Configuration
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os


@dataclass
class Config:
    """Global configuration for FORAI."""
    
    # Paths
    base_dir: Path = field(default_factory=lambda: Path(os.environ.get("FORAI_BASE", "D:/FORAI")))
    
    @property
    def db_dir(self) -> Path:
        return self.base_dir / "db"
    
    @property
    def artifacts_dir(self) -> Path:
        return self.base_dir / "artifacts"
    
    @property
    def reports_dir(self) -> Path:
        return self.base_dir / "reports"
    
    @property
    def models_dir(self) -> Path:
        return self.base_dir / "models"
    
    # External tools
    kape_path: Optional[Path] = None
    plaso_path: Optional[Path] = None
    
    # LLM settings
    llm_model: str = "llama3"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 500
    
    # Graph settings
    graph_max_nodes: int = 10000
    temporal_window_ms: float = 60000  # 1 minute
    anomaly_threshold: float = 0.5
    
    # BHSM settings
    bhsm_embed_dim: int = 32
    bhsm_max_traces: int = 1000
    bhsm_learning_rate: float = 0.015
    
    # RL settings
    rl_gamma: float = 0.99
    rl_epsilon: float = 0.1
    rl_learning_rate: float = 0.001
    
    def __post_init__(self):
        # Create directories
        for d in [self.db_dir, self.artifacts_dir, self.reports_dir, self.models_dir]:
            d.mkdir(parents=True, exist_ok=True)


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global config, creating if needed."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config):
    """Set global config."""
    global _config
    _config = config
