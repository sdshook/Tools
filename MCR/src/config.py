"""
config.py
MCR Configuration Management

All configurable values are centralized here. For production deployments,
these can be overridden via environment variables.
"""

import os


class MCRConfig:
    """
    MCR configuration with environment variable overrides.
    
    Environment Variables:
        MCR_NATS_URL: NATS server URL (default: nats://localhost:4222)
        MCR_TENANT: Tenant identifier for multi-tenant deployments (default: default)
        MCR_DOMAIN: Domain classification for subject hierarchy (default: workflows)
        MCR_STREAM_NAME: JetStream stream name (default: MCR_CONTEXT)
        MCR_RELEVANCE_RATIO: Context reconstruction relevance ratio (default: 0.35)
        MCR_MAX_STREAM_AGE: Maximum event retention in seconds (default: 86400)
        MCR_MAX_STREAM_MSGS: Maximum messages per stream (default: 500000)
        MCR_MAX_STREAM_BYTES: Maximum stream size in bytes (default: 536870912)
        ANTHROPIC_API_KEY: Anthropic API key for live model calls
    """
    
    # NATS/JetStream Configuration
    NATS_URL = os.getenv("MCR_NATS_URL", "nats://localhost:4222")
    
    # Multi-tenant Configuration
    TENANT = os.getenv("MCR_TENANT", "default")
    DOMAIN = os.getenv("MCR_DOMAIN", "workflows")
    
    # Stream Configuration
    STREAM_NAME = os.getenv("MCR_STREAM_NAME", "MCR_CONTEXT")
    MAX_STREAM_AGE = int(os.getenv("MCR_MAX_STREAM_AGE", "86400"))  # 24 hours
    MAX_STREAM_MSGS = int(os.getenv("MCR_MAX_STREAM_MSGS", "500000"))
    MAX_STREAM_BYTES = int(os.getenv("MCR_MAX_STREAM_BYTES", str(512 * 1024 * 1024)))
    
    # Reconstruction Configuration
    RELEVANCE_RATIO = float(os.getenv("MCR_RELEVANCE_RATIO", "0.35"))
    
    # Model Provider Configuration
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    
    @classmethod
    def stream_subject(cls) -> str:
        """Returns the wildcard subject pattern for the MCR stream."""
        return f"{cls.TENANT}.{cls.DOMAIN}.>"
    
    @classmethod
    def workflow_subject(cls, workflow_type: str, correlation_id: str, event_type: str) -> str:
        """
        Constructs a fully qualified subject for an event.
        
        Subject hierarchy: {tenant}.{domain}.{workflow_type}.{correlation_id}.{event_type}
        
        This structure enables:
        - Tenant isolation at level 1
        - Domain-based stream partitioning at level 2
        - Workflow-type filtering at level 3
        - Correlation-based consumer filtering at level 4
        - Event-type selection at level 5
        """
        return f"{cls.TENANT}.{cls.DOMAIN}.{workflow_type}.{correlation_id}.{event_type}"
    
    @classmethod
    def validate(cls) -> list[str]:
        """
        Validates configuration and returns list of warnings/errors.
        Returns empty list if configuration is valid.
        """
        issues = []
        
        if cls.RELEVANCE_RATIO <= 0 or cls.RELEVANCE_RATIO > 1:
            issues.append(f"MCR_RELEVANCE_RATIO must be between 0 and 1, got {cls.RELEVANCE_RATIO}")
        
        if cls.MAX_STREAM_AGE < 3600:
            issues.append(f"MCR_MAX_STREAM_AGE less than 1 hour may cause premature event expiration")
        
        if not cls.ANTHROPIC_API_KEY:
            issues.append("ANTHROPIC_API_KEY not set; live model calls will fail")
        
        return issues
    
    @classmethod
    def print_config(cls):
        """Prints current configuration (masking sensitive values)."""
        print("MCR Configuration:")
        print(f"  NATS_URL:          {cls.NATS_URL}")
        print(f"  TENANT:            {cls.TENANT}")
        print(f"  DOMAIN:            {cls.DOMAIN}")
        print(f"  STREAM_NAME:       {cls.STREAM_NAME}")
        print(f"  STREAM_SUBJECT:    {cls.stream_subject()}")
        print(f"  MAX_STREAM_AGE:    {cls.MAX_STREAM_AGE}s")
        print(f"  MAX_STREAM_MSGS:   {cls.MAX_STREAM_MSGS:,}")
        print(f"  MAX_STREAM_BYTES:  {cls.MAX_STREAM_BYTES:,}")
        print(f"  RELEVANCE_RATIO:   {cls.RELEVANCE_RATIO}")
        print(f"  ANTHROPIC_API_KEY: {'[SET]' if cls.ANTHROPIC_API_KEY else '[NOT SET]'}")


# Model Provider Pool (extend for additional providers)
PROVIDER_POOL = [
    {
        "name": "claude-3-haiku",
        "api_model": "claude-3-haiku-20240307",
        "capability": "basic",
        "latency_p50_ms": 150,
        "cost_per_mtok_input": 0.25,
        "cost_per_mtok_output": 1.25,
        "data_classes": ["internal", "confidential"],
    },
    {
        "name": "claude-sonnet-4",
        "api_model": "claude-sonnet-4-20250514",
        "capability": "reasoning",
        "latency_p50_ms": 380,
        "cost_per_mtok_input": 3.00,
        "cost_per_mtok_output": 15.00,
        "data_classes": ["internal", "confidential"],
    },
    {
        "name": "claude-opus-4",
        "api_model": "claude-sonnet-4-20250514",  # Fallback to Sonnet
        "capability": "advanced",
        "latency_p50_ms": 750,
        "cost_per_mtok_input": 15.00,
        "cost_per_mtok_output": 75.00,
        "data_classes": ["internal", "confidential"],
    },
]

CAPABILITY_RANK = {"basic": 0, "reasoning": 1, "advanced": 2}
