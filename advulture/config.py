"""
ADVulture configuration — loaded from config.yaml or environment variables.
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import yaml


class LDAPConfig(BaseModel):
    server: str = "ldaps://dc01.corp.local"
    port: int = 636
    use_ssl: bool = True
    username: str = ""
    password: str = ""
    domain: str = ""
    base_dn: str = ""
    page_size: int = 1000


class LogConfig(BaseModel):
    # EVTX file paths (offline analysis)
    evtx_paths: List[Path] = Field(default_factory=list)
    # WinRM live collection
    winrm_hosts: List[str] = Field(default_factory=list)
    winrm_username: str = ""
    winrm_password: str = ""
    # SIEM API
    splunk_url: Optional[str] = None
    splunk_token: Optional[str] = None
    sentinel_workspace_id: Optional[str] = None
    # Collection windows (days)
    authn_window_days: int = 30
    authz_window_days: int = 90


class EntraConfig(BaseModel):
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    enabled: bool = False


class ADFSConfig(BaseModel):
    server_hosts: List[str] = Field(default_factory=list)
    enabled: bool = False


class MLConfig(BaseModel):
    model_path: Optional[Path] = None
    forest_path: Optional[Path] = None
    gnn_hidden_dim: int = 128
    gnn_num_layers: int = 3
    markov_iterations: int = 150
    markov_convergence: float = 1e-9


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ADVULTURE_", env_nested_delimiter="__")

    ldap: LDAPConfig = Field(default_factory=LDAPConfig)
    logs: LogConfig = Field(default_factory=LogConfig)
    entra: EntraConfig = Field(default_factory=EntraConfig)
    adfs: ADFSConfig = Field(default_factory=ADFSConfig)
    ml: MLConfig = Field(default_factory=MLConfig)

    db_path: Path = Path("advulture.duckdb")
    report_dir: Path = Path("reports")
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
