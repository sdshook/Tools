"""
Graph node types for forensic artifacts.
"""

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class NodeType(Enum):
    """Forensic graph node types."""
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    USER = "user"
    SERVICE = "service"


@dataclass
class Node:
    """Base graph node."""
    node_id: str
    node_type: NodeType
    timestamp: float
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    hash: str = ""
    
    def __post_init__(self):
        if not self.hash:
            content = f"{self.node_id}:{self.node_type.value}:{self.timestamp}:{json.dumps(self.properties, sort_keys=True)}"
            self.hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "type": self.node_type.value,
            "timestamp": self.timestamp,
            "properties": self.properties,
            "confidence": self.confidence,
            "hash": self.hash
        }


@dataclass
class ProcessNode(Node):
    """Process execution node."""
    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    user_sid: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.PROCESS
        self.properties.update({
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "command_line": self.command_line,
            "user_sid": self.user_sid
        })
        super().__post_init__()


@dataclass
class FileNode(Node):
    """File artifact node."""
    path: str = ""
    file_hash: str = ""
    size: int = 0
    created: float = 0
    modified: float = 0
    accessed: float = 0
    
    def __post_init__(self):
        self.node_type = NodeType.FILE
        self.properties.update({
            "path": self.path,
            "file_hash": self.file_hash,
            "size": self.size,
            "created": self.created,
            "modified": self.modified,
            "accessed": self.accessed
        })
        super().__post_init__()


@dataclass
class NetworkNode(Node):
    """Network connection node."""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    protocol: str = "TCP"
    
    def __post_init__(self):
        self.node_type = NodeType.NETWORK
        self.properties.update({
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol
        })
        super().__post_init__()


@dataclass
class RegistryNode(Node):
    """Registry modification node."""
    key_path: str = ""
    value_name: str = ""
    value_data: str = ""
    value_type: str = ""
    operation: str = ""  # create, modify, delete
    
    def __post_init__(self):
        self.node_type = NodeType.REGISTRY
        self.properties.update({
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value_data": self.value_data,
            "value_type": self.value_type,
            "operation": self.operation
        })
        super().__post_init__()


@dataclass
class UserNode(Node):
    """User account node."""
    username: str = ""
    sid: str = ""
    domain: str = ""
    is_admin: bool = False
    logon_count: int = 0
    last_logon: float = 0
    
    def __post_init__(self):
        self.node_type = NodeType.USER
        self.properties.update({
            "username": self.username,
            "sid": self.sid,
            "domain": self.domain,
            "is_admin": self.is_admin,
            "logon_count": self.logon_count,
            "last_logon": self.last_logon
        })
        super().__post_init__()


@dataclass
class ServiceNode(Node):
    """Windows service node."""
    service_name: str = ""
    display_name: str = ""
    binary_path: str = ""
    start_type: str = ""
    account: str = ""
    state: str = ""
    
    def __post_init__(self):
        self.node_type = NodeType.SERVICE
        self.properties.update({
            "service_name": self.service_name,
            "display_name": self.display_name,
            "binary_path": self.binary_path,
            "start_type": self.start_type,
            "account": self.account,
            "state": self.state
        })
        super().__post_init__()
