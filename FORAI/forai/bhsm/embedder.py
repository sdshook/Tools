"""
Feature embedding for BHSM.
"""

import re
import math
import numpy as np
from typing import Dict, Any, List

from ..config import get_config


class ForensicEmbedder:
    """
    Embeds forensic evidence into 32-dimensional vectors.
    
    Dimensions:
    [0-7]:   Text features (length, entropy, special chars)
    [8-15]:  Forensic indicators (suspicious patterns)
    [16-23]: Temporal features (time-based anomalies)
    [24-31]: Activity features (network, file, process)
    """
    
    def __init__(self, dim: int = None):
        config = get_config()
        self.dim = dim or config.bhsm_embed_dim
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r"powershell.*-enc",
            r"cmd.*/c",
            r"mimikatz",
            r"psexec",
            r"netcat|nc\.exe",
            r"whoami|systeminfo",
            r"reg\s+add|reg\s+delete",
            r"schtasks|at\s+\d",
        ]
        
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns]
    
    def embed(self, text: str, metadata: Dict[str, Any] = None) -> np.ndarray:
        """
        Embed text and metadata into a feature vector.
        
        Args:
            text: Evidence text/summary
            metadata: Additional evidence metadata
            
        Returns:
            32-dimensional normalized vector
        """
        vec = np.zeros(self.dim, dtype=np.float32)
        metadata = metadata or {}
        
        # Text features [0-7]
        vec[0] = min(len(text) / 500, 1.0)  # Length normalized
        vec[1] = self._entropy(text) / 4.0  # Entropy normalized
        vec[2] = sum(1 for c in text if not c.isalnum()) / max(len(text), 1)  # Special char ratio
        vec[3] = text.lower().count("\\") / max(len(text), 1) * 10  # Path depth indicator
        vec[4] = len(text.split()) / 100  # Word count
        vec[5] = sum(1 for c in text if c.isupper()) / max(len(text), 1)  # Uppercase ratio
        vec[6] = len(re.findall(r'\d+', text)) / 20  # Number count
        vec[7] = 1.0 if re.search(r'[a-f0-9]{32,}', text.lower()) else 0.0  # Hash present
        
        # Forensic indicators [8-15]
        text_lower = text.lower()
        for i, pattern in enumerate(self.compiled_patterns[:8]):
            vec[8 + i] = 1.0 if pattern.search(text_lower) else 0.0
        
        # Temporal features [16-23]
        timestamp = metadata.get("timestamp", 0)
        if timestamp:
            from datetime import datetime
            try:
                dt = datetime.fromtimestamp(timestamp)
                vec[16] = dt.hour / 24  # Hour of day
                vec[17] = dt.weekday() / 7  # Day of week
                vec[18] = 1.0 if dt.hour < 6 or dt.hour > 22 else 0.0  # Off-hours
                vec[19] = 1.0 if dt.weekday() >= 5 else 0.0  # Weekend
            except:
                pass
        
        # Activity features [24-31]
        artifact_type = metadata.get("artifact_type", "").lower()
        vec[24] = 1.0 if "network" in artifact_type or "dns" in artifact_type else 0.0
        vec[25] = 1.0 if "file" in artifact_type or "mft" in artifact_type else 0.0
        vec[26] = 1.0 if "process" in artifact_type or "prefetch" in artifact_type else 0.0
        vec[27] = 1.0 if "registry" in artifact_type else 0.0
        vec[28] = 1.0 if "user" in artifact_type or "logon" in artifact_type else 0.0
        vec[29] = metadata.get("confidence", 1.0)
        vec[30] = metadata.get("anomaly_score", 0.0)
        vec[31] = self._suspicion_score(text_lower)
        
        # Normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-12:
            vec = vec / norm
        
        return vec
    
    def _entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _suspicion_score(self, text: str) -> float:
        """Calculate overall suspicion score from patterns."""
        matches = sum(1 for p in self.compiled_patterns if p.search(text))
        return min(matches / len(self.compiled_patterns), 1.0)
    
    def embed_batch(self, items: List[Dict[str, Any]]) -> np.ndarray:
        """Embed multiple items."""
        vectors = []
        for item in items:
            text = item.get("text", item.get("summary", ""))
            vec = self.embed(text, item)
            vectors.append(vec)
        return np.array(vectors)
