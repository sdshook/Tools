"""
LLM provider interface for FORAI.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
import sqlite3

from ..config import get_config


@dataclass
class LLMResponse:
    """Response from LLM with provenance."""
    text: str
    prompt_hash: str
    response_hash: str
    graph_state_hash: str
    model_name: str
    temperature: float
    timestamp: float


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 500, 
                temperature: float = 0.1) -> str:
        """Generate response from prompt."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is available."""
        pass
    
    @property
    @abstractmethod
    def model_name(self) -> str:
        """Get model name for provenance."""
        pass


class OllamaProvider(LLMProvider):
    """Ollama-based LLM provider."""
    
    def __init__(self, model: str = "llama3", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host
        self._available: Optional[bool] = None
    
    def generate(self, prompt: str, max_tokens: int = 500,
                temperature: float = 0.1) -> str:
        try:
            import requests
            
            response = requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens
                    },
                    "stream": False
                },
                timeout=120
            )
            
            if response.status_code == 200:
                return response.json().get("response", "")
            return f"Error: {response.status_code}"
            
        except Exception as e:
            return f"Error: {e}"
    
    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        
        try:
            import requests
            response = requests.get(f"{self.host}/api/tags", timeout=5)
            self._available = response.status_code == 200
        except:
            self._available = False
        
        return self._available
    
    @property
    def model_name(self) -> str:
        return f"ollama:{self.model}"


class LlamaCppProvider(LLMProvider):
    """llama-cpp-python based LLM provider."""
    
    def __init__(self, model_path: Path):
        self.model_path = model_path
        self._model = None
    
    def _load_model(self):
        if self._model is not None:
            return
        
        try:
            from llama_cpp import Llama
            self._model = Llama(
                model_path=str(self.model_path),
                n_ctx=2048,
                n_threads=4,
                verbose=False
            )
        except Exception as e:
            print(f"Failed to load model: {e}")
    
    def generate(self, prompt: str, max_tokens: int = 500,
                temperature: float = 0.1) -> str:
        self._load_model()
        
        if self._model is None:
            return "Model not available"
        
        try:
            response = self._model(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                stop=["Question:", "Evidence:", "\n\n"],
                echo=False
            )
            return response["choices"][0]["text"].strip()
        except Exception as e:
            return f"Error: {e}"
    
    def is_available(self) -> bool:
        return self.model_path.exists()
    
    @property
    def model_name(self) -> str:
        return f"llama-cpp:{self.model_path.name}"


class LLMLogger:
    """Logs LLM interactions for provenance."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        from ..db.schema import LLM_LOG_SCHEMA
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript(LLM_LOG_SCHEMA)
    
    def log(self, case_id: str, prompt: str, response: str,
            graph_state_hash: str, model_name: str, temperature: float) -> LLMResponse:
        """Log an LLM interaction."""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        response_hash = hashlib.sha256(response.encode()).hexdigest()[:16]
        timestamp = time.time()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO llm_log 
                (case_id, timestamp, prompt_hash, response_hash, graph_state_hash,
                 model_name, temperature, prompt_text, response_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id, timestamp, prompt_hash, response_hash, graph_state_hash,
                model_name, temperature, prompt, response
            ))
        
        return LLMResponse(
            text=response,
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            graph_state_hash=graph_state_hash,
            model_name=model_name,
            temperature=temperature,
            timestamp=timestamp
        )
    
    def get_log(self, case_id: str) -> list:
        """Get LLM interaction log for a case."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM llm_log WHERE case_id = ? ORDER BY timestamp
            """, (case_id,)).fetchall()
            return [dict(row) for row in rows]


def create_provider(config=None) -> Optional[LLMProvider]:
    """Create LLM provider based on configuration."""
    config = config or get_config()
    
    # Try Ollama first
    ollama = OllamaProvider(model=config.llm_model)
    if ollama.is_available():
        return ollama
    
    # Try llama-cpp
    model_path = config.models_dir / f"{config.llm_model}.gguf"
    if model_path.exists():
        return LlamaCppProvider(model_path)
    
    # Try finding any .gguf file
    gguf_files = list(config.models_dir.glob("*.gguf"))
    if gguf_files:
        return LlamaCppProvider(gguf_files[0])
    
    return None
