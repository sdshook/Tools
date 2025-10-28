"""
BHSM Lite - Lightweight components for FORAI
Essential semantic indexing and memory components without heavy ML dependencies.

This provides the core BHSM functionality needed for FORAI performance optimization:
- SimEmbedder: Fast deterministic semantic embeddings
- PSIIndex: Persistent semantic index for quick nearest-neighbor search
- BDHMemory: Reward-gated memory for learning useful evidence patterns

(c) 2025 - Shane D. Shook, All Rights Reserved
"""

import hashlib
import json
import time
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import numpy as np

# Configuration
EMBED_DIM = 32
DEFAULT_PSI_PATH = Path("psi_index.db")

def l2_norm(x: np.ndarray) -> np.ndarray:
    """L2 normalization with numerical stability."""
    norm = np.linalg.norm(x)
    return x / (norm + 1e-12)

@dataclass
class PSIDocument:
    """Document stored in PSI index"""
    doc_id: str
    text: str
    vector: np.ndarray
    tags: List[str]
    valence: float
    protected: bool
    timestamp: float

class SimEmbedder:
    """
    Fast deterministic semantic embedder using hash-based features.
    Provides consistent embeddings without requiring neural networks.
    """
    
    def __init__(self, dim: int = EMBED_DIM):
        self.dim = dim
        self._cache = {}
        
    def embed(self, text: str) -> np.ndarray:
        """Generate deterministic embedding for text"""
        if text in self._cache:
            return self._cache[text]
            
        # Normalize text
        text = text.lower().strip()
        if not text:
            return np.zeros(self.dim)
            
        # Generate multiple hash-based features
        features = np.zeros(self.dim)
        
        # Word-level features
        words = text.split()
        for i, word in enumerate(words[:self.dim//4]):
            hash_val = int(hashlib.md5(word.encode()).hexdigest()[:8], 16)
            features[i % self.dim] += (hash_val % 1000) / 1000.0
            
        # Character n-gram features
        for n in [2, 3, 4]:
            for i in range(len(text) - n + 1):
                ngram = text[i:i+n]
                hash_val = int(hashlib.md5(ngram.encode()).hexdigest()[:8], 16)
                features[(hash_val % (self.dim//4)) + (n-2)*(self.dim//4)] += 1.0
                
        # Length and structure features
        features[-4] = len(words) / 100.0  # Word count
        features[-3] = len(text) / 1000.0  # Character count
        features[-2] = text.count('.') / 10.0  # Sentence markers
        features[-1] = sum(1 for c in text if c.isupper()) / len(text) if text else 0  # Uppercase ratio
        
        # Normalize
        embedding = l2_norm(features)
        self._cache[text] = embedding
        return embedding
        
    def similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between vectors"""
        return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2) + 1e-12)

class PSIIndex:
    """
    Persistent Semantic Index for fast document retrieval.
    Stores documents with their embeddings for quick similarity search.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_PSI_PATH
        self.embedder = SimEmbedder()
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for PSI storage"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS psi_documents (
                    doc_id TEXT PRIMARY KEY,
                    text TEXT NOT NULL,
                    vector BLOB NOT NULL,
                    tags TEXT NOT NULL,
                    valence REAL NOT NULL,
                    protected INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON psi_documents(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_valence ON psi_documents(valence)")
            
    def add_doc(self, doc_id: str, text: str, vector: Optional[np.ndarray] = None, 
                tags: Optional[List[str]] = None, valence: float = 0.0, protected: bool = False):
        """Add document to PSI index"""
        if vector is None:
            vector = self.embedder.embed(text)
            
        tags = tags or []
        timestamp = time.time()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO psi_documents 
                (doc_id, text, vector, tags, valence, protected, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                doc_id, text, vector.tobytes(), 
                json.dumps(tags), valence, int(protected), timestamp
            ))
            
    def search(self, query_vector: np.ndarray, top_k: int = 5, 
               min_similarity: float = 0.1) -> List[Tuple[float, str, np.ndarray]]:
        """Search for similar documents"""
        results = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT doc_id, text, vector, valence FROM psi_documents")
            
            for row in cursor:
                doc_id, text, vector_bytes, valence = row
                doc_vector = np.frombuffer(vector_bytes, dtype=np.float64)
                
                similarity = self.embedder.similarity(query_vector, doc_vector)
                if similarity >= min_similarity:
                    results.append((similarity, doc_id, doc_vector))
                    
        # Sort by similarity and return top_k
        results.sort(key=lambda x: x[0], reverse=True)
        return results[:top_k]
        
    def get_doc(self, doc_id: str) -> Optional[PSIDocument]:
        """Retrieve document by ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT doc_id, text, vector, tags, valence, protected, timestamp
                FROM psi_documents WHERE doc_id = ?
            """, (doc_id,))
            
            row = cursor.fetchone()
            if row:
                doc_id, text, vector_bytes, tags_json, valence, protected, timestamp = row
                vector = np.frombuffer(vector_bytes, dtype=np.float64)
                tags = json.loads(tags_json)
                return PSIDocument(doc_id, text, vector, tags, valence, bool(protected), timestamp)
                
        return None
        
    def count(self) -> int:
        """Get total number of documents"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM psi_documents")
            return cursor.fetchone()[0]

class BDHMemory:
    """
    Bidirectional Hebbian Memory with reward gating.
    Learns which evidence patterns are consistently useful.
    """
    
    def __init__(self, store_type: str = "forai", db_path: Optional[Path] = None):
        self.store_type = store_type
        self.db_path = db_path or Path(f"bdh_{store_type}.db")
        self.embedder = SimEmbedder()
        self._init_database()
        
    def _init_database(self):
        """Initialize BDH memory database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bdh_traces (
                    trace_id TEXT PRIMARY KEY,
                    vector BLOB NOT NULL,
                    valence REAL NOT NULL,
                    reward_count INTEGER DEFAULT 0,
                    last_reward REAL DEFAULT 0,
                    consolidation_score REAL DEFAULT 0,
                    timestamp REAL NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_consolidation ON bdh_traces(consolidation_score)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_valence ON bdh_traces(valence)")
            
    def add_or_update(self, trace_id: str, vector: np.ndarray, valence: float = 0.0):
        """Add or update memory trace"""
        timestamp = time.time()
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if trace exists
            cursor = conn.execute("SELECT reward_count, consolidation_score FROM bdh_traces WHERE trace_id = ?", (trace_id,))
            existing = cursor.fetchone()
            
            if existing:
                reward_count, consolidation_score = existing
                # Update existing trace
                conn.execute("""
                    UPDATE bdh_traces 
                    SET vector = ?, valence = ?, timestamp = ?
                    WHERE trace_id = ?
                """, (vector.tobytes(), valence, timestamp, trace_id))
            else:
                # Insert new trace
                conn.execute("""
                    INSERT INTO bdh_traces 
                    (trace_id, vector, valence, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (trace_id, vector.tobytes(), valence, timestamp))
                
    def reward_gated_update(self, trace_id: str, state_vec: np.ndarray, reward: float):
        """Apply reward-gated learning to strengthen useful patterns"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT vector, valence, reward_count, consolidation_score 
                FROM bdh_traces WHERE trace_id = ?
            """, (trace_id,))
            
            row = cursor.fetchone()
            if row:
                vector_bytes, valence, reward_count, consolidation_score = row
                trace_vector = np.frombuffer(vector_bytes, dtype=np.float64)
                
                # Update consolidation score based on reward
                new_reward_count = reward_count + 1
                new_consolidation_score = consolidation_score + reward * 0.1
                new_valence = valence + reward * 0.05
                
                conn.execute("""
                    UPDATE bdh_traces 
                    SET reward_count = ?, consolidation_score = ?, valence = ?, last_reward = ?
                    WHERE trace_id = ?
                """, (new_reward_count, new_consolidation_score, new_valence, reward, trace_id))
                
    def get_top_traces(self, top_k: int = 10) -> List[Tuple[str, float, np.ndarray]]:
        """Get top consolidated traces"""
        results = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT trace_id, consolidation_score, vector 
                FROM bdh_traces 
                ORDER BY consolidation_score DESC 
                LIMIT ?
            """, (top_k,))
            
            for row in cursor:
                trace_id, score, vector_bytes = row
                vector = np.frombuffer(vector_bytes, dtype=np.float64)
                results.append((trace_id, score, vector))
                
        return results
        
    def consolidate_to_psi(self, psi_index: PSIIndex, threshold: float = 0.5):
        """Consolidate high-value traces to PSI index"""
        consolidated_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT trace_id, vector, consolidation_score, valence
                FROM bdh_traces 
                WHERE consolidation_score >= ?
            """, (threshold,))
            
            for row in cursor:
                trace_id, vector_bytes, score, valence = row
                vector = np.frombuffer(vector_bytes, dtype=np.float64)
                
                # Add to PSI with high valence
                psi_index.add_doc(
                    doc_id=f"bdh_{trace_id}",
                    text=f"Consolidated evidence pattern: {trace_id}",
                    vector=vector,
                    tags=["consolidated", "high_value"],
                    valence=valence,
                    protected=True
                )
                consolidated_count += 1
                
        return consolidated_count

# Global instances for FORAI integration
_global_embedder = None
_global_psi = None
_global_bdh = None

def get_global_components() -> Tuple[SimEmbedder, PSIIndex, BDHMemory]:
    """Get or create global BHSM components for FORAI"""
    global _global_embedder, _global_psi, _global_bdh
    
    if _global_embedder is None:
        _global_embedder = SimEmbedder()
        
    if _global_psi is None:
        _global_psi = PSIIndex(Path("forai_psi.db"))
        
    if _global_bdh is None:
        _global_bdh = BDHMemory("forai", Path("forai_bdh.db"))
        
    return _global_embedder, _global_psi, _global_bdh

# Compatibility aliases for FORAI
SimEmbedder = SimEmbedder
PSIIndex = PSIIndex  
BDHMemory = BDHMemory
psi = None  # Will be initialized when needed

def init_global_psi():
    """Initialize global PSI instance"""
    global psi
    if psi is None:
        _, psi, _ = get_global_components()
    return psi

if __name__ == "__main__":
    # Simple test
    print("Testing BHSM Lite components...")
    
    embedder = SimEmbedder()
    psi = PSIIndex(Path("test_psi.db"))
    bdh = BDHMemory("test")
    
    # Test embedding
    text1 = "USB device connected with serial number ABC123"
    text2 = "Registry key modified for malware persistence"
    text3 = "USB device ABC123 accessed sensitive files"
    
    vec1 = embedder.embed(text1)
    vec2 = embedder.embed(text2)
    vec3 = embedder.embed(text3)
    
    print(f"Embedding dimensions: {len(vec1)}")
    print(f"Similarity USB texts: {embedder.similarity(vec1, vec3):.3f}")
    print(f"Similarity USB vs Registry: {embedder.similarity(vec1, vec2):.3f}")
    
    # Test PSI
    psi.add_doc("doc1", text1, vec1, tags=["usb", "device"])
    psi.add_doc("doc2", text2, vec2, tags=["registry", "malware"])
    psi.add_doc("doc3", text3, vec3, tags=["usb", "access"])
    
    # Search
    query_vec = embedder.embed("USB device serial number")
    results = psi.search(query_vec, top_k=3)
    
    print(f"\nPSI Search Results for 'USB device serial number':")
    for similarity, doc_id, _ in results:
        print(f"  {doc_id}: {similarity:.3f}")
        
    # Test BDH
    bdh.add_or_update("trace1", vec1, valence=0.2)
    bdh.reward_gated_update("trace1", vec1, reward=1.0)
    
    top_traces = bdh.get_top_traces(5)
    print(f"\nTop BDH traces: {len(top_traces)}")
    
    print("BHSM Lite test completed successfully!")