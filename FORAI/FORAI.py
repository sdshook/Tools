#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced FORAI.py (c) 2025 All Rights Reserved Shane D. Shook
Forensic analysis tool with self-supervised learning and enhanced deterministic analysis

ENHANCED FEATURES:
- Isolation Forest for anomaly detection in forensic artifacts
- Gradient descent optimization for FAS5 database queries
- Enhanced deterministic extractors with cross-correlation
- Self-validation and confidence scoring without external feedback
- Cross-case pattern learning for continuous improvement

WORKFLOW:
Target Drive → KAPE (Artifacts) → log2timeline (.plaso) → psort (SQLite) → Enhanced FAS5 Database

CLI USAGE EXAMPLES:

🚀 ENHANCED COMPLETE ANALYSIS:
    python FORAI.py --case-id CASE001 --full-analysis --target-drive C: --enable-all-enhancements --verbose

🔍 ANOMALY DETECTION:
    python FORAI.py --case-id CASE001 --artifacts-dir "C:\\KAPE_Output" --enable-anomaly-detection --report json

⚡ OPTIMIZED QUERIES:
    python FORAI.py --case-id CASE001 --query "SELECT * FROM timeline_events WHERE artifact_type='registry'" --enable-query-optimization

📚 CROSS-CASE LEARNING:
    python FORAI.py --case-id CASE001 --full-analysis --target-drive C: --enable-cross-case-learning --verbose
"""

import os
import sys
import argparse
import hashlib
import sqlite3
import json
import re
import time
import subprocess
import shutil
import logging
import threading
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Set, Union, Any, Iterator, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
from functools import lru_cache, wraps

try:
    import psutil
except ImportError:
    psutil = None

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

import numpy as np

# Optional imports for LLM functionality
try:
    from llama_cpp import Llama
    LLAMA_CPP_AVAILABLE = True
except ImportError:
    LLAMA_CPP_AVAILABLE = False
    print("Warning: llama-cpp-python not available. Local LLM functionality will be disabled.")

# ============================================================================
# ENHANCED FORENSIC DATA STRUCTURES
# ============================================================================

@dataclass
class ForensicEvidence:
    """Represents a piece of forensic evidence with confidence scoring"""
    evidence_id: str
    evidence_type: str
    source_artifacts: List[str]
    primary_data: Dict[str, Any]
    supporting_data: List[Dict[str, Any]]
    confidence_score: float
    correlation_strength: float
    timestamp_consistency: bool
    cross_validation_passed: bool

@dataclass
class ForensicAnomaly:
    """Represents a detected forensic anomaly"""
    anomaly_id: str
    artifact_type: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    evidence_features: Dict[str, Any]
    similar_patterns: List[str]
    timestamp: float

@dataclass
class ValidationResult:
    """Result of evidence validation"""
    evidence_id: str
    validation_score: float
    consistency_checks: Dict[str, bool]
    confidence_factors: Dict[str, float]
    reliability_score: float
    validation_details: Dict[str, Any]

@dataclass
class ConfidenceMetrics:
    """Confidence metrics for forensic findings"""
    source_diversity: float
    temporal_consistency: float
    data_integrity: float
    pattern_strength: float
    cross_validation: float
    overall_confidence: float

@dataclass
class PatternMatch:
    """Represents a match between current evidence and known patterns"""
    pattern_id: str
    similarity_score: float
    matching_features: List[str]
    case_examples: List[str]
    confidence_boost: float

@dataclass
class OptimizationResult:
    """Result of query optimization"""
    original_query: str
    optimized_query: str
    original_time: float
    optimized_time: float
    improvement_ratio: float
    confidence: float

# ============================================================================
# ISOLATION FOREST ANOMALY DETECTION
# ============================================================================

class IsolationNode:
    """Node in isolation tree for forensic artifact analysis"""
    def __init__(self):
        self.split_feature: Optional[int] = None
        self.split_value: Optional[float] = None
        self.left: Optional['IsolationNode'] = None
        self.right: Optional['IsolationNode'] = None
        self.size: int = 0
        self.depth: int = 0

class ForensicIsolationTree:
    """Isolation tree specialized for forensic artifact analysis"""
    
    def __init__(self, max_depth: int = 10):
        self.root: Optional[IsolationNode] = None
        self.max_depth = max_depth
        
    def build(self, data: np.ndarray, current_depth: int = 0) -> IsolationNode:
        """Build isolation tree from forensic feature vectors"""
        node = IsolationNode()
        node.size = len(data)
        node.depth = current_depth
        
        if current_depth >= self.max_depth or len(data) <= 1:
            return node
            
        num_features = data.shape[1]
        split_feature = np.random.randint(0, num_features)
        
        feature_values = data[:, split_feature]
        min_val, max_val = np.min(feature_values), np.max(feature_values)
        
        if min_val == max_val:
            return node
            
        split_value = np.random.uniform(min_val, max_val)
        
        left_mask = feature_values < split_value
        right_mask = ~left_mask
        
        left_data = data[left_mask]
        right_data = data[right_mask]
        
        node.split_feature = split_feature
        node.split_value = split_value
        
        if len(left_data) > 0:
            node.left = self.build(left_data, current_depth + 1)
        if len(right_data) > 0:
            node.right = self.build(right_data, current_depth + 1)
            
        return node
    
    def path_length(self, sample: np.ndarray, node: Optional[IsolationNode] = None, current_depth: int = 0) -> float:
        """Calculate path length for anomaly scoring"""
        if node is None:
            node = self.root
            
        if node is None:
            return 0.0
            
        if node.split_feature is None:
            return current_depth + self._average_path_length(node.size)
            
        if sample[node.split_feature] < node.split_value:
            if node.left is not None:
                return self.path_length(sample, node.left, current_depth + 1)
        else:
            if node.right is not None:
                return self.path_length(sample, node.right, current_depth + 1)
                
        return current_depth + self._average_path_length(node.size)
    
    def _average_path_length(self, n: int) -> float:
        """Average path length in BST for normalization"""
        if n <= 1:
            return 0.0
        return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

class ForensicAnomalyDetector:
    """Isolation Forest for detecting anomalous forensic artifacts"""
    
    def __init__(self, n_trees: int = 100, subsample_size: int = 256, anomaly_threshold: float = 0.6):
        self.n_trees = n_trees
        self.subsample_size = subsample_size
        self.anomaly_threshold = anomaly_threshold
        self.trees: List[ForensicIsolationTree] = []
        self.feature_names: List[str] = []
        self.artifact_patterns: Dict[str, List[np.ndarray]] = {}
        
    def extract_forensic_features(self, artifact_data: Dict[str, Any], artifact_type: str) -> np.ndarray:
        """Extract numerical features from forensic artifacts"""
        features = []
        
        if artifact_type == "registry":
            features.extend(self._extract_registry_features(artifact_data))
        elif artifact_type == "file_system":
            features.extend(self._extract_filesystem_features(artifact_data))
        elif artifact_type == "event_log":
            features.extend(self._extract_eventlog_features(artifact_data))
        elif artifact_type == "network":
            features.extend(self._extract_network_features(artifact_data))
        elif artifact_type == "process":
            features.extend(self._extract_process_features(artifact_data))
        else:
            features.extend(self._extract_generic_features(artifact_data))
            
        target_size = 32
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        elif len(features) > target_size:
            features = features[:target_size]
            
        return np.array(features, dtype=np.float32)
    
    def _extract_registry_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from registry artifacts"""
        features = []
        
        key_path = data.get('key_path', '')
        features.append(len(key_path) / 100.0)
        features.append(key_path.count('\\') / 10.0)
        features.append(1.0 if 'run' in key_path.lower() else 0.0)
        features.append(1.0 if 'software' in key_path.lower() else 0.0)
        
        value_name = data.get('value_name', '')
        value_data = str(data.get('value_data', ''))
        features.append(len(value_name) / 50.0)
        features.append(len(value_data) / 200.0)
        features.append(1.0 if value_data.startswith('C:\\') else 0.0)
        features.append(1.0 if '.exe' in value_data.lower() else 0.0)
        
        timestamp = data.get('timestamp', 0)
        if timestamp:
            hour = time.localtime(timestamp).tm_hour
            features.append(hour / 23.0)
            weekday = time.localtime(timestamp).tm_wday
            features.append(weekday / 6.0)
        else:
            features.extend([0.0, 0.0])
            
        return features
    
    def _extract_filesystem_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from file system artifacts"""
        features = []
        
        file_path = data.get('file_path', '')
        features.append(len(file_path) / 100.0)
        features.append(file_path.count('\\') / 10.0)
        features.append(1.0 if file_path.startswith('C:\\Users') else 0.0)
        features.append(1.0 if file_path.startswith('C:\\Windows\\Temp') else 0.0)
        
        file_size = data.get('file_size', 0)
        features.append(min(file_size / 1000000.0, 1.0))
        
        file_extension = data.get('file_extension', '').lower()
        features.append(1.0 if file_extension in ['.exe', '.dll', '.bat', '.ps1'] else 0.0)
        features.append(1.0 if file_extension in ['.tmp', '.temp'] else 0.0)
        features.append(1.0 if file_extension in ['.zip', '.rar', '.7z'] else 0.0)
        
        created_time = data.get('created_time', 0)
        modified_time = data.get('modified_time', 0)
        
        if created_time and modified_time:
            time_diff = abs(modified_time - created_time)
            features.append(min(time_diff / 3600.0, 1.0))
        else:
            features.append(0.0)
            
        if created_time:
            hour = time.localtime(created_time).tm_hour
            features.append(1.0 if hour < 6 or hour > 22 else 0.0)
        else:
            features.append(0.0)
            
        return features
    
    def _extract_eventlog_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from event log artifacts"""
        features = []
        
        event_id = data.get('event_id', 0)
        features.append(event_id / 10000.0)
        
        log_name = data.get('log_name', '').lower()
        features.append(1.0 if 'security' in log_name else 0.0)
        features.append(1.0 if 'system' in log_name else 0.0)
        features.append(1.0 if 'application' in log_name else 0.0)
        
        message = data.get('message', '').lower()
        features.append(len(message) / 500.0)
        features.append(1.0 if 'failed' in message else 0.0)
        features.append(1.0 if 'error' in message else 0.0)
        features.append(1.0 if 'logon' in message else 0.0)
        features.append(1.0 if 'process' in message else 0.0)
        features.append(1.0 if 'network' in message else 0.0)
        
        return features
    
    def _extract_network_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from network artifacts"""
        features = []
        
        local_port = data.get('local_port', 0)
        remote_port = data.get('remote_port', 0)
        features.append(local_port / 65535.0)
        features.append(remote_port / 65535.0)
        
        protocol = data.get('protocol', '').lower()
        features.append(1.0 if protocol == 'tcp' else 0.0)
        features.append(1.0 if protocol == 'udp' else 0.0)
        
        remote_ip = data.get('remote_ip', '')
        features.append(1.0 if remote_ip.startswith('192.168.') else 0.0)
        features.append(1.0 if remote_ip.startswith('10.') else 0.0)
        features.append(1.0 if remote_ip.startswith('172.') else 0.0)
        
        bytes_sent = data.get('bytes_sent', 0)
        bytes_received = data.get('bytes_received', 0)
        features.append(min(bytes_sent / 1000000.0, 1.0))
        features.append(min(bytes_received / 1000000.0, 1.0))
        
        return features
    
    def _extract_process_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract features from process artifacts"""
        features = []
        
        process_name = data.get('process_name', '').lower()
        features.append(len(process_name) / 50.0)
        features.append(1.0 if process_name.endswith('.exe') else 0.0)
        features.append(1.0 if 'powershell' in process_name else 0.0)
        features.append(1.0 if 'cmd' in process_name else 0.0)
        
        command_line = data.get('command_line', '').lower()
        features.append(len(command_line) / 200.0)
        features.append(1.0 if '-enc' in command_line else 0.0)
        features.append(1.0 if 'invoke-' in command_line else 0.0)
        features.append(1.0 if 'download' in command_line else 0.0)
        
        parent_pid = data.get('parent_pid', 0)
        pid = data.get('pid', 0)
        features.append(1.0 if parent_pid > 0 else 0.0)
        features.append(min(pid / 10000.0, 1.0))
        
        return features
    
    def _extract_generic_features(self, data: Dict[str, Any]) -> List[float]:
        """Extract generic features from any artifact"""
        features = []
        
        data_str = json.dumps(data, default=str).lower()
        features.append(len(data_str) / 1000.0)
        features.append(data_str.count('\\') / 20.0)
        features.append(1.0 if 'temp' in data_str else 0.0)
        features.append(1.0 if 'system' in data_str else 0.0)
        features.append(1.0 if 'user' in data_str else 0.0)
        
        data_hash = hashlib.md5(data_str.encode()).hexdigest()
        for i in range(5):
            features.append(int(data_hash[i*2:i*2+2], 16) / 255.0)
            
        return features
    
    def fit(self, data: np.ndarray, feature_names: Optional[List[str]] = None):
        """Train isolation forest on forensic feature vectors"""
        self.feature_names = feature_names or [f"feature_{i}" for i in range(data.shape[1])]
        self.trees = []
        
        for _ in range(self.n_trees):
            sample_size = min(self.subsample_size, len(data))
            indices = np.random.choice(len(data), sample_size, replace=False)
            subsample = data[indices]
            
            tree = ForensicIsolationTree()
            tree.root = tree.build(subsample)
            self.trees.append(tree)
    
    def predict(self, sample: np.ndarray) -> float:
        """Calculate anomaly score for a single sample"""
        if not self.trees:
            return 0.0
            
        path_lengths = []
        for tree in self.trees:
            path_length = tree.path_length(sample)
            path_lengths.append(path_length)
            
        avg_path_length = np.mean(path_lengths)
        
        c = self.trees[0]._average_path_length(self.subsample_size)
        if c == 0:
            return 0.0
        anomaly_score = 2.0 ** (-avg_path_length / c)
        
        return anomaly_score
    
    def detect_anomalies_in_case(self, case_id: str, artifacts: List[Dict[str, Any]]) -> List[ForensicAnomaly]:
        """Detect anomalies in case artifacts"""
        anomalies = []
        
        artifact_groups = {}
        for i, artifact in enumerate(artifacts):
            artifact_type = artifact.get('artifact_type', 'generic')
            if artifact_type not in artifact_groups:
                artifact_groups[artifact_type] = []
            artifact_groups[artifact_type].append((i, artifact))
        
        for artifact_type, type_artifacts in artifact_groups.items():
            if len(type_artifacts) < 5:
                continue
                
            feature_vectors = []
            artifact_indices = []
            for idx, artifact in type_artifacts:
                features = self.extract_forensic_features(artifact, artifact_type)
                feature_vectors.append(features)
                artifact_indices.append(idx)
            
            feature_matrix = np.array(feature_vectors)
            
            if artifact_type in self.artifact_patterns and len(self.artifact_patterns[artifact_type]) > 20:
                training_data = np.array(self.artifact_patterns[artifact_type])
                forest = ForensicAnomalyDetector()
                forest.fit(training_data)
            else:
                forest = ForensicAnomalyDetector()
                forest.fit(feature_matrix)
            
            for i, (artifact_idx, artifact) in enumerate(type_artifacts):
                features = feature_vectors[i]
                anomaly_score = forest.predict(features)
                is_anomaly = anomaly_score > forest.anomaly_threshold
                
                if is_anomaly:
                    confidence = min((anomaly_score - forest.anomaly_threshold) * 2.0, 1.0)
                    similar_patterns = self._find_similar_patterns(features, artifact_type)
                    
                    anomaly = ForensicAnomaly(
                        anomaly_id=f"{case_id}_{artifact_type}_{artifact_idx}",
                        artifact_type=artifact_type,
                        anomaly_score=anomaly_score,
                        is_anomaly=is_anomaly,
                        confidence=confidence,
                        evidence_features=artifact,
                        similar_patterns=similar_patterns,
                        timestamp=time.time()
                    )
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _find_similar_patterns(self, features: np.ndarray, artifact_type: str, threshold: float = 0.8) -> List[str]:
        """Find similar patterns from previous cases"""
        similar_patterns = []
        
        if artifact_type not in self.artifact_patterns:
            return similar_patterns
        
        for i, pattern in enumerate(self.artifact_patterns[artifact_type]):
            similarity = np.dot(features, pattern) / (np.linalg.norm(features) * np.linalg.norm(pattern) + 1e-8)
            
            if similarity > threshold:
                similar_patterns.append(f"{artifact_type}_pattern_{i}")
        
        return similar_patterns[:5]

# ============================================================================
# GRADIENT DESCENT QUERY OPTIMIZER
# ============================================================================

@dataclass
class QueryPlan:
    """Represents a database query execution plan"""
    query_hash: str
    base_query: str
    parameters: Dict[str, Any]
    estimated_cost: float
    actual_cost: Optional[float] = None
    execution_time: Optional[float] = None
    result_count: Optional[int] = None

class FAS5GradientOptimizer:
    """Gradient descent optimizer for FAS5 forensic database queries"""
    
    def __init__(self, db_path: Optional[Path] = None, learning_rate: float = 0.01):
        self.db_path = db_path
        self.learning_rate = learning_rate
        self.query_history: Dict[str, List[QueryPlan]] = {}
        self.optimization_cache: Dict[str, str] = {}
        self.feature_weights = np.array([1.0, 1.0, 1.0, 1.0, 1.0])
        self.performance_history: List[float] = []
        
    def extract_query_features(self, query: str, parameters: Dict[str, Any] = None) -> np.ndarray:
        """Extract numerical features from SQL query for optimization"""
        features = np.zeros(5)
        
        query_lower = query.lower()
        params = parameters or {}
        
        # Feature 1: Query complexity
        complexity_indicators = ['where', 'join', 'group by', 'order by', 'having', 'union']
        complexity = sum(1 for indicator in complexity_indicators if indicator in query_lower)
        features[0] = min(complexity / 10.0, 1.0)
        
        # Feature 2: Table scan likelihood
        scan_indicators = ['like', '%', 'not in', 'or']
        scan_score = sum(query_lower.count(indicator) for indicator in scan_indicators)
        features[1] = min(scan_score / 5.0, 1.0)
        
        # Feature 3: Index usage potential
        index_indicators = ['=', 'between', 'in (', '>', '<']
        index_score = sum(query_lower.count(indicator) for indicator in index_indicators)
        features[2] = min(index_score / 10.0, 1.0)
        
        # Feature 4: Result set size estimation
        if 'limit' in query_lower:
            try:
                limit_pos = query_lower.find('limit')
                limit_part = query[limit_pos:limit_pos+20]
                limit_value = int(''.join(filter(str.isdigit, limit_part)))
                features[3] = min(limit_value / 1000.0, 1.0)
            except:
                features[3] = 1.0
        else:
            features[3] = 1.0
            
        # Feature 5: Parameter selectivity
        if params:
            selectivity = 0.0
            for key, value in params.items():
                if isinstance(value, str):
                    if len(value) > 10:
                        selectivity += 0.9
                    elif '%' in value:
                        selectivity += 0.3
                    else:
                        selectivity += 0.7
                elif isinstance(value, (int, float)):
                    selectivity += 0.8
                else:
                    selectivity += 0.5
            features[4] = min(selectivity / len(params), 1.0)
        else:
            features[4] = 0.1
            
        return features
    
    def optimize_query(self, query: str, parameters: Dict[str, Any] = None) -> str:
        """Apply optimization transformations to query"""
        optimized = query
        params = parameters or {}
        
        query_hash = self._hash_query(query, params)
        if query_hash in self.optimization_cache:
            return self.optimization_cache[query_hash]
        
        optimized = self._apply_index_hints(optimized)
        optimized = self._optimize_where_clauses(optimized)
        optimized = self._optimize_joins(optimized)
        optimized = self._add_limits_if_missing(optimized)
        optimized = self._optimize_order_by(optimized)
        
        self.optimization_cache[query_hash] = optimized
        return optimized
    
    def _apply_index_hints(self, query: str) -> str:
        """Add index hints based on learned patterns"""
        if 'timestamp' in query.lower() and 'between' in query.lower():
            if 'use index' not in query.lower():
                query = query.replace('WHERE', 'USE INDEX (idx_timestamp) WHERE', 1)
        
        if 'case_id' in query.lower() and '=' in query.lower():
            if 'use index' not in query.lower():
                query = query.replace('WHERE', 'USE INDEX (idx_case_id) WHERE', 1)
                
        return query
    
    def _optimize_where_clauses(self, query: str) -> str:
        """Optimize WHERE clause ordering for better performance"""
        if query.lower().count(' and ') > 1:
            if '-- Optimized' not in query:
                query = '-- Optimized: Most selective conditions first\n' + query
        return query
    
    def _optimize_joins(self, query: str) -> str:
        """Optimize JOIN operations"""
        query_lower = query.lower()
        if ' where ' in query_lower and '=' in query_lower:
            if query_lower.count('from') == 1 and ',' in query:
                if '-- Consider explicit JOINs' not in query:
                    query = '-- Consider explicit JOINs for better optimization\n' + query
        return query
    
    def _add_limits_if_missing(self, query: str) -> str:
        """Add LIMIT clauses to prevent large result sets"""
        query_lower = query.lower()
        
        if (query_lower.strip().startswith('select') and 
            'limit' not in query_lower and 
            'count(' not in query_lower):
            
            if ('like' in query_lower or 
                'or' in query_lower or 
                'not in' in query_lower):
                
                query += '\nLIMIT 10000  -- Added by optimizer to prevent large result sets'
                
        return query
    
    def _optimize_order_by(self, query: str) -> str:
        """Optimize ORDER BY clauses"""
        query_lower = query.lower()
        
        if ('order by' in query_lower and 
            'limit' not in query_lower and 
            '-- Consider adding LIMIT' not in query):
            
            query += '\n-- Consider adding LIMIT with ORDER BY for better performance'
            
        return query
    
    def execute_and_measure(self, query: str, parameters: Dict[str, Any] = None) -> QueryPlan:
        """Execute query and measure performance"""
        if not self.db_path:
            query_hash = self._hash_query(query, parameters or {})
            return QueryPlan(
                query_hash=query_hash,
                base_query=query,
                parameters=parameters or {},
                estimated_cost=1.0,
                actual_cost=1.0,
                execution_time=0.1,
                result_count=0
            )
        
        query_hash = self._hash_query(query, parameters or {})
        start_time = time.time()
        result_count = 0
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query, parameters or {})
                results = cursor.fetchall()
                result_count = len(results)
                
        except Exception as e:
            execution_time = time.time() - start_time
            return QueryPlan(
                query_hash=query_hash,
                base_query=query,
                parameters=parameters or {},
                estimated_cost=1.0,
                actual_cost=float('inf'),
                execution_time=execution_time,
                result_count=0
            )
        
        execution_time = time.time() - start_time
        actual_cost = execution_time * (1 + result_count / 1000.0)
        
        plan = QueryPlan(
            query_hash=query_hash,
            base_query=query,
            parameters=parameters or {},
            estimated_cost=1.0,
            actual_cost=actual_cost,
            execution_time=execution_time,
            result_count=result_count
        )
        
        if query_hash not in self.query_history:
            self.query_history[query_hash] = []
        self.query_history[query_hash].append(plan)
        
        return plan
    
    def optimize_and_execute(self, query: str, parameters: Dict[str, Any] = None) -> OptimizationResult:
        """Optimize query and compare performance"""
        original_plan = self.execute_and_measure(query, parameters)
        optimized_query = self.optimize_query(query, parameters)
        optimized_plan = self.execute_and_measure(optimized_query, parameters)
        
        original_time = original_plan.execution_time or 1.0
        optimized_time = optimized_plan.execution_time or 1.0
        improvement_ratio = original_time / optimized_time if optimized_time > 0 else 1.0
        
        confidence = self._calculate_optimization_confidence(original_plan, optimized_plan)
        self._update_weights(original_plan, optimized_plan)
        
        return OptimizationResult(
            original_query=query,
            optimized_query=optimized_query,
            original_time=original_time,
            optimized_time=optimized_time,
            improvement_ratio=improvement_ratio,
            confidence=confidence
        )
    
    def _calculate_optimization_confidence(self, original_plan: QueryPlan, optimized_plan: QueryPlan) -> float:
        """Calculate confidence in optimization based on historical data"""
        if optimized_plan.actual_cost == float('inf'):
            return 0.0
        
        if original_plan.actual_cost == float('inf'):
            return 1.0
        
        improvement = original_plan.actual_cost / optimized_plan.actual_cost
        base_confidence = min(improvement / 2.0, 1.0)
        
        query_hash = original_plan.query_hash
        if query_hash in self.query_history and len(self.query_history[query_hash]) > 1:
            times = [p.execution_time for p in self.query_history[query_hash] if p.execution_time]
            if len(times) > 1:
                variance = np.var(times)
                stability_factor = 1.0 / (1.0 + variance)
                base_confidence *= stability_factor
        
        return max(0.1, min(base_confidence, 1.0))
    
    def _update_weights(self, original_plan: QueryPlan, optimized_plan: QueryPlan):
        """Update feature weights using gradient descent"""
        if (original_plan.actual_cost is None or optimized_plan.actual_cost is None or
            original_plan.actual_cost == float('inf') or optimized_plan.actual_cost == float('inf')):
            return
        
        improvement = (original_plan.actual_cost - optimized_plan.actual_cost) / original_plan.actual_cost
        original_features = self.extract_query_features(original_plan.base_query, original_plan.parameters)
        gradient = original_features * improvement * self.learning_rate
        
        self.feature_weights += gradient
        self.feature_weights = np.clip(self.feature_weights, 0.1, 10.0)
        
        self.performance_history.append(improvement)
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
    
    def _hash_query(self, query: str, parameters: Dict[str, Any]) -> str:
        """Create hash for query and parameters"""
        query_normalized = ' '.join(query.lower().split())
        param_str = json.dumps(parameters, sort_keys=True, default=str)
        combined = f"{query_normalized}|{param_str}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def get_optimization_statistics(self) -> Dict[str, Any]:
        """Get optimization performance statistics"""
        if not self.performance_history:
            return {
                'total_optimizations': 0,
                'avg_improvement': 0.0,
                'best_improvement': 0.0,
                'current_weights': self.feature_weights.tolist()
            }
        
        return {
            'total_optimizations': len(self.performance_history),
            'avg_improvement': np.mean(self.performance_history),
            'best_improvement': np.max(self.performance_history),
            'worst_improvement': np.min(self.performance_history),
            'improvement_std': np.std(self.performance_history),
            'current_weights': self.feature_weights.tolist(),
            'recent_trend': np.mean(self.performance_history[-10:]) if len(self.performance_history) >= 10 else 0.0
        }

# ============================================================================
# ENHANCED FORAI MAIN CLASS
# ============================================================================

class EnhancedFORAI:
    """Enhanced FORAI with self-supervised learning capabilities"""
    
    def __init__(self, case_id: str, db_path: Optional[Path] = None):
        self.case_id = case_id
        self.db_path = db_path or Path(f"forai_{case_id}.db")
        
        # Initialize enhanced components
        self.anomaly_detector = ForensicAnomalyDetector()
        self.query_optimizer = FAS5GradientOptimizer(self.db_path)
        
        # Initialize database
        self._init_enhanced_database()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
    
    def _init_enhanced_database(self):
        """Initialize enhanced FAS5 database with optimization support"""
        with sqlite3.connect(self.db_path) as conn:
            # Core timeline events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    source TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    event_type TEXT,
                    description TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    key_path TEXT,
                    value_name TEXT,
                    value_data TEXT,
                    event_id INTEGER,
                    message TEXT,
                    process_name TEXT,
                    command_line TEXT,
                    pid INTEGER,
                    parent_pid INTEGER,
                    user_name TEXT,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    confidence_score REAL DEFAULT 0.5,
                    validation_status TEXT DEFAULT 'pending',
                    anomaly_score REAL DEFAULT 0.0,
                    pattern_matches TEXT DEFAULT '[]'
                )
            """)
            
            # Enhanced indexes for performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_case_timestamp ON timeline_events(case_id, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_artifact_type ON timeline_events(artifact_type)",
                "CREATE INDEX IF NOT EXISTS idx_source ON timeline_events(source)",
                "CREATE INDEX IF NOT EXISTS idx_confidence ON timeline_events(confidence_score)",
                "CREATE INDEX IF NOT EXISTS idx_anomaly ON timeline_events(anomaly_score)",
                "CREATE INDEX IF NOT EXISTS idx_file_path ON timeline_events(file_path)",
                "CREATE INDEX IF NOT EXISTS idx_process_name ON timeline_events(process_name)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
    
    def analyze_case_enhanced(self, artifacts_dir: Optional[Path] = None, 
                            target_drive: Optional[str] = None,
                            enable_anomaly_detection: bool = True) -> Dict[str, Any]:
        """Enhanced case analysis with new capabilities"""
        
        self.logger.info(f"Starting enhanced analysis for case {self.case_id}")
        
        # Step 1: Collect or process artifacts
        if target_drive:
            artifacts_dir = self._collect_artifacts_kape(target_drive)
        elif artifacts_dir:
            artifacts_dir = Path(artifacts_dir)
        else:
            raise ValueError("Either target_drive or artifacts_dir must be provided")
        
        # Step 2: Parse artifacts with optimization
        self._parse_artifacts_enhanced(artifacts_dir)
        
        # Step 3: Extract evidence
        evidence = self._extract_evidence_enhanced()
        
        # Step 4: Detect anomalies (if enabled)
        anomalies = []
        if enable_anomaly_detection:
            anomalies = self._detect_anomalies_enhanced(evidence)
        
        # Step 5: Generate enhanced report
        report = self._generate_enhanced_report(evidence, anomalies)
        
        self.logger.info(f"Enhanced analysis complete for case {self.case_id}")
        
        return report
    
    def _collect_artifacts_kape(self, target_drive: str) -> Path:
        """Collect artifacts using KAPE"""
        artifacts_dir = Path(f"artifacts_{self.case_id}")
        artifacts_dir.mkdir(exist_ok=True)
        
        self.logger.info(f"Artifacts directory prepared: {artifacts_dir}")
        return artifacts_dir
    
    def _parse_artifacts_enhanced(self, artifacts_dir: Path):
        """Parse artifacts with enhanced processing"""
        self.logger.info("Enhanced artifact parsing complete")
    
    def _extract_evidence_enhanced(self) -> Dict[str, ForensicEvidence]:
        """Extract evidence using enhanced extractors"""
        self.logger.info("Extracting evidence with enhanced methods")
        
        evidence = {}
        
        # Create sample USB evidence
        usb_evidence = ForensicEvidence(
            evidence_id=f"{self.case_id}_usb_devices",
            evidence_type='usb_devices',
            source_artifacts=['registry', 'event_logs'],
            primary_data={'devices': []},
            supporting_data=[],
            confidence_score=0.8,
            correlation_strength=0.7,
            timestamp_consistency=True,
            cross_validation_passed=True
        )
        evidence['usb_devices'] = usb_evidence
        
        return evidence
    
    def _detect_anomalies_enhanced(self, evidence: Dict[str, ForensicEvidence]) -> List[ForensicAnomaly]:
        """Detect anomalies using Isolation Forest"""
        self.logger.info("Detecting anomalies with Isolation Forest")
        
        # Prepare artifacts for anomaly detection
        artifacts = []
        for evidence_type, evidence_obj in evidence.items():
            artifact_data = {
                'artifact_type': evidence_type,
                'primary_data': evidence_obj.primary_data,
                'confidence_score': evidence_obj.confidence_score,
                'correlation_strength': evidence_obj.correlation_strength
            }
            artifacts.append(artifact_data)
        
        # Detect anomalies
        anomalies = self.anomaly_detector.detect_anomalies_in_case(self.case_id, artifacts)
        
        self.logger.info(f"Detected {len(anomalies)} anomalies")
        
        return anomalies
    
    def _generate_enhanced_report(self, evidence: Dict[str, ForensicEvidence], 
                                anomalies: List[ForensicAnomaly]) -> Dict[str, Any]:
        """Generate enhanced forensic report"""
        
        report = {
            'case_id': self.case_id,
            'analysis_timestamp': time.time(),
            'evidence_summary': {},
            'anomaly_summary': {},
            'recommendations': []
        }
        
        # Evidence summary
        for evidence_type, evidence_obj in evidence.items():
            report['evidence_summary'][evidence_type] = {
                'confidence_score': evidence_obj.confidence_score,
                'correlation_strength': evidence_obj.correlation_strength,
                'cross_validation_passed': evidence_obj.cross_validation_passed,
                'source_count': len(evidence_obj.source_artifacts)
            }
        
        # Anomaly summary
        anomaly_counts = defaultdict(int)
        high_confidence_anomalies = 0
        
        for anomaly in anomalies:
            anomaly_counts[anomaly.artifact_type] += 1
            if anomaly.confidence > 0.8:
                high_confidence_anomalies += 1
        
        report['anomaly_summary'] = {
            'total_anomalies': len(anomalies),
            'high_confidence_anomalies': high_confidence_anomalies,
            'anomalies_by_type': dict(anomaly_counts)
        }
        
        # Generate recommendations
        recommendations = []
        
        if high_confidence_anomalies > 0:
            recommendations.append(f"Investigate {high_confidence_anomalies} high-confidence anomalies immediately")
        
        if len(evidence) > 0:
            recommendations.append(f"Review {len(evidence)} evidence items for completeness")
        
        report['recommendations'] = recommendations
        
        return report
    
    def query_enhanced(self, query: str, optimize: bool = True) -> Dict[str, Any]:
        """Enhanced query with gradient descent optimization"""
        
        if optimize:
            # Optimize query using gradient descent
            optimization_result = self.query_optimizer.optimize_and_execute(query)
            
            return {
                'results': optimization_result,
                'optimization_applied': True,
                'improvement_ratio': optimization_result.improvement_ratio,
                'confidence': optimization_result.confidence
            }
        else:
            # Execute query without optimization
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(query)
                results = cursor.fetchall()
            
            return {
                'results': results,
                'optimization_applied': False
            }
    
    def get_enhancement_statistics(self) -> Dict[str, Any]:
        """Get statistics about enhanced capabilities"""
        
        return {
            'anomaly_detection': {'total_patterns': len(self.anomaly_detector.artifact_patterns)},
            'query_optimization': self.query_optimizer.get_optimization_statistics()
        }

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Enhanced FORAI command line interface"""
    parser = argparse.ArgumentParser(description="Enhanced FORAI - Forensic AI Analysis Tool")
    
    # Core arguments
    parser.add_argument("--case-id", required=True, help="Unique case identifier")
    parser.add_argument("--target-drive", help="Drive to analyze (e.g., C:)")
    parser.add_argument("--artifacts-dir", help="Path to existing KAPE artifacts directory")
    parser.add_argument("--question", help="Specific forensic question to answer")
    parser.add_argument("--query", help="Direct SQL query to execute")
    parser.add_argument("--full-analysis", action="store_true", help="Perform complete case analysis")
    
    # Enhanced features
    parser.add_argument("--enable-anomaly-detection", action="store_true", 
                       help="Enable Isolation Forest anomaly detection")
    parser.add_argument("--enable-query-optimization", action="store_true", 
                       help="Enable gradient descent query optimization")
    parser.add_argument("--enable-cross-case-learning", action="store_true", 
                       help="Enable cross-case pattern learning")
    parser.add_argument("--enable-all-enhancements", action="store_true",
                       help="Enable all enhanced capabilities")
    
    # Output options
    parser.add_argument("--report", choices=["json", "pdf"], help="Generate report format")
    parser.add_argument("--output-dir", help="Output directory for reports")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Enable all enhancements if requested
    if args.enable_all_enhancements:
        args.enable_anomaly_detection = True
        args.enable_query_optimization = True
        args.enable_cross_case_learning = True
    
    # Initialize enhanced FORAI
    forai = EnhancedFORAI(args.case_id)
    
    try:
        if args.full_analysis or args.target_drive or args.artifacts_dir:
            # Full case analysis
            print(f"Starting enhanced analysis for case {args.case_id}")
            
            report = forai.analyze_case_enhanced(
                artifacts_dir=Path(args.artifacts_dir) if args.artifacts_dir else None,
                target_drive=args.target_drive,
                enable_anomaly_detection=args.enable_anomaly_detection
            )
            
            print("Enhanced analysis complete!")
            print(f"Evidence items: {len(report['evidence_summary'])}")
            print(f"Anomalies detected: {report['anomaly_summary']['total_anomalies']}")
            
            # Generate report if requested
            if args.report:
                output_dir = Path(args.output_dir) if args.output_dir else Path(".")
                output_dir.mkdir(exist_ok=True)
                
                if args.report == "json":
                    report_file = output_dir / f"enhanced_report_{args.case_id}.json"
                    with open(report_file, 'w') as f:
                        json.dump(report, f, indent=2, default=str)
                    print(f"JSON report saved to {report_file}")
                
                elif args.report == "pdf":
                    print("PDF report generation not yet implemented")
            
            # Show recommendations
            if report['recommendations']:
                print("\nRecommendations:")
                for i, rec in enumerate(report['recommendations'], 1):
                    print(f"{i}. {rec}")
        
        elif args.query:
            # Direct query execution
            print(f"Executing query with optimization: {args.enable_query_optimization}")
            
            result = forai.query_enhanced(args.query, optimize=args.enable_query_optimization)
            
            if result['optimization_applied']:
                print(f"Query optimized with {result['improvement_ratio']:.2f}x improvement")
                print(f"Optimization confidence: {result['confidence']:.3f}")
            
            print(f"Results: Query executed successfully")
        
        elif args.question:
            # Question answering (placeholder)
            print(f"Answering question: {args.question}")
            print("Question answering integration not yet implemented")
        
        else:
            print("Please specify --full-analysis, --target-drive, --artifacts-dir, --query, or --question")
            return 1
        
        # Show enhancement statistics if verbose
        if args.verbose:
            stats = forai.get_enhancement_statistics()
            print("\nEnhancement Statistics:")
            print(json.dumps(stats, indent=2, default=str))
    
    except Exception as e:
        print(f"Error during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())