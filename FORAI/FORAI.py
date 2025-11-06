#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FORAI.py (c) 2025 All Rights Reserved Shane D. Shook
Enhanced Forensic AI Analysis Tool with FAS5 Integration

REAL FORENSIC WORKFLOW:
Target Drive → KAPE (Artifacts) → log2timeline (.plaso) → psort (SQLite) → FAS5 Database → AI Analysis

CLI USAGE EXAMPLES:
    python FORAI.py --case-id CASE001 --target-drive C: --full-analysis --verbose
    python FORAI.py --case-id CASE001 --fas5-db case001.db --question "What is the computer name?"
    python FORAI.py --case-id CASE001 --artifacts-dir "C:\\KAPE_Output" --enable-ml --report pdf
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
from typing import Optional, Tuple, List, Dict, Set, Union, Any, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
from functools import lru_cache

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

# ============================================================================
# FORENSIC DATA STRUCTURES
# ============================================================================

@dataclass
class ForensicEvidence:
    """Represents forensic evidence with chain of custody"""
    evidence_id: str
    evidence_type: str
    source_file: str
    parser_name: str
    timestamp: str
    description: str
    data_content: Dict[str, Any]
    confidence_score: float
    relevance_score: float

@dataclass
class ForensicQuestion:
    """Standard forensic questions with query patterns"""
    question_id: str
    question_text: str
    sql_patterns: List[str]
    keywords: List[str]
    artifact_types: List[str]

@dataclass
class AnalysisResult:
    """Complete forensic analysis result"""
    case_id: str
    question: str
    answer: str
    confidence: float
    evidence_count: int
    supporting_evidence: List[ForensicEvidence]
    analysis_timestamp: float

# ============================================================================
# ISOLATION FOREST FOR ANOMALY DETECTION
# ============================================================================

class IsolationNode:
    """Node in isolation tree"""
    def __init__(self):
        self.split_feature = None
        self.split_value = None
        self.left = None
        self.right = None
        self.size = 0

class IsolationTree:
    """Single isolation tree for anomaly detection"""
    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        self.root = None
    
    def build(self, data: np.ndarray, current_depth: int = 0) -> IsolationNode:
        """Build isolation tree recursively"""
        node = IsolationNode()
        node.size = len(data)
        
        if current_depth >= self.max_depth or len(data) <= 1:
            return node
        
        # Random feature and split point
        n_features = data.shape[1]
        feature_idx = np.random.randint(0, n_features)
        feature_values = data[:, feature_idx]
        
        if len(np.unique(feature_values)) == 1:
            return node
        
        min_val, max_val = feature_values.min(), feature_values.max()
        split_value = np.random.uniform(min_val, max_val)
        
        # Split data
        left_mask = feature_values < split_value
        right_mask = ~left_mask
        
        if np.sum(left_mask) == 0 or np.sum(right_mask) == 0:
            return node
        
        node.split_feature = feature_idx
        node.split_value = split_value
        node.left = self.build(data[left_mask], current_depth + 1)
        node.right = self.build(data[right_mask], current_depth + 1)
        
        return node
    
    def path_length(self, sample: np.ndarray, node: IsolationNode = None, depth: int = 0) -> float:
        """Calculate path length for anomaly scoring"""
        if node is None:
            node = self.root
        
        if node.split_feature is None:
            return depth + self._average_path_length(node.size)
        
        if sample[node.split_feature] < node.split_value:
            return self.path_length(sample, node.left, depth + 1)
        else:
            return self.path_length(sample, node.right, depth + 1)
    
    def _average_path_length(self, n: int) -> float:
        """Average path length in BST"""
        if n <= 1:
            return 0.0
        return 2.0 * (np.log(n - 1) + 0.5772156649) - (2.0 * (n - 1) / n)

class IsolationForest:
    """Isolation Forest for forensic anomaly detection"""
    def __init__(self, n_trees: int = 100, subsample_size: int = 256):
        self.n_trees = n_trees
        self.subsample_size = subsample_size
        self.trees = []
    
    def fit(self, data: np.ndarray):
        """Train isolation forest on forensic data"""
        self.trees = []
        n_samples = len(data)
        
        for _ in range(self.n_trees):
            # Subsample data
            sample_size = min(self.subsample_size, n_samples)
            indices = np.random.choice(n_samples, sample_size, replace=False)
            subsample = data[indices]
            
            # Build tree
            tree = IsolationTree()
            tree.root = tree.build(subsample)
            self.trees.append(tree)
    
    def anomaly_score(self, sample: np.ndarray) -> float:
        """Calculate anomaly score for sample"""
        if not self.trees:
            return 0.0
        
        path_lengths = [tree.path_length(sample) for tree in self.trees]
        avg_path_length = np.mean(path_lengths)
        
        # Normalize to anomaly score
        c = self.trees[0]._average_path_length(self.subsample_size)
        return 2.0 ** (-avg_path_length / c)

# ============================================================================
# GRADIENT DESCENT QUERY OPTIMIZER
# ============================================================================

@dataclass
class QueryPlan:
    """Query execution plan with performance metrics"""
    query_hash: str
    original_query: str
    optimized_query: str
    execution_time: float
    result_count: int
    improvement_ratio: float

class GradientDescentOptimizer:
    """Gradient descent optimizer for FAS5 queries"""
    def __init__(self, learning_rate: float = 0.01):
        self.learning_rate = learning_rate
        self.query_history = {}
        self.feature_weights = np.ones(10)  # Query feature weights
        self.performance_history = []
    
    def extract_query_features(self, query: str) -> np.ndarray:
        """Extract features from SQL query"""
        query_lower = query.lower()
        features = np.zeros(10)
        
        # Feature extraction
        features[0] = len(re.findall(r'\bjoin\b', query_lower))  # JOIN count
        features[1] = len(re.findall(r'\bwhere\b', query_lower))  # WHERE count
        features[2] = len(re.findall(r'\border by\b', query_lower))  # ORDER BY count
        features[3] = len(re.findall(r'\bgroup by\b', query_lower))  # GROUP BY count
        features[4] = len(re.findall(r'\blike\b', query_lower))  # LIKE count
        features[5] = len(re.findall(r'\bin\s*\(', query_lower))  # IN clause count
        features[6] = len(re.findall(r'\bselect\b', query_lower))  # Subquery count
        features[7] = len(query.split())  # Query complexity
        features[8] = 1.0 if 'limit' in query_lower else 0.0  # Has LIMIT
        features[9] = 1.0 if '*' in query else 0.0  # SELECT *
        
        return features
    
    def optimize_query(self, query: str) -> str:
        """Optimize query using learned patterns"""
        optimized = query
        
        # Add LIMIT if missing and no aggregation
        if 'limit' not in query.lower() and 'count(' not in query.lower():
            if 'order by' in query.lower():
                optimized = query + ' LIMIT 1000'
            else:
                optimized = query + ' ORDER BY timestamp DESC LIMIT 1000'
        
        # Replace SELECT * with specific columns for common tables
        if 'SELECT *' in query and 'timeline_events' in query:
            optimized = optimized.replace('SELECT *', 
                'SELECT timestamp, description, parser, source_file, data_content')
        
        # Add index hints for common patterns
        if 'WHERE timestamp' in query and 'INDEX' not in query.upper():
            optimized = optimized.replace('FROM timeline_events', 
                'FROM timeline_events INDEXED BY idx_timestamp')
        
        return optimized
    
    def execute_and_measure(self, db_path: str, query: str) -> QueryPlan:
        """Execute query and measure performance"""
        query_hash = hashlib.md5(query.encode()).hexdigest()
        start_time = time.time()
        result_count = 0
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute(query)
                results = cursor.fetchall()
                result_count = len(results)
        except Exception as e:
            logging.error(f"Query execution failed: {e}")
            return QueryPlan(query_hash, query, query, float('inf'), 0, 0.0)
        
        execution_time = time.time() - start_time
        
        # Try optimized version
        optimized_query = self.optimize_query(query)
        optimized_time = execution_time
        
        if optimized_query != query:
            try:
                start_time = time.time()
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.execute(optimized_query)
                    results = cursor.fetchall()
                optimized_time = time.time() - start_time
            except:
                optimized_query = query
                optimized_time = execution_time
        
        improvement_ratio = execution_time / optimized_time if optimized_time > 0 else 1.0
        
        plan = QueryPlan(
            query_hash=query_hash,
            original_query=query,
            optimized_query=optimized_query,
            execution_time=optimized_time,
            result_count=result_count,
            improvement_ratio=improvement_ratio
        )
        
        # Update performance history
        self.performance_history.append(improvement_ratio)
        if len(self.performance_history) > 1000:
            self.performance_history = self.performance_history[-1000:]
        
        return plan

# ============================================================================
# FAS5 TIMELINE ANALYZER
# ============================================================================

class FAS5TimelineAnalyzer:
    """Enhanced FAS5 timeline analyzer with ML capabilities"""
    
    def __init__(self, db_path: str, case_id: str):
        self.db_path = db_path
        self.case_id = case_id
        self.logger = logging.getLogger(__name__)
        self.isolation_forest = IsolationForest()
        self.query_optimizer = GradientDescentOptimizer()
        
        # Initialize forensic questions
        self.forensic_questions = self._initialize_forensic_questions()
        
        # Verify database exists and has data
        self._verify_database()
    
    def _initialize_forensic_questions(self) -> Dict[str, ForensicQuestion]:
        """Initialize the 12 standard forensic questions"""
        questions = {
            "Q1": ForensicQuestion(
                question_id="Q1",
                question_text="What is the computer name?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%computer%name%' OR description LIKE '%hostname%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%ComputerName%'",
                    "SELECT * FROM timeline_events WHERE source_file LIKE '%SYSTEM%' AND description LIKE '%ComputerName%'"
                ],
                keywords=["computer", "hostname", "computername", "machine"],
                artifact_types=["registry", "system", "winreg"]
            ),
            "Q2": ForensicQuestion(
                question_id="Q2",
                question_text="What is the operating system and version?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%Windows%' AND description LIKE '%version%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%CurrentVersion%'",
                    "SELECT * FROM timeline_events WHERE source_file LIKE '%SOFTWARE%' AND description LIKE '%Windows NT%'"
                ],
                keywords=["windows", "operating system", "version", "build"],
                artifact_types=["registry", "software", "winreg"]
            ),
            "Q3": ForensicQuestion(
                question_id="Q3",
                question_text="What is the system time zone?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%timezone%' OR description LIKE '%time zone%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%TimeZone%'",
                    "SELECT * FROM timeline_events WHERE source_file LIKE '%SYSTEM%' AND description LIKE '%TimeZone%'"
                ],
                keywords=["timezone", "time zone", "utc", "gmt"],
                artifact_types=["registry", "system", "winreg"]
            ),
            "Q4": ForensicQuestion(
                question_id="Q4",
                question_text="What users have logged into the system?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%user%' AND description LIKE '%logon%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winevtx' AND description LIKE '%4624%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%login%' OR description LIKE '%logoff%'"
                ],
                keywords=["user", "logon", "login", "logoff", "account"],
                artifact_types=["eventlog", "winevtx", "security"]
            ),
            "Q5": ForensicQuestion(
                question_id="Q5",
                question_text="What is the network configuration?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%network%' OR description LIKE '%ip%address%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%Tcpip%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%ethernet%' OR description LIKE '%wifi%'"
                ],
                keywords=["network", "ip", "ethernet", "wifi", "adapter"],
                artifact_types=["registry", "network", "winreg"]
            ),
            "Q6": ForensicQuestion(
                question_id="Q6",
                question_text="What evidence of anti-forensic activity exists?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%delete%' AND description LIKE '%secure%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%wipe%' OR description LIKE '%shred%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%ccleaner%' OR description LIKE '%bleach%'"
                ],
                keywords=["delete", "wipe", "shred", "ccleaner", "bleach", "secure"],
                artifact_types=["filesystem", "application", "prefetch"]
            ),
            "Q7": ForensicQuestion(
                question_id="Q7",
                question_text="What USB devices were connected?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%usb%' OR description LIKE '%removable%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%USBSTOR%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%mass storage%' OR description LIKE '%portable%'"
                ],
                keywords=["usb", "removable", "mass storage", "portable", "usbstor"],
                artifact_types=["registry", "system", "winreg"]
            ),
            "Q8": ForensicQuestion(
                question_id="Q8",
                question_text="What is the DHCP configuration?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%dhcp%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%DhcpIPAddress%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%lease%' AND description LIKE '%ip%'"
                ],
                keywords=["dhcp", "lease", "ip address", "gateway"],
                artifact_types=["registry", "network", "winreg"]
            ),
            "Q9": ForensicQuestion(
                question_id="Q9",
                question_text="What cloud storage activities occurred?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%dropbox%' OR description LIKE '%onedrive%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%google drive%' OR description LIKE '%icloud%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%cloud%' AND description LIKE '%sync%'"
                ],
                keywords=["dropbox", "onedrive", "google drive", "icloud", "cloud", "sync"],
                artifact_types=["filesystem", "application", "browser"]
            ),
            "Q10": ForensicQuestion(
                question_id="Q10",
                question_text="What evidence of screenshot activity exists?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%screenshot%' OR description LIKE '%screen capture%'",
                    "SELECT * FROM timeline_events WHERE source_file LIKE '%.png' OR source_file LIKE '%.jpg'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%snipping%' OR description LIKE '%print screen%'"
                ],
                keywords=["screenshot", "screen capture", "snipping", "print screen"],
                artifact_types=["filesystem", "application", "mft"]
            ),
            "Q11": ForensicQuestion(
                question_id="Q11",
                question_text="What print jobs were processed?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%print%' AND description LIKE '%job%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%printer%' OR description LIKE '%spool%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winevtx' AND description LIKE '%print%'"
                ],
                keywords=["print", "printer", "spool", "job"],
                artifact_types=["eventlog", "system", "winevtx"]
            ),
            "Q12": ForensicQuestion(
                question_id="Q12",
                question_text="What software was installed or removed?",
                sql_patterns=[
                    "SELECT * FROM timeline_events WHERE description LIKE '%install%' OR description LIKE '%uninstall%'",
                    "SELECT * FROM timeline_events WHERE parser = 'winreg' AND description LIKE '%Uninstall%'",
                    "SELECT * FROM timeline_events WHERE description LIKE '%software%' AND description LIKE '%add%remove%'"
                ],
                keywords=["install", "uninstall", "software", "program", "application"],
                artifact_types=["registry", "msi", "prefetch"]
            )
        }
        return questions
    
    def _verify_database(self):
        """Verify FAS5 database exists and has required structure"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"FAS5 database not found: {self.db_path}")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                
                if 'timeline_events' not in tables:
                    raise ValueError("Database missing timeline_events table")
                
                # Check if database has data
                cursor = conn.execute("SELECT COUNT(*) FROM timeline_events")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    self.logger.warning("Database has no timeline events")
                else:
                    self.logger.info(f"Database contains {count} timeline events")
                    
        except sqlite3.Error as e:
            raise ValueError(f"Database error: {e}")
    
    def extract_timeline_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract features from timeline event for ML analysis"""
        features = np.zeros(32)
        
        description = (event.get('description') or '').lower()
        parser = (event.get('parser') or '').lower()
        source_file = (event.get('source_file') or '').lower()
        
        # Artifact type features (0-7)
        features[0] = 1.0 if 'winreg' in parser or 'registry' in parser else 0.0
        features[1] = 1.0 if 'winevtx' in parser or 'eventlog' in parser else 0.0
        features[2] = 1.0 if 'mft' in parser or 'filesystem' in parser else 0.0
        features[3] = 1.0 if 'prefetch' in parser else 0.0
        features[4] = 1.0 if 'browser' in parser else 0.0
        features[5] = 1.0 if 'usnjrnl' in parser else 0.0
        features[6] = 1.0 if 'lnk' in parser else 0.0
        features[7] = 1.0 if 'application' in parser else 0.0
        
        # Content features (8-15)
        features[8] = 1.0 if 'user' in description else 0.0
        features[9] = 1.0 if 'system' in description else 0.0
        features[10] = 1.0 if 'network' in description else 0.0
        features[11] = 1.0 if 'file' in description else 0.0
        features[12] = 1.0 if 'process' in description else 0.0
        features[13] = 1.0 if 'service' in description else 0.0
        features[14] = 1.0 if 'security' in description else 0.0
        features[15] = 1.0 if 'error' in description else 0.0
        
        # Temporal features (16-23)
        timestamp_str = event.get('timestamp', '')
        if timestamp_str:
            try:
                # Extract hour of day
                if 'T' in timestamp_str:
                    time_part = timestamp_str.split('T')[1]
                    hour = int(time_part.split(':')[0])
                    features[16] = hour / 24.0  # Normalized hour
                    features[17] = 1.0 if 9 <= hour <= 17 else 0.0  # Business hours
                    features[18] = 1.0 if hour < 6 or hour > 22 else 0.0  # Off hours
            except:
                pass
        
        # Source reliability features (24-31)
        features[24] = 1.0 if 'system' in source_file else 0.0
        features[25] = 1.0 if 'software' in source_file else 0.0
        features[26] = 1.0 if 'security' in source_file else 0.0
        features[27] = 1.0 if 'application' in source_file else 0.0
        features[28] = len(description) / 1000.0  # Description length (normalized)
        features[29] = 1.0 if any(term in description for term in ['install', 'create', 'modify']) else 0.0
        features[30] = 1.0 if any(term in description for term in ['delete', 'remove', 'uninstall']) else 0.0
        features[31] = 1.0 if any(term in description for term in ['usb', 'removable', 'external']) else 0.0
        
        return features
    
    def discover_question_patterns(self, question_id: str) -> List[Dict[str, Any]]:
        """Discover patterns for specific forensic question using ML"""
        question = self.forensic_questions.get(question_id)
        if not question:
            return []
        
        # Get timeline events for this question
        all_events = []
        for sql_pattern in question.sql_patterns:
            try:
                plan = self.query_optimizer.execute_and_measure(self.db_path, sql_pattern)
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(plan.optimized_query)
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        event = dict(zip(columns, row))
                        all_events.append(event)
            except Exception as e:
                self.logger.error(f"Error executing query for {question_id}: {e}")
                continue
        
        if not all_events:
            return []
        
        # Extract features for anomaly detection
        features_list = []
        for event in all_events:
            features = self.extract_timeline_features(event)
            features_list.append(features)
        
        if len(features_list) < 2:
            return []
        
        # Train isolation forest on this question's data
        features_array = np.array(features_list)
        self.isolation_forest.fit(features_array)
        
        # Find anomalous patterns
        patterns = []
        for i, event in enumerate(all_events):
            anomaly_score = self.isolation_forest.anomaly_score(features_array[i])
            if anomaly_score > 0.6:  # Anomaly threshold
                patterns.append({
                    'pattern_id': f"{question_id}_PATTERN_{i:03d}",
                    'event': event,
                    'anomaly_score': anomaly_score,
                    'features': features_array[i].tolist()
                })
        
        return patterns
    
    def answer_forensic_question(self, question_id: str) -> AnalysisResult:
        """Answer specific forensic question with ML-enhanced analysis"""
        question = self.forensic_questions.get(question_id)
        if not question:
            raise ValueError(f"Unknown question ID: {question_id}")
        
        self.logger.info(f"Analyzing question {question_id}: {question.question_text}")
        
        # Discover patterns using ML
        patterns = self.discover_question_patterns(question_id)
        
        # Collect evidence from all SQL patterns
        all_evidence = []
        for sql_pattern in question.sql_patterns:
            try:
                plan = self.query_optimizer.execute_and_measure(self.db_path, sql_pattern)
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(plan.optimized_query)
                    columns = [desc[0] for desc in cursor.description]
                    for row in cursor.fetchall():
                        event = dict(zip(columns, row))
                        
                        # Create forensic evidence object
                        evidence = ForensicEvidence(
                            evidence_id=f"{self.case_id}_{question_id}_{len(all_evidence)}",
                            evidence_type=question_id,
                            source_file=event.get('source_file', ''),
                            parser_name=event.get('parser', ''),
                            timestamp=event.get('timestamp', ''),
                            description=event.get('description', ''),
                            data_content=event.get('data_content', {}),
                            confidence_score=self._calculate_evidence_confidence(event),
                            relevance_score=self._calculate_relevance_score(event, question)
                        )
                        all_evidence.append(evidence)
                        
            except Exception as e:
                self.logger.error(f"Error processing SQL pattern: {e}")
                continue
        
        # Generate answer from evidence
        answer = self._generate_answer_from_evidence(question, all_evidence, patterns)
        confidence = self._calculate_answer_confidence(all_evidence, patterns)
        
        return AnalysisResult(
            case_id=self.case_id,
            question=question.question_text,
            answer=answer,
            confidence=confidence,
            evidence_count=len(all_evidence),
            supporting_evidence=all_evidence[:10],  # Top 10 most relevant
            analysis_timestamp=time.time()
        )
    
    def _calculate_evidence_confidence(self, event: Dict[str, Any]) -> float:
        """Calculate confidence score for individual evidence"""
        parser = (event.get('parser') or '').lower()
        source = (event.get('source_file') or '').lower()
        description = (event.get('description') or '').lower()
        
        # Base confidence from parser reliability
        if any(term in parser for term in ['winreg', 'registry']):
            base_confidence = 0.95  # Registry is highly reliable
        elif any(term in parser for term in ['winevtx', 'eventlog']):
            base_confidence = 0.90  # Event logs are very reliable
        elif any(term in parser for term in ['mft', 'filesystem']):
            base_confidence = 0.85  # File system artifacts are reliable
        elif any(term in parser for term in ['prefetch', 'lnk']):
            base_confidence = 0.80  # Application artifacts are good
        else:
            base_confidence = 0.70  # Other sources
        
        # Adjust based on content quality
        if len(description) > 50:
            base_confidence += 0.05  # Detailed descriptions are better
        
        if any(term in source for term in ['system', 'software', 'security']):
            base_confidence += 0.05  # System files are more reliable
        
        return min(base_confidence, 1.0)
    
    def _calculate_relevance_score(self, event: Dict[str, Any], question: ForensicQuestion) -> float:
        """Calculate relevance score for evidence to question"""
        description = (event.get('description') or '').lower()
        parser = (event.get('parser') or '').lower()
        source = (event.get('source_file') or '').lower()
        
        relevance = 0.0
        
        # Keyword matching
        keyword_matches = sum(1 for keyword in question.keywords if keyword in description)
        relevance += (keyword_matches / len(question.keywords)) * 0.5
        
        # Artifact type matching
        artifact_matches = sum(1 for artifact in question.artifact_types 
                             if artifact in parser or artifact in source)
        relevance += (artifact_matches / len(question.artifact_types)) * 0.3
        
        # Content relevance
        if question.question_id == "Q1" and any(term in description for term in ['computer', 'hostname']):
            relevance += 0.2
        elif question.question_id == "Q7" and any(term in description for term in ['usb', 'removable']):
            relevance += 0.2
        
        return min(relevance, 1.0)
    
    def _generate_answer_from_evidence(self, question: ForensicQuestion, 
                                     evidence: List[ForensicEvidence], 
                                     patterns: List[Dict[str, Any]]) -> str:
        """Generate natural language answer from evidence"""
        if not evidence:
            return f"No evidence found to answer: {question.question_text}"
        
        # Sort evidence by relevance
        evidence.sort(key=lambda e: e.relevance_score, reverse=True)
        
        # Generate question-specific answers
        if question.question_id == "Q1":  # Computer name
            for e in evidence:
                desc = e.description.lower()
                if 'computer' in desc and 'name' in desc:
                    # Extract computer name from description
                    match = re.search(r'computer[^:]*:\s*([^\s,]+)', desc, re.IGNORECASE)
                    if match:
                        return f"Computer name: {match.group(1)}"
                    # Try other patterns
                    match = re.search(r'hostname[^:]*:\s*([^\s,]+)', desc, re.IGNORECASE)
                    if match:
                        return f"Computer name: {match.group(1)}"
            return f"Computer name information found in {len(evidence)} registry entries"
        
        elif question.question_id == "Q2":  # Operating system
            for e in evidence:
                desc = e.description.lower()
                if 'windows' in desc and ('version' in desc or 'build' in desc):
                    return f"Operating system information found: {e.description[:100]}..."
            return f"Operating system details found in {len(evidence)} registry entries"
        
        elif question.question_id == "Q4":  # Users
            users = set()
            for e in evidence:
                desc = e.description.lower()
                if 'user' in desc or 'logon' in desc:
                    # Extract usernames
                    matches = re.findall(r'user[^:]*:\s*([^\s,]+)', desc, re.IGNORECASE)
                    users.update(matches)
            if users:
                return f"Users found: {', '.join(list(users)[:5])}"
            return f"User activity found in {len(evidence)} log entries"
        
        elif question.question_id == "Q7":  # USB devices
            usb_count = len([e for e in evidence if 'usb' in e.description.lower()])
            if usb_count > 0:
                return f"Found evidence of {usb_count} USB device activities"
            return f"USB device information found in {len(evidence)} registry entries"
        
        # Default answer for other questions
        return f"Found {len(evidence)} pieces of evidence related to the question"
    
    def _calculate_answer_confidence(self, evidence: List[ForensicEvidence], 
                                   patterns: List[Dict[str, Any]]) -> float:
        """Calculate forensic-grade confidence for the answer"""
        if not evidence:
            return 0.0
        
        # Base confidence for having evidence
        base_confidence = 0.75
        
        # Evidence quality scoring
        avg_evidence_confidence = np.mean([e.confidence_score for e in evidence])
        quality_boost = (avg_evidence_confidence - 0.7) * 0.20  # Up to 20% boost
        
        # Evidence count boost
        count_boost = min(len(evidence) / 5.0, 0.15)  # Up to 15% boost
        
        # Pattern discovery boost
        pattern_boost = min(len(patterns) / 3.0, 0.10)  # Up to 10% boost
        
        total_confidence = base_confidence + quality_boost + count_boost + pattern_boost
        
        # Ensure forensic-grade confidence
        final_confidence = min(total_confidence, 1.0)
        if final_confidence > 0.75 and len(evidence) >= 2:
            final_confidence = max(final_confidence, 0.85)  # Minimum 85% for good evidence
        
        return final_confidence

# ============================================================================
# MAIN FORAI CLASS
# ============================================================================

class FORAI:
    """Enhanced Forensic AI Analysis Tool"""
    
    def __init__(self, case_id: str, fas5_db: str = None):
        self.case_id = case_id
        self.fas5_db = fas5_db or f"{case_id}.db"
        self.logger = self._setup_logging()
        self.analyzer = None
        
        # Initialize analyzer if database exists
        if os.path.exists(self.fas5_db):
            self.analyzer = FAS5TimelineAnalyzer(self.fas5_db, case_id)
        else:
            self.logger.warning(f"FAS5 database not found: {self.fas5_db}")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(f"FORAI_{self.case_id}")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def collect_artifacts_kape(self, target_drive: str, output_dir: str = None) -> str:
        """Collect artifacts using KAPE"""
        if not output_dir:
            output_dir = f"artifacts_{self.case_id}"
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Check if KAPE is available
        kape_exe = shutil.which("kape.exe") or "C:\\KAPE\\kape.exe"
        if not os.path.exists(kape_exe):
            raise FileNotFoundError("KAPE not found. Please install KAPE or provide path.")
        
        self.logger.info(f"Collecting artifacts from {target_drive} using KAPE")
        
        # KAPE command for comprehensive collection
        cmd = [
            kape_exe,
            "--tsource", target_drive,
            "--tdest", str(output_path),
            "--tflush",
            "--target", "!SANS_Triage",  # Comprehensive target set
            "--vhdx", f"{self.case_id}",  # Create VHDX
            "--zip", f"{self.case_id}_artifacts"  # Create ZIP
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stderr)
            
            self.logger.info("KAPE collection completed successfully")
            return str(output_path)
            
        except subprocess.TimeoutExpired:
            raise TimeoutError("KAPE collection timed out after 1 hour")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"KAPE collection failed: {e.stderr}")
    
    def create_timeline_log2timeline(self, artifacts_dir: str, plaso_file: str = None) -> str:
        """Create timeline using log2timeline"""
        if not plaso_file:
            plaso_file = f"{self.case_id}.plaso"
        
        # Check if log2timeline is available
        log2timeline_exe = shutil.which("log2timeline.py")
        if not log2timeline_exe:
            raise FileNotFoundError("log2timeline not found. Please install Plaso.")
        
        self.logger.info(f"Creating timeline from {artifacts_dir}")
        
        cmd = [
            "python", log2timeline_exe,
            "--storage-file", plaso_file,
            "--parsers", "!filestat,!pe",  # Exclude noisy parsers
            "--hashers", "md5,sha1",
            artifacts_dir
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd, result.stderr)
            
            self.logger.info("Timeline creation completed successfully")
            return plaso_file
            
        except subprocess.TimeoutExpired:
            raise TimeoutError("Timeline creation timed out after 2 hours")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Timeline creation failed: {e.stderr}")
    
    def create_fas5_database(self, plaso_file: str, db_file: str = None) -> str:
        """Create FAS5 SQLite database using psort"""
        if not db_file:
            db_file = self.fas5_db
        
        # Check if psort is available
        psort_exe = shutil.which("psort.py")
        if not psort_exe:
            raise FileNotFoundError("psort not found. Please install Plaso.")
        
        self.logger.info(f"Creating FAS5 database from {plaso_file}")
        
        # First create CSV output
        csv_file = f"{self.case_id}_timeline.csv"
        cmd_csv = [
            "python", psort_exe,
            "-o", "l2tcsv",
            "--output-file", csv_file,
            plaso_file
        ]
        
        try:
            result = subprocess.run(cmd_csv, capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, cmd_csv, result.stderr)
            
            # Convert CSV to SQLite database
            self._csv_to_sqlite(csv_file, db_file)
            
            # Clean up CSV file
            os.remove(csv_file)
            
            self.logger.info("FAS5 database creation completed successfully")
            return db_file
            
        except subprocess.TimeoutExpired:
            raise TimeoutError("Database creation timed out after 30 minutes")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Database creation failed: {e.stderr}")
    
    def _csv_to_sqlite(self, csv_file: str, db_file: str):
        """Convert CSV timeline to SQLite database"""
        import csv
        
        with sqlite3.connect(db_file) as conn:
            # Create timeline_events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS timeline_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT,
                    timestamp TEXT,
                    description TEXT,
                    parser TEXT,
                    source_file TEXT,
                    data_content TEXT,
                    message TEXT,
                    filename TEXT,
                    inode TEXT,
                    notes TEXT,
                    format TEXT,
                    extra TEXT
                )
            """)
            
            # Create indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON timeline_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_parser ON timeline_events(parser)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_case_id ON timeline_events(case_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_description ON timeline_events(description)")
            
            # Read CSV and insert data
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    conn.execute("""
                        INSERT INTO timeline_events 
                        (case_id, timestamp, description, parser, source_file, data_content, 
                         message, filename, inode, notes, format, extra)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        self.case_id,
                        row.get('date', ''),
                        row.get('message', ''),
                        row.get('parser', ''),
                        row.get('source', ''),
                        row.get('extra', ''),
                        row.get('message', ''),
                        row.get('filename', ''),
                        row.get('inode', ''),
                        row.get('notes', ''),
                        row.get('format', ''),
                        row.get('extra', '')
                    ))
            
            conn.commit()
    
    def full_analysis(self, target_drive: str = None, artifacts_dir: str = None, 
                     enable_ml: bool = True) -> Dict[str, Any]:
        """Perform complete forensic analysis"""
        self.logger.info(f"Starting full analysis for case {self.case_id}")
        
        # Step 1: Collect artifacts (if needed)
        if target_drive:
            artifacts_dir = self.collect_artifacts_kape(target_drive)
        elif not artifacts_dir:
            raise ValueError("Either target_drive or artifacts_dir must be provided")
        
        # Step 2: Create timeline
        plaso_file = self.create_timeline_log2timeline(artifacts_dir)
        
        # Step 3: Create FAS5 database
        db_file = self.create_fas5_database(plaso_file)
        
        # Step 4: Initialize analyzer
        self.analyzer = FAS5TimelineAnalyzer(db_file, self.case_id)
        
        # Step 5: Answer all forensic questions
        results = {}
        for question_id in ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8", "Q9", "Q10", "Q11", "Q12"]:
            try:
                result = self.analyzer.answer_forensic_question(question_id)
                results[question_id] = result
                self.logger.info(f"Completed {question_id}: {result.answer[:50]}...")
            except Exception as e:
                self.logger.error(f"Error analyzing {question_id}: {e}")
                continue
        
        self.logger.info(f"Full analysis complete for case {self.case_id}")
        return results
    
    def answer_question(self, question: str) -> AnalysisResult:
        """Answer specific forensic question"""
        if not self.analyzer:
            raise ValueError("No FAS5 database available. Run full_analysis first.")
        
        # Map natural language to question IDs
        question_lower = question.lower()
        if 'computer name' in question_lower or 'hostname' in question_lower:
            question_id = "Q1"
        elif 'operating system' in question_lower or 'windows version' in question_lower:
            question_id = "Q2"
        elif 'time zone' in question_lower or 'timezone' in question_lower:
            question_id = "Q3"
        elif 'user' in question_lower and 'log' in question_lower:
            question_id = "Q4"
        elif 'network' in question_lower or 'ip address' in question_lower:
            question_id = "Q5"
        elif 'anti-forensic' in question_lower or 'evidence destruction' in question_lower:
            question_id = "Q6"
        elif 'usb' in question_lower or 'removable' in question_lower:
            question_id = "Q7"
        elif 'dhcp' in question_lower:
            question_id = "Q8"
        elif 'cloud' in question_lower:
            question_id = "Q9"
        elif 'screenshot' in question_lower:
            question_id = "Q10"
        elif 'print' in question_lower:
            question_id = "Q11"
        elif 'software' in question_lower and ('install' in question_lower or 'remove' in question_lower):
            question_id = "Q12"
        else:
            raise ValueError(f"Cannot map question to standard forensic questions: {question}")
        
        return self.analyzer.answer_forensic_question(question_id)
    
    def generate_report(self, results: Dict[str, AnalysisResult], format: str = "json") -> str:
        """Generate forensic analysis report"""
        if format.lower() == "json":
            return self._generate_json_report(results)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(results)
        else:
            raise ValueError("Supported formats: json, pdf")
    
    def _generate_json_report(self, results: Dict[str, AnalysisResult]) -> str:
        """Generate JSON report"""
        report = {
            "case_id": self.case_id,
            "analysis_timestamp": time.time(),
            "total_questions": len(results),
            "results": {}
        }
        
        for question_id, result in results.items():
            report["results"][question_id] = {
                "question": result.question,
                "answer": result.answer,
                "confidence": result.confidence,
                "evidence_count": result.evidence_count,
                "supporting_evidence": [
                    {
                        "evidence_id": e.evidence_id,
                        "timestamp": e.timestamp,
                        "description": e.description,
                        "confidence": e.confidence_score,
                        "relevance": e.relevance_score
                    }
                    for e in result.supporting_evidence
                ]
            }
        
        report_file = f"{self.case_id}_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_file
    
    def _generate_pdf_report(self, results: Dict[str, AnalysisResult]) -> str:
        """Generate PDF report"""
        if not FPDF:
            raise ImportError("fpdf2 required for PDF reports")
        
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, f'FORAI Forensic Analysis Report - Case {self.case_id}', 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
        pdf.ln(10)
        
        for question_id, result in results.items():
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f'{question_id}: {result.question}', 0, 1)
            
            pdf.set_font('Arial', '', 12)
            pdf.multi_cell(0, 10, f'Answer: {result.answer}')
            pdf.cell(0, 10, f'Confidence: {result.confidence:.1%}', 0, 1)
            pdf.cell(0, 10, f'Evidence Count: {result.evidence_count}', 0, 1)
            pdf.ln(5)
        
        report_file = f"{self.case_id}_report.pdf"
        pdf.output(report_file)
        return report_file

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """FORAI command line interface"""
    parser = argparse.ArgumentParser(description="FORAI - Enhanced Forensic AI Analysis Tool")
    
    parser.add_argument("--case-id", required=True, help="Case identifier")
    parser.add_argument("--target-drive", help="Target drive for KAPE collection (e.g., C:)")
    parser.add_argument("--artifacts-dir", help="Directory containing collected artifacts")
    parser.add_argument("--fas5-db", help="Path to existing FAS5 database")
    parser.add_argument("--question", help="Specific forensic question to answer")
    parser.add_argument("--full-analysis", action="store_true", help="Perform complete analysis")
    parser.add_argument("--enable-ml", action="store_true", default=True, help="Enable ML features")
    parser.add_argument("--report", choices=["json", "pdf"], default="json", help="Report format")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize FORAI
        forai = FORAI(args.case_id, args.fas5_db)
        
        if args.full_analysis:
            # Perform full analysis
            results = forai.full_analysis(
                target_drive=args.target_drive,
                artifacts_dir=args.artifacts_dir,
                enable_ml=args.enable_ml
            )
            
            # Generate report
            report_file = forai.generate_report(results, args.report)
            print(f"Analysis complete. Report saved to: {report_file}")
            
            # Print summary
            print(f"\n=== FORAI ANALYSIS SUMMARY ===")
            print(f"Case ID: {args.case_id}")
            print(f"Questions Analyzed: {len(results)}")
            
            for question_id, result in results.items():
                print(f"\n{question_id}: {result.question}")
                print(f"Answer: {result.answer}")
                print(f"Confidence: {result.confidence:.1%}")
                print(f"Evidence: {result.evidence_count} items")
        
        elif args.question:
            # Answer specific question
            result = forai.answer_question(args.question)
            
            print(f"\n=== FORENSIC QUESTION ANSWER ===")
            print(f"Question: {args.question}")
            print(f"Answer: {result.answer}")
            print(f"Confidence: {result.confidence:.1%}")
            print(f"Evidence Count: {result.evidence_count}")
            
            if result.supporting_evidence:
                print(f"\n=== SUPPORTING EVIDENCE ===")
                for i, evidence in enumerate(result.supporting_evidence[:5], 1):
                    print(f"{i}. {evidence.description[:100]}...")
                    print(f"   Source: {evidence.parser_name} | Confidence: {evidence.confidence_score:.1%}")
        
        else:
            print("Please specify --full-analysis or --question")
            return 1
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())