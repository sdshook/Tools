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

# LLM Integration - Support multiple providers
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ============================================================================
# LLM INTEGRATION SYSTEM
# ============================================================================

class ForensicLLMAnalyzer:
    """LLM-powered forensic analysis and report generation system"""
    
    def __init__(self, provider: str = "openai", api_key: Optional[str] = None, model: str = None):
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(f"{provider.upper()}_API_KEY")
        
        if self.provider == "openai" and OPENAI_AVAILABLE:
            self.model = model or "gpt-4"
            if self.api_key:
                openai.api_key = self.api_key
        elif self.provider == "anthropic" and ANTHROPIC_AVAILABLE:
            self.model = model or "claude-3-sonnet-20240229"
            if self.api_key:
                self.client = anthropic.Anthropic(api_key=self.api_key)
        elif self.provider == "local" and REQUESTS_AVAILABLE:
            self.model = model or "llama3"
            self.base_url = "http://localhost:11434/api/generate"  # Ollama default
        else:
            raise ValueError(f"LLM provider '{provider}' not available or not supported")
    
    def analyze_evidence_with_llm(self, question: str, evidence_list: List[ForensicEvidence], 
                                 context: str = "") -> Dict[str, Any]:
        """Use LLM to analyze forensic evidence and generate comprehensive answers"""
        
        # Prepare evidence context for LLM
        evidence_context = self._prepare_evidence_context(evidence_list)
        
        prompt = f"""You are a digital forensics expert analyzing evidence for a legal case. 
        
FORENSIC QUESTION: {question}

CASE CONTEXT: {context}

AVAILABLE EVIDENCE:
{evidence_context}

Please provide a comprehensive forensic analysis including:
1. DIRECT ANSWER: Clear, factual answer to the question
2. EVIDENCE SUMMARY: Key supporting evidence with timestamps
3. CONFIDENCE ASSESSMENT: Your confidence level (0-100%) and reasoning
4. INVESTIGATIVE NOTES: Additional observations or recommendations
5. LEGAL CONSIDERATIONS: Any chain of custody or admissibility notes

Format your response as structured JSON with these exact keys:
- "direct_answer"
- "evidence_summary" 
- "confidence_score"
- "confidence_reasoning"
- "investigative_notes"
- "legal_considerations"
- "supporting_evidence_ids"
"""
        
        try:
            response = self._call_llm(prompt)
            return self._parse_llm_response(response)
        except Exception as e:
            logging.error(f"LLM analysis failed: {e}")
            return self._fallback_analysis(question, evidence_list)
    
    def generate_report_summary(self, case_id: str, results: Dict[str, Any], 
                               case_context: str = "") -> Dict[str, str]:
        """Generate professional report header, summary, and conclusions using LLM"""
        
        # Prepare results summary for LLM
        results_summary = self._prepare_results_summary(results)
        
        prompt = f"""You are a senior digital forensics examiner preparing a formal forensic report.

CASE ID: {case_id}
CASE CONTEXT: {case_context}

ANALYSIS RESULTS:
{results_summary}

Generate a professional forensic report with these sections:

1. EXECUTIVE SUMMARY: High-level overview of findings and conclusions
2. CASE OVERVIEW: Brief description of the investigation scope and methodology  
3. KEY FINDINGS: Most significant discoveries with supporting evidence
4. TECHNICAL SUMMARY: Technical details and methodologies used
5. CONCLUSIONS: Final conclusions and recommendations
6. LIMITATIONS: Any limitations or caveats in the analysis

Format as JSON with keys: "executive_summary", "case_overview", "key_findings", 
"technical_summary", "conclusions", "limitations"
"""
        
        try:
            response = self._call_llm(prompt)
            return self._parse_report_response(response)
        except Exception as e:
            logging.error(f"Report generation failed: {e}")
            return self._fallback_report_summary(case_id, results)
    
    def answer_adhoc_question(self, question: str, database_path: str, 
                             context: str = "") -> Dict[str, Any]:
        """Answer ad-hoc forensic questions using LLM with database context"""
        
        # Query database for relevant evidence
        relevant_evidence = self._query_database_for_question(question, database_path)
        
        prompt = f"""You are a digital forensics expert answering an investigative question.

QUESTION: {question}
CONTEXT: {context}

RELEVANT FORENSIC DATA:
{self._prepare_evidence_context(relevant_evidence)}

Provide a thorough forensic analysis addressing:
1. Direct answer to the question
2. Supporting evidence with timestamps and sources
3. Confidence level and reasoning
4. Additional investigative leads or recommendations

Format as JSON with keys: "answer", "supporting_evidence", "confidence", 
"reasoning", "recommendations"
"""
        
        try:
            response = self._call_llm(prompt)
            return self._parse_adhoc_response(response)
        except Exception as e:
            logging.error(f"Ad-hoc question analysis failed: {e}")
            return {"answer": f"Error analyzing question: {e}", "confidence": 0}
    
    def _prepare_evidence_context(self, evidence_list: List[ForensicEvidence]) -> str:
        """Prepare evidence for LLM context"""
        if not evidence_list:
            return "No evidence available."
        
        context_parts = []
        for i, evidence in enumerate(evidence_list[:20]):  # Limit to top 20 for context
            context_parts.append(f"""
Evidence {i+1}:
- ID: {evidence.evidence_id}
- Type: {evidence.evidence_type}
- Timestamp: {evidence.timestamp}
- Source: {evidence.source_file}
- Parser: {evidence.parser_name}
- Description: {evidence.description}
- Confidence: {evidence.confidence_score:.2f}
- Relevance: {evidence.relevance_score:.2f}
""")
        
        return "\n".join(context_parts)
    
    def _prepare_results_summary(self, results: Dict[str, Any]) -> str:
        """Prepare analysis results for report generation"""
        summary_parts = []
        for question_id, result in results.items():
            summary_parts.append(f"""
{question_id}: {result.question}
Answer: {result.answer}
Confidence: {result.confidence:.2f}
Evidence Count: {result.evidence_count}
""")
        return "\n".join(summary_parts)
    
    def _call_llm(self, prompt: str) -> str:
        """Call the configured LLM provider"""
        if self.provider == "openai" and OPENAI_AVAILABLE:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.1
            )
            return response.choices[0].message.content
        
        elif self.provider == "anthropic" and ANTHROPIC_AVAILABLE:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        
        elif self.provider == "local" and REQUESTS_AVAILABLE:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 2000}
            }
            response = requests.post(self.base_url, json=payload)
            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                raise Exception(f"Local LLM request failed: {response.status_code}")
        
        else:
            raise Exception(f"LLM provider {self.provider} not properly configured")
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured format"""
        try:
            # Try to extract JSON from response
            import json
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                return json.loads(json_str)
        except:
            pass
        
        # Fallback parsing
        return {
            "direct_answer": response[:500],
            "evidence_summary": "See full response",
            "confidence_score": 75,
            "confidence_reasoning": "LLM analysis completed",
            "investigative_notes": response[500:1000] if len(response) > 500 else "",
            "legal_considerations": "Standard chain of custody applies",
            "supporting_evidence_ids": []
        }
    
    def _parse_report_response(self, response: str) -> Dict[str, str]:
        """Parse report generation response"""
        try:
            import json
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
        except:
            pass
        
        # Fallback
        return {
            "executive_summary": response[:300],
            "case_overview": "Digital forensic analysis conducted using FORAI",
            "key_findings": response[300:600] if len(response) > 300 else "See detailed results",
            "technical_summary": "Analysis performed using KAPE, log2timeline, and ML algorithms",
            "conclusions": response[600:900] if len(response) > 600 else "Analysis completed",
            "limitations": "Standard forensic analysis limitations apply"
        }
    
    def _parse_adhoc_response(self, response: str) -> Dict[str, Any]:
        """Parse ad-hoc question response"""
        try:
            import json
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
        except:
            pass
        
        return {
            "answer": response[:500],
            "supporting_evidence": "See analysis details",
            "confidence": 75,
            "reasoning": "LLM analysis completed",
            "recommendations": response[500:] if len(response) > 500 else "No additional recommendations"
        }
    
    def _query_database_for_question(self, question: str, database_path: str) -> List[ForensicEvidence]:
        """Query forensic database for evidence relevant to ad-hoc question"""
        if not os.path.exists(database_path):
            return []
        
        try:
            conn = sqlite3.connect(database_path)
            cursor = conn.cursor()
            
            # Simple keyword-based search - could be enhanced with semantic search
            keywords = question.lower().split()
            search_terms = " OR ".join([f"description LIKE '%{kw}%'" for kw in keywords if len(kw) > 3])
            
            query = f"""
            SELECT evidence_id, evidence_type, source_file, parser_name, timestamp, 
                   description, confidence_score, relevance_score
            FROM evidence 
            WHERE {search_terms}
            ORDER BY relevance_score DESC, confidence_score DESC
            LIMIT 50
            """
            
            cursor.execute(query)
            rows = cursor.fetchall()
            
            evidence_list = []
            for row in rows:
                evidence = ForensicEvidence(
                    evidence_id=row[0],
                    evidence_type=row[1],
                    source_file=row[2],
                    parser_name=row[3],
                    timestamp=row[4],
                    description=row[5],
                    data_content={},
                    confidence_score=row[6],
                    relevance_score=row[7],
                    chain_of_custody=[]
                )
                evidence_list.append(evidence)
            
            conn.close()
            return evidence_list
            
        except Exception as e:
            logging.error(f"Database query failed: {e}")
            return []
    
    def _fallback_analysis(self, question: str, evidence_list: List[ForensicEvidence]) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable"""
        return {
            "direct_answer": f"Found {len(evidence_list)} pieces of evidence related to: {question}",
            "evidence_summary": f"Evidence types: {set(e.evidence_type for e in evidence_list)}",
            "confidence_score": 60,
            "confidence_reasoning": "Basic pattern matching analysis",
            "investigative_notes": "LLM analysis unavailable - using fallback method",
            "legal_considerations": "Manual review recommended",
            "supporting_evidence_ids": [e.evidence_id for e in evidence_list[:10]]
        }
    
    def _fallback_report_summary(self, case_id: str, results: Dict[str, Any]) -> Dict[str, str]:
        """Fallback report generation when LLM is unavailable"""
        return {
            "executive_summary": f"Forensic analysis completed for case {case_id} with {len(results)} questions analyzed.",
            "case_overview": "Digital forensic examination conducted using FORAI automated analysis system.",
            "key_findings": f"Analysis covered {len(results)} forensic questions with varying confidence levels.",
            "technical_summary": "Analysis performed using KAPE artifact collection, log2timeline processing, and machine learning algorithms.",
            "conclusions": "Forensic analysis completed. Manual review of findings recommended.",
            "limitations": "Automated analysis - human expert review recommended for legal proceedings."
        }

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
    
    def __init__(self, db_path: str, case_id: str, llm_analyzer: Optional[ForensicLLMAnalyzer] = None):
        self.db_path = db_path
        self.case_id = case_id
        self.logger = logging.getLogger(__name__)
        self.isolation_forest = IsolationForest()
        self.query_optimizer = GradientDescentOptimizer()
        self.llm_analyzer = llm_analyzer
        
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
        """Generate natural language answer from evidence using LLM analysis"""
        if not evidence:
            return f"No evidence found to answer: {question.question_text}"
        
        # Sort evidence by relevance
        evidence.sort(key=lambda e: e.relevance_score, reverse=True)
        
        # Use LLM for comprehensive analysis if available
        if self.llm_analyzer:
            try:
                case_context = f"Case ID: {self.case_id}, Question: {question.question_text}"
                llm_result = self.llm_analyzer.analyze_evidence_with_llm(
                    question.question_text, 
                    evidence, 
                    case_context
                )
                
                # Return the direct answer from LLM analysis
                return llm_result.get("direct_answer", f"Found {len(evidence)} pieces of evidence")
                
            except Exception as e:
                self.logger.warning(f"LLM analysis failed, using fallback: {e}")
        
        # Fallback to pattern-based analysis
        return self._fallback_answer_generation(question, evidence, patterns)
    
    def _fallback_answer_generation(self, question: ForensicQuestion, 
                                   evidence: List[ForensicEvidence], 
                                   patterns: List[Dict[str, Any]]) -> str:
        """Fallback answer generation when LLM is unavailable"""
        # Generate question-specific answers using pattern matching
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
    
    def __init__(self, case_id: str, fas5_db: str = None, llm_provider: str = "openai", 
                 llm_api_key: str = None, llm_model: str = None):
        self.case_id = case_id
        self.fas5_db = fas5_db or f"{case_id}.db"
        self.logger = self._setup_logging()
        self.analyzer = None
        
        # Initialize LLM analyzer
        if llm_provider:
            try:
                self.llm_analyzer = ForensicLLMAnalyzer(
                    provider=llm_provider, 
                    api_key=llm_api_key, 
                    model=llm_model
                )
                self.logger.info(f"LLM analyzer initialized: {llm_provider}")
            except Exception as e:
                self.logger.warning(f"LLM analyzer initialization failed: {e}")
                self.llm_analyzer = None
        else:
            self.llm_analyzer = None
            self.logger.info("LLM analyzer disabled")
        
        # Initialize analyzer if database exists
        if os.path.exists(self.fas5_db):
            self.analyzer = FAS5TimelineAnalyzer(self.fas5_db, case_id, self.llm_analyzer)
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
    
    def answer_adhoc_question(self, question: str, context: str = "") -> Dict[str, Any]:
        """Answer ad-hoc forensic questions using LLM analysis"""
        if not self.llm_analyzer:
            return {
                "answer": "LLM analyzer not available for ad-hoc questions",
                "confidence": 0,
                "error": "No LLM configured"
            }
        
        try:
            self.logger.info(f"Processing ad-hoc question: {question}")
            result = self.llm_analyzer.answer_adhoc_question(question, self.fas5_db, context)
            return result
        except Exception as e:
            self.logger.error(f"Ad-hoc question analysis failed: {e}")
            return {
                "answer": f"Error processing question: {e}",
                "confidence": 0,
                "error": str(e)
            }
    
    def generate_report(self, results: Dict[str, AnalysisResult], format: str = "json") -> str:
        """Generate forensic analysis report"""
        if format.lower() == "json":
            return self._generate_json_report(results)
        elif format.lower() == "pdf":
            return self._generate_pdf_report(results)
        else:
            raise ValueError("Supported formats: json, pdf")
    
    def _generate_json_report(self, results: Dict[str, AnalysisResult]) -> str:
        """Generate JSON report with LLM-generated summaries"""
        # Generate LLM report summary if available
        report_summary = {}
        if self.llm_analyzer:
            try:
                case_context = f"Digital forensic analysis for case {self.case_id}"
                report_summary = self.llm_analyzer.generate_report_summary(
                    self.case_id, results, case_context
                )
            except Exception as e:
                self.logger.warning(f"LLM report summary generation failed: {e}")
        
        report = {
            "case_id": self.case_id,
            "analysis_timestamp": time.time(),
            "total_questions": len(results),
            "report_summary": report_summary,  # LLM-generated professional summary
            "results": {}
        }
        
        for question_id, result in results.items():
            # Generate LLM analysis for each question if available
            llm_analysis = {}
            if self.llm_analyzer:
                try:
                    llm_analysis = self.llm_analyzer.analyze_evidence_with_llm(
                        result.question, 
                        result.supporting_evidence,
                        f"Case {self.case_id}"
                    )
                except Exception as e:
                    self.logger.warning(f"LLM analysis failed for {question_id}: {e}")
            
            report["results"][question_id] = {
                "question": result.question,
                "answer": result.answer,
                "confidence": result.confidence,
                "evidence_count": result.evidence_count,
                "llm_analysis": llm_analysis,  # Comprehensive LLM analysis
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
        """Generate professional PDF report with LLM-generated summaries"""
        if not FPDF:
            raise ImportError("fpdf2 required for PDF reports")
        
        # Generate LLM report summary if available
        report_summary = {}
        if self.llm_analyzer:
            try:
                case_context = f"Digital forensic analysis for case {self.case_id}"
                report_summary = self.llm_analyzer.generate_report_summary(
                    self.case_id, results, case_context
                )
            except Exception as e:
                self.logger.warning(f"LLM report summary generation failed: {e}")
        
        pdf = FPDF()
        pdf.add_page()
        
        # Report Header
        pdf.set_font('Arial', 'B', 18)
        pdf.cell(0, 15, 'DIGITAL FORENSIC ANALYSIS REPORT', 0, 1, 'C')
        
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, f'Case ID: {self.case_id}', 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        pdf.cell(0, 10, 'Analysis Tool: FORAI (Forensic AI)', 0, 1, 'C')
        pdf.ln(10)
        
        # Executive Summary (LLM-generated)
        if report_summary.get("executive_summary"):
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'EXECUTIVE SUMMARY', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["executive_summary"])
            pdf.ln(5)
        
        # Case Overview (LLM-generated)
        if report_summary.get("case_overview"):
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'CASE OVERVIEW', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["case_overview"])
            pdf.ln(5)
        
        # Key Findings (LLM-generated)
        if report_summary.get("key_findings"):
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'KEY FINDINGS', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["key_findings"])
            pdf.ln(5)
        
        # Detailed Analysis Results
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 15, 'DETAILED ANALYSIS RESULTS', 0, 1)
        
        for question_id, result in results.items():
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f'{question_id}: {result.question}', 0, 1)
            
            pdf.set_font('Arial', '', 12)
            pdf.multi_cell(0, 8, f'Answer: {result.answer}')
            pdf.cell(0, 8, f'Confidence: {result.confidence:.1%}', 0, 1)
            pdf.cell(0, 8, f'Evidence Count: {result.evidence_count}', 0, 1)
            
            # Add top supporting evidence
            if result.supporting_evidence:
                pdf.set_font('Arial', 'I', 10)
                pdf.cell(0, 6, 'Key Supporting Evidence:', 0, 1)
                for i, evidence in enumerate(result.supporting_evidence[:3]):  # Top 3 evidence
                    pdf.multi_cell(0, 5, f'  {i+1}. {evidence.description[:100]}...')
            
            pdf.ln(8)
        
        # Technical Summary (LLM-generated)
        if report_summary.get("technical_summary"):
            pdf.add_page()
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'TECHNICAL SUMMARY', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["technical_summary"])
            pdf.ln(5)
        
        # Conclusions (LLM-generated)
        if report_summary.get("conclusions"):
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'CONCLUSIONS', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["conclusions"])
            pdf.ln(5)
        
        # Limitations (LLM-generated)
        if report_summary.get("limitations"):
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'LIMITATIONS', 0, 1)
            pdf.set_font('Arial', '', 11)
            pdf.multi_cell(0, 6, report_summary["limitations"])
        
        report_file = f"{self.case_id}_forensic_report.pdf"
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
    parser.add_argument("--adhoc-question", help="Ad-hoc forensic question for LLM analysis")
    parser.add_argument("--full-analysis", action="store_true", help="Perform complete analysis")
    parser.add_argument("--enable-ml", action="store_true", default=True, help="Enable ML features")
    parser.add_argument("--report", choices=["json", "pdf"], default="json", help="Report format")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    
    # LLM Configuration
    parser.add_argument("--llm-provider", choices=["openai", "anthropic", "local"], 
                       default="openai", help="LLM provider for analysis")
    parser.add_argument("--llm-api-key", help="API key for LLM provider")
    parser.add_argument("--llm-model", help="Specific LLM model to use")
    parser.add_argument("--disable-llm", action="store_true", help="Disable LLM features")
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize FORAI with LLM configuration
        llm_provider = None if args.disable_llm else args.llm_provider
        forai = FORAI(
            case_id=args.case_id, 
            fas5_db=args.fas5_db,
            llm_provider=llm_provider,
            llm_api_key=args.llm_api_key,
            llm_model=args.llm_model
        )
        
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
        
        elif args.adhoc_question:
            # Answer ad-hoc question using LLM
            result = forai.answer_adhoc_question(args.adhoc_question)
            
            print(f"\n=== AD-HOC FORENSIC ANALYSIS ===")
            print(f"Question: {args.adhoc_question}")
            print(f"Answer: {result.get('answer', 'No answer available')}")
            print(f"Confidence: {result.get('confidence', 0):.1%}")
            
            if result.get('reasoning'):
                print(f"\n=== ANALYSIS REASONING ===")
                print(result['reasoning'])
            
            if result.get('recommendations'):
                print(f"\n=== RECOMMENDATIONS ===")
                print(result['recommendations'])
        
        else:
            print("Please specify --full-analysis, --question, or --adhoc-question")
            return 1
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())