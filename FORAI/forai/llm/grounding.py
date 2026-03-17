"""
Graph-grounded LLM prompts for FORAI.
"""

from typing import Any, Dict, List, Optional

from ..graph.graph import ForensicGraph
from .provider import LLMProvider, LLMLogger, LLMResponse


SYSTEM_PROMPT = """You are a forensic analyst assistant. Answer questions using ONLY the evidence provided in the graph context below. Do not speculate or add information not present in the evidence.

If the evidence is insufficient to answer, say so clearly.

Always cite specific nodes or edges from the context to support your conclusions."""


def build_explanation_prompt(question: str, subgraph_context: str, 
                            additional_context: str = "") -> str:
    """Build a graph-grounded prompt for explanation."""
    prompt = f"""{SYSTEM_PROMPT}

{subgraph_context}

{f"Additional Context: {additional_context}" if additional_context else ""}

Question: {question}

Answer (cite evidence from the graph):"""
    
    return prompt


def build_analysis_prompt(evidence_summary: str, question: str) -> str:
    """Build prompt for forensic analysis."""
    prompt = f"""{SYSTEM_PROMPT}

Evidence Summary:
{evidence_summary}

Question: {question}

Analysis (based only on the evidence above):"""
    
    return prompt


class GraphGroundedLLM:
    """
    LLM wrapper that provides graph-grounded explanations.
    
    All prompts include graph context and all responses are logged
    with graph state hashes for provenance.
    """
    
    def __init__(self, provider: LLMProvider, graph: ForensicGraph,
                 logger: LLMLogger, case_id: str):
        self.provider = provider
        self.graph = graph
        self.logger = logger
        self.case_id = case_id
    
    def explain(self, node_id: str, question: str, 
                depth: int = 2, temperature: float = 0.1) -> LLMResponse:
        """
        Generate explanation for a node grounded in graph context.
        
        Args:
            node_id: Node to explain
            question: Question to answer
            depth: Subgraph depth for context
            temperature: LLM temperature
            
        Returns:
            LLMResponse with provenance
        """
        # Get subgraph context
        subgraph = self.graph.get_subgraph(node_id, depth=depth)
        context = self.graph.serialize_for_llm(subgraph)
        graph_hash = self.graph.get_state_hash()
        
        # Build prompt
        prompt = build_explanation_prompt(question, context)
        
        # Generate response
        response_text = self.provider.generate(
            prompt, 
            max_tokens=500,
            temperature=temperature
        )
        
        # Log with provenance
        response = self.logger.log(
            case_id=self.case_id,
            prompt=prompt,
            response=response_text,
            graph_state_hash=graph_hash,
            model_name=self.provider.model_name,
            temperature=temperature
        )
        
        return response
    
    def analyze_evidence(self, evidence_list: List[Dict[str, Any]], 
                        question: str, temperature: float = 0.1) -> LLMResponse:
        """
        Analyze evidence list and answer question.
        
        Args:
            evidence_list: List of evidence items
            question: Question to answer
            temperature: LLM temperature
            
        Returns:
            LLMResponse with provenance
        """
        # Build evidence summary
        summary_lines = ["Evidence items:"]
        for e in evidence_list[:20]:  # Limit context
            ts = e.get("timestamp", 0)
            atype = e.get("artifact_type", "unknown")
            text = e.get("summary", str(e))[:100]
            summary_lines.append(f"- [{atype}] {text}")
        
        summary = "\n".join(summary_lines)
        graph_hash = self.graph.get_state_hash()
        
        # Build prompt
        prompt = build_analysis_prompt(summary, question)
        
        # Generate
        response_text = self.provider.generate(
            prompt,
            max_tokens=500,
            temperature=temperature
        )
        
        # Log
        response = self.logger.log(
            case_id=self.case_id,
            prompt=prompt,
            response=response_text,
            graph_state_hash=graph_hash,
            model_name=self.provider.model_name,
            temperature=temperature
        )
        
        return response
    
    def is_available(self) -> bool:
        """Check if LLM is available."""
        return self.provider.is_available()
