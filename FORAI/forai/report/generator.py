"""
Forensic report generator with full provenance.
"""

import json
import hashlib
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..db.evidence import EvidenceDB
from ..extraction.extractors import QuestionAnswer, ForensicExtractor


def generate_report(case_id: str,
                   answers: List[QuestionAnswer],
                   db: EvidenceDB,
                   trajectory: Optional[Dict] = None,
                   llm_log: Optional[List[Dict]] = None,
                   graph_hash: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate comprehensive forensic report.
    
    Includes:
    - 12 standard question answers with attribution
    - Chain of custody log
    - RL agent trajectory (if used)
    - LLM interaction log with hashes (if used)
    - Graph state hash
    """
    report = {
        "metadata": {
            "case_id": case_id,
            "generated_at": datetime.now().isoformat(),
            "generator": "FORAI v2.0",
            "report_hash": ""
        },
        "summary": {
            "total_questions": len(answers),
            "high_confidence_answers": sum(1 for a in answers if a.confidence >= 0.8),
            "evidence_sources": len(set(s for a in answers for s in a.sources))
        },
        "questions": [],
        "chain_of_custody": db.get_custody_log(case_id),
        "provenance": {
            "graph_state_hash": graph_hash,
            "trajectory": trajectory,
            "llm_interactions": llm_log
        }
    }
    
    # Add question answers
    for answer in answers:
        report["questions"].append({
            "id": answer.question_id,
            "question": answer.question,
            "answer": answer.answer,
            "confidence": answer.confidence,
            "sources": answer.sources,
            "evidence_count": answer.evidence_count,
            "details": answer.details
        })
    
    # Compute report hash
    content = json.dumps(report["questions"], sort_keys=True)
    report["metadata"]["report_hash"] = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    return report


def save_report_json(report: Dict[str, Any], output_path: Path):
    """Save report as JSON."""
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)


def save_report_pdf(report: Dict[str, Any], output_path: Path):
    """Save report as PDF."""
    try:
        from fpdf import FPDF
    except ImportError:
        print("fpdf2 not installed, saving as JSON instead")
        save_report_json(report, output_path.with_suffix('.json'))
        return
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"Forensic Analysis Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Case ID: {report['metadata']['case_id']}", ln=True, align="C")
    pdf.cell(0, 6, f"Generated: {report['metadata']['generated_at']}", ln=True, align="C")
    pdf.ln(10)
    
    # Summary
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    summary = report["summary"]
    pdf.cell(0, 6, f"Questions Answered: {summary['total_questions']}", ln=True)
    pdf.cell(0, 6, f"High Confidence: {summary['high_confidence_answers']}", ln=True)
    pdf.cell(0, 6, f"Evidence Sources: {summary['evidence_sources']}", ln=True)
    pdf.ln(5)
    
    # Questions
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Forensic Questions", ln=True)
    
    for q in report["questions"]:
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(0, 6, f"{q['id']}: {q['question']}")
        
        pdf.set_font("Helvetica", "", 9)
        
        # Answer (handle multi-line)
        answer_lines = q['answer'].split('\n')
        for line in answer_lines[:10]:
            # Sanitize for PDF
            line = line.encode('latin-1', errors='replace').decode('latin-1')
            pdf.multi_cell(0, 5, f"  {line}")
        
        pdf.set_font("Helvetica", "I", 8)
        pdf.cell(0, 5, f"  Confidence: {q['confidence']:.0%} | Sources: {len(q['sources'])}", ln=True)
        pdf.ln(3)
    
    # Chain of Custody
    if report["chain_of_custody"]:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Chain of Custody", ln=True)
        pdf.set_font("Helvetica", "", 8)
        
        for entry in report["chain_of_custody"][:50]:
            ts = datetime.fromtimestamp(entry.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
            event = entry.get("event_type", "")
            desc = entry.get("description", "")[:80]
            pdf.cell(0, 4, f"{ts} | {event}: {desc}", ln=True)
    
    # Provenance
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Provenance", ln=True)
    pdf.set_font("Helvetica", "", 9)
    
    prov = report["provenance"]
    pdf.cell(0, 5, f"Graph State Hash: {prov.get('graph_state_hash', 'N/A')}", ln=True)
    pdf.cell(0, 5, f"Report Hash: {report['metadata']['report_hash']}", ln=True)
    
    if prov.get("trajectory"):
        pdf.cell(0, 5, f"RL Trajectory ID: {prov['trajectory'].get('trajectory_id', 'N/A')}", ln=True)
        pdf.cell(0, 5, f"Steps: {len(prov['trajectory'].get('steps', []))}", ln=True)
    
    if prov.get("llm_interactions"):
        pdf.cell(0, 5, f"LLM Interactions: {len(prov['llm_interactions'])}", ln=True)
    
    pdf.output(str(output_path))


def save_report(report: Dict[str, Any], output_path: Path, format: str = "json"):
    """Save report in specified format."""
    if format == "pdf":
        save_report_pdf(report, output_path)
    else:
        save_report_json(report, output_path)
