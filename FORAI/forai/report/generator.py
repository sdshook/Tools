"""
Forensic report generator with full provenance.

Reports are saved to: {output_dir}/{case_id}_{YYMMDDHHMMSS}/
Default output_dir: ./Reports
"""

import json
import hashlib
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..db.evidence import EvidenceDB
from ..extraction.extractors import QuestionAnswer, ForensicExtractor


# Default report output directory
DEFAULT_REPORTS_DIR = Path("Reports")


def get_report_dir(case_id: str, output_dir: Optional[Union[str, Path]] = None) -> Path:
    """
    Get the report directory path for a case.
    
    Args:
        case_id: Case identifier
        output_dir: Base output directory (default: ./Reports)
        
    Returns:
        Path to report directory: {output_dir}/{case_id}_{YYMMDDHHMMSS}/
    """
    base_dir = Path(output_dir) if output_dir else DEFAULT_REPORTS_DIR
    timestamp = datetime.now().strftime("%y%m%d%H%M%S")
    report_dir = base_dir / f"{case_id}_{timestamp}"
    return report_dir


def ensure_report_dir(case_id: str, output_dir: Optional[Union[str, Path]] = None) -> Path:
    """
    Create and return the report directory path.
    
    Args:
        case_id: Case identifier
        output_dir: Base output directory (default: ./Reports)
        
    Returns:
        Path to created report directory
    """
    report_dir = get_report_dir(case_id, output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


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


def save_full_report(case_id: str,
                     report: Dict[str, Any],
                     output_dir: Optional[Union[str, Path]] = None,
                     formats: List[str] = None) -> Path:
    """
    Save complete report package to designated directory.
    
    Creates: {output_dir}/{case_id}_{YYMMDDHHMMSS}/
    Contains:
      - report.json (always)
      - report.pdf (if 'pdf' in formats)
      - provenance.json (trajectory, LLM log, hashes)
      - manifest.txt (file listing with hashes)
    
    Args:
        case_id: Case identifier
        report: Generated report dict
        output_dir: Base output directory (default: ./Reports)
        formats: List of formats to save ['json', 'pdf'] (default: both)
        
    Returns:
        Path to the report directory
    """
    if formats is None:
        formats = ["json", "pdf"]
    
    # Create report directory
    report_dir = ensure_report_dir(case_id, output_dir)
    
    # Always save JSON
    json_path = report_dir / "report.json"
    save_report_json(report, json_path)
    
    # Save PDF if requested
    if "pdf" in formats:
        pdf_path = report_dir / "report.pdf"
        save_report_pdf(report, pdf_path)
    
    # Save provenance separately for easy access
    provenance = {
        "case_id": case_id,
        "report_hash": report["metadata"]["report_hash"],
        "generated_at": report["metadata"]["generated_at"],
        "graph_state_hash": report["provenance"].get("graph_state_hash"),
        "trajectory": report["provenance"].get("trajectory"),
        "llm_interactions": report["provenance"].get("llm_interactions"),
        "chain_of_custody_entries": len(report.get("chain_of_custody", []))
    }
    provenance_path = report_dir / "provenance.json"
    with open(provenance_path, 'w') as f:
        json.dump(provenance, f, indent=2, default=str)
    
    # Create manifest with file hashes
    manifest_lines = [
        f"FORAI Report Manifest",
        f"Case ID: {case_id}",
        f"Generated: {report['metadata']['generated_at']}",
        f"Report Hash: {report['metadata']['report_hash']}",
        "",
        "Files:",
    ]
    
    for file_path in sorted(report_dir.iterdir()):
        if file_path.is_file() and file_path.name != "manifest.txt":
            file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()[:16]
            manifest_lines.append(f"  {file_path.name}: {file_hash}")
    
    manifest_path = report_dir / "manifest.txt"
    manifest_path.write_text("\n".join(manifest_lines))
    
    return report_dir


def save_report_text(report: Dict[str, Any], output_path: Path):
    """Save report as plain text (for quick review)."""
    lines = [
        "=" * 60,
        "FORAI Forensic Analysis Report",
        "=" * 60,
        f"Case ID: {report['metadata']['case_id']}",
        f"Generated: {report['metadata']['generated_at']}",
        f"Report Hash: {report['metadata']['report_hash']}",
        "",
        "-" * 60,
        "SUMMARY",
        "-" * 60,
        f"Questions Answered: {report['summary']['total_questions']}",
        f"High Confidence: {report['summary']['high_confidence_answers']}",
        f"Evidence Sources: {report['summary']['evidence_sources']}",
        "",
        "-" * 60,
        "FORENSIC QUESTIONS",
        "-" * 60,
    ]
    
    for q in report["questions"]:
        lines.append("")
        lines.append(f"{q['id']}: {q['question']}")
        lines.append("-" * 40)
        lines.append(f"Answer: {q['answer']}")
        lines.append(f"Confidence: {q['confidence']:.0%}")
        lines.append(f"Sources ({len(q['sources'])}): {', '.join(q['sources'][:5])}")
        if len(q['sources']) > 5:
            lines.append(f"  ... and {len(q['sources']) - 5} more")
    
    lines.extend([
        "",
        "-" * 60,
        "PROVENANCE",
        "-" * 60,
        f"Graph State Hash: {report['provenance'].get('graph_state_hash', 'N/A')}",
    ])
    
    if report["provenance"].get("trajectory"):
        traj = report["provenance"]["trajectory"]
        lines.append(f"RL Trajectory: {traj.get('trajectory_id', 'N/A')} ({len(traj.get('steps', []))} steps)")
    
    if report["provenance"].get("llm_interactions"):
        lines.append(f"LLM Interactions: {len(report['provenance']['llm_interactions'])}")
    
    lines.extend([
        "",
        "=" * 60,
        "END OF REPORT",
        "=" * 60,
    ])
    
    output_path.write_text("\n".join(lines))
