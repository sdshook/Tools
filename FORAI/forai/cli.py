"""
FORAI Command Line Interface.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import Config, set_config, get_config
from .db.evidence import EvidenceDB
from .extraction.extractors import ForensicExtractor, STANDARD_QUESTIONS
from .extraction.plaso import import_plaso_to_db, FAST_PARSERS, STANDARD_PARSERS
from .graph.graph import ForensicGraph
from .graph.builder import build_graph_from_evidence
from .report.generator import generate_report, save_full_report, DEFAULT_REPORTS_DIR


def cmd_analyze(args):
    """Run full analysis on a case."""
    config = get_config()
    
    print(f"=== FORAI Analysis: {args.case_id} ===")
    
    # Setup database
    db_path = config.db_dir / f"{args.case_id}.db"
    db = EvidenceDB(db_path)
    db.log_custody_event(args.case_id, "ANALYSIS_START", f"Starting analysis")
    
    # Import Plaso data if provided
    if args.plaso_file:
        print(f"Importing Plaso file: {args.plaso_file}")
        plaso_path = Path(args.plaso_file)
        if not plaso_path.exists():
            print(f"Error: Plaso file not found: {plaso_path}")
            return 1
        
        count = import_plaso_to_db(plaso_path, db, args.case_id)
        print(f"Imported {count} events")
        db.log_custody_event(args.case_id, "PLASO_IMPORT", f"Imported {count} events from {plaso_path}")
    
    # Check we have evidence
    stats = db.get_case_stats(args.case_id)
    if stats["total_evidence"] == 0:
        print("Error: No evidence in database. Import a Plaso file first.")
        return 1
    
    print(f"Evidence: {stats['total_evidence']} items, {len(stats['by_type'])} artifact types")
    
    # Build graph
    print("Building knowledge graph...")
    graph = ForensicGraph(db_path, args.case_id)
    node_count = build_graph_from_evidence(db, graph, args.case_id)
    print(f"Graph: {node_count} nodes")
    
    # Infer temporal edges
    print("Inferring temporal relationships...")
    graph.infer_temporal_edges()
    graph_stats = graph.get_stats()
    print(f"Edges: {graph_stats['edge_count']} ({graph_stats['anomalous_edges']} anomalous)")
    
    # Answer questions
    print("\nAnswering forensic questions...")
    extractor = ForensicExtractor(db, args.case_id)
    answers = extractor.answer_all_questions()
    
    for answer in answers:
        confidence_str = f"{answer.confidence:.0%}"
        print(f"  {answer.question_id}: {confidence_str} - {answer.answer.split(chr(10))[0][:60]}...")
    
    # Generate report
    print(f"\nGenerating report...")
    report = generate_report(
        case_id=args.case_id,
        answers=answers,
        db=db,
        graph_hash=graph.get_state_hash()
    )
    
    # Determine output directory
    output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_REPORTS_DIR
    
    # Determine formats
    formats = ["json"]
    if args.report_format == "pdf":
        formats.append("pdf")
    elif args.report_format == "all":
        formats = ["json", "pdf"]
    
    # Save full report package
    report_dir = save_full_report(
        case_id=args.case_id,
        report=report,
        output_dir=output_dir,
        formats=formats
    )
    
    print(f"\nReport saved to: {report_dir}/")
    print(f"  - report.json")
    if "pdf" in formats:
        print(f"  - report.pdf")
    print(f"  - provenance.json")
    print(f"  - manifest.txt")
    
    db.log_custody_event(args.case_id, "ANALYSIS_COMPLETE", f"Report generated: {report_dir}")
    
    return 0


def cmd_question(args):
    """Answer a specific forensic question."""
    config = get_config()
    db_path = config.db_dir / f"{args.case_id}.db"
    
    if not db_path.exists():
        print(f"Error: No database for case {args.case_id}")
        return 1
    
    db = EvidenceDB(db_path)
    extractor = ForensicExtractor(db, args.case_id)
    
    # Find matching question
    question_id = args.question.upper()
    answer = extractor.answer_question(question_id)
    
    if answer:
        print(f"\n{answer.question_id}: {answer.question}")
        print("-" * 60)
        print(answer.answer)
        print(f"\nConfidence: {answer.confidence:.0%}")
        print(f"Sources: {', '.join(answer.sources[:5])}")
    else:
        print(f"Unknown question ID: {question_id}")
        print("Available: Q1-Q12")
    
    return 0


def cmd_interactive(args):
    """Launch interactive analysis mode."""
    config = get_config()
    db_path = config.db_dir / f"{args.case_id}.db"
    
    if not db_path.exists():
        print(f"Error: No database for case {args.case_id}")
        return 1
    
    db = EvidenceDB(db_path)
    graph = ForensicGraph(db_path, args.case_id)
    
    # Try to setup LLM
    llm = None
    try:
        from .llm.provider import create_provider, LLMLogger
        from .llm.grounding import GraphGroundedLLM
        
        provider = create_provider()
        if provider and provider.is_available():
            logger = LLMLogger(db_path)
            llm = GraphGroundedLLM(provider, graph, logger, args.case_id)
            print(f"LLM available: {provider.model_name}")
    except:
        pass
    
    print(f"\n=== FORAI Interactive Mode: {args.case_id} ===")
    print("Commands: search <query>, question <Q1-Q12>, explain <node_id>, quit")
    print()
    
    extractor = ForensicExtractor(db, args.case_id)
    
    while True:
        try:
            cmd = input("forai> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        
        if not cmd:
            continue
        
        parts = cmd.split(maxsplit=1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        if action in ("quit", "exit", "q"):
            break
        
        elif action == "search":
            if not arg:
                print("Usage: search <query>")
                continue
            results = db.search_evidence(args.case_id, arg, limit=10)
            for r in results:
                print(f"  [{r.artifact_type}] {r.summary[:70]}...")
        
        elif action == "question":
            qid = arg.upper() or "Q1"
            answer = extractor.answer_question(qid)
            if answer:
                print(f"\n{answer.answer}")
                print(f"\nConfidence: {answer.confidence:.0%}")
            else:
                print(f"Unknown question: {qid}")
        
        elif action == "explain" and llm:
            if not arg:
                print("Usage: explain <node_id>")
                continue
            response = llm.explain(arg, "Why is this node significant?")
            print(f"\n{response.text}")
            print(f"\n[Hash: {response.response_hash}]")
        
        elif action == "stats":
            stats = db.get_case_stats(args.case_id)
            print(f"Evidence: {stats['total_evidence']}")
            for atype, count in stats.get('by_type', {}).items():
                print(f"  {atype}: {count}")
        
        else:
            print(f"Unknown command: {action}")
    
    return 0


def cmd_list_questions(args):
    """List all standard forensic questions."""
    print("\n=== Standard Forensic Questions ===\n")
    for q in STANDARD_QUESTIONS:
        print(f"{q['id']}: {q['question']}")
        print(f"    Artifacts: {', '.join(q['artifact_types'])}")
        print()
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="FORAI - Forensic AI Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--base-dir", type=Path, 
                       help="Base directory for FORAI data")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # analyze command
    p_analyze = subparsers.add_parser("analyze", help="Run full analysis")
    p_analyze.add_argument("case_id", help="Case identifier")
    p_analyze.add_argument("--plaso-file", type=Path, help="Plaso file to import")
    p_analyze.add_argument("--output-dir", "-o", type=Path,
                          help="Report output directory (default: ./Reports)")
    p_analyze.add_argument("--report-format", choices=["json", "pdf", "all"], default="all",
                          help="Report format: json, pdf, or all (default: all)")
    p_analyze.set_defaults(func=cmd_analyze)
    
    # question command
    p_question = subparsers.add_parser("question", help="Answer a forensic question")
    p_question.add_argument("case_id", help="Case identifier")
    p_question.add_argument("question", help="Question ID (Q1-Q12)")
    p_question.set_defaults(func=cmd_question)
    
    # interactive command
    p_interactive = subparsers.add_parser("interactive", help="Interactive analysis mode")
    p_interactive.add_argument("case_id", help="Case identifier")
    p_interactive.set_defaults(func=cmd_interactive)
    
    # list-questions command
    p_list = subparsers.add_parser("list-questions", help="List standard questions")
    p_list.set_defaults(func=cmd_list_questions)
    
    args = parser.parse_args()
    
    # Setup config
    if args.base_dir:
        config = Config(base_dir=args.base_dir)
        set_config(config)
    
    if args.command is None:
        parser.print_help()
        return 0
    
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
