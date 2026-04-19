#!/usr/bin/env python3
"""
mcr_cli.py
MCR Command-Line Interface for CI/CD and scripting integration.

Usage:
    # Start a new workflow
    mcr start --type incident
    
    # Publish an event
    mcr publish --workflow-id <id> --step 0 --role user --content "Analyze this..."
    
    # Reconstruct context
    mcr reconstruct --workflow-id <id> --step 1 --task "Correlate findings..."
    
    # Get workflow history
    mcr history --workflow-id <id>
    
    # Get stream status
    mcr status

Environment Variables:
    MCR_NATS_URL: NATS server URL (default: nats://localhost:4222)
    MCR_TENANT: Tenant identifier (default: default)
    MCR_DOMAIN: Domain classification (default: workflows)
"""

import argparse
import asyncio
import json
import sys
from typing import Optional

from mcr_client import MCRClient, MCRConfig


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MCR Command-Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Start a workflow and capture the ID
    WORKFLOW_ID=$(mcr start --type incident --json | jq -r .workflow_id)
    
    # Publish user request
    mcr publish --workflow-id $WORKFLOW_ID --step 0 --role user \\
        --content "Analyze security alert for host 10.4.22.107"
    
    # Publish assistant response
    mcr publish --workflow-id $WORKFLOW_ID --step 0 --role assistant \\
        --content "Severity: HIGH. Recommend immediate isolation."
    
    # Reconstruct context for next step
    mcr reconstruct --workflow-id $WORKFLOW_ID --step 1 \\
        --task "Correlate with threat intelligence" --json
    
    # Use in CI/CD pipeline
    mcr publish --workflow-id $CI_PIPELINE_ID --step $CI_JOB_INDEX \\
        --role user --content "$(cat analysis_request.txt)" \\
        --type ci --metadata '{"job": "security-scan"}'
""",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Start workflow
    start_parser = subparsers.add_parser("start", help="Start a new workflow")
    start_parser.add_argument("--type", default="workflow", help="Workflow type")
    start_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # Publish event
    publish_parser = subparsers.add_parser("publish", help="Publish an event")
    publish_parser.add_argument("--workflow-id", required=True, help="Workflow ID")
    publish_parser.add_argument("--step", type=int, required=True, help="Step index")
    publish_parser.add_argument("--role", required=True, choices=["user", "assistant", "system"])
    publish_parser.add_argument("--content", required=True, help="Event content (use - for stdin)")
    publish_parser.add_argument("--type", default="workflow", help="Workflow type")
    publish_parser.add_argument("--event-type", default="request", choices=["request", "response"])
    publish_parser.add_argument("--metadata", help="JSON metadata")
    publish_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # Reconstruct context
    reconstruct_parser = subparsers.add_parser("reconstruct", help="Reconstruct context")
    reconstruct_parser.add_argument("--workflow-id", required=True, help="Workflow ID")
    reconstruct_parser.add_argument("--step", type=int, required=True, help="Current step index")
    reconstruct_parser.add_argument("--task", required=True, help="Current task description")
    reconstruct_parser.add_argument("--type", default="workflow", help="Workflow type")
    reconstruct_parser.add_argument("--ratio", type=float, help="Relevance ratio (0-1)")
    reconstruct_parser.add_argument("--json", action="store_true", help="Output JSON")
    reconstruct_parser.add_argument("--messages-only", action="store_true", help="Output only messages array")
    
    # Get history
    history_parser = subparsers.add_parser("history", help="Get workflow history")
    history_parser.add_argument("--workflow-id", required=True, help="Workflow ID")
    history_parser.add_argument("--type", default="workflow", help="Workflow type")
    history_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    # Stream status
    status_parser = subparsers.add_parser("status", help="Get stream status")
    status_parser.add_argument("--json", action="store_true", help="Output JSON")
    
    return parser


async def cmd_start(args, client: MCRClient):
    workflow_id = client.start_workflow(args.type)
    if args.json:
        print(json.dumps({"workflow_id": workflow_id, "workflow_type": args.type}))
    else:
        print(f"Workflow ID: {workflow_id}")
        print(f"Type: {args.type}")


async def cmd_publish(args, client: MCRClient):
    content = args.content
    if content == "-":
        content = sys.stdin.read()
    
    metadata = None
    if args.metadata:
        metadata = json.loads(args.metadata)
    
    seq = await client.publish_event(
        workflow_id=args.workflow_id,
        step_index=args.step,
        role=args.role,
        content=content,
        workflow_type=args.type,
        event_type=args.event_type,
        metadata=metadata,
    )
    
    if args.json:
        print(json.dumps({
            "sequence": seq,
            "workflow_id": args.workflow_id,
            "step": args.step,
            "role": args.role,
        }))
    else:
        print(f"Published: seq={seq}, workflow={args.workflow_id}, step={args.step}")


async def cmd_reconstruct(args, client: MCRClient):
    result = await client.reconstruct(
        workflow_id=args.workflow_id,
        current_step=args.step,
        current_task=args.task,
        workflow_type=args.type,
        relevance_ratio=args.ratio,
    )
    
    if args.messages_only:
        print(json.dumps(result["messages"], indent=2))
    elif args.json:
        # Convert events to serializable format
        output = {
            "messages": result["messages"],
            "stats": result["stats"],
        }
        print(json.dumps(output, indent=2))
    else:
        stats = result["stats"]
        print(f"Reconstruction for step {args.step}:")
        print(f"  Prior events: {stats['prior_events']}")
        print(f"  Prior tokens: {stats['prior_tokens']}")
        print(f"  Selected events: {stats['selected_events']}")
        print(f"  Selected tokens: {stats['selected_tokens']}")
        print(f"  Tokens eliminated: {stats['tokens_eliminated']}")
        print(f"  Actual ratio: {stats.get('actual_ratio', 'N/A')}")
        print()
        print("Messages:")
        for msg in result["messages"]:
            preview = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
            print(f"  [{msg['role']}]: {preview}")


async def cmd_history(args, client: MCRClient):
    events = await client.get_workflow_history(
        workflow_id=args.workflow_id,
        workflow_type=args.type,
    )
    
    if args.json:
        output = [{
            "step": e.step_index,
            "event_type": e.event_type,
            "role": e.role,
            "content": e.content,
            "token_count": e.token_count,
            "timestamp": e.timestamp,
        } for e in events]
        print(json.dumps(output, indent=2))
    else:
        print(f"Workflow {args.workflow_id} history ({len(events)} events):")
        for e in events:
            preview = e.content[:80] + "..." if len(e.content) > 80 else e.content
            print(f"  Step {e.step_index} [{e.event_type}/{e.role}]: {preview}")


async def cmd_status(args, client: MCRClient):
    info = await client.stream_info()
    
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print("MCR Stream Status:")
        print(f"  Messages: {info['messages']}")
        print(f"  Bytes: {info['bytes']:,}")
        print(f"  Sequence range: {info['first_seq']} - {info['last_seq']}")


async def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    async with MCRClient() as client:
        if args.command == "start":
            await cmd_start(args, client)
        elif args.command == "publish":
            await cmd_publish(args, client)
        elif args.command == "reconstruct":
            await cmd_reconstruct(args, client)
        elif args.command == "history":
            await cmd_history(args, client)
        elif args.command == "status":
            await cmd_status(args, client)
    
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
