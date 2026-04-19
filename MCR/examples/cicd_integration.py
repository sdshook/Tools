"""
cicd_integration.py
Example: Using MCR in CI/CD pipelines.

This example shows how to integrate MCR into CI/CD workflows for:
- Multi-stage analysis pipelines
- Incremental code review
- Security scanning with context
- Test failure analysis

The key benefit: Each CI job can access relevant context from prior jobs
without re-processing everything.
"""

import asyncio
import json
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcr_client import MCRClient


async def cicd_pipeline_example():
    """
    Example: Multi-stage CI/CD pipeline with MCR context.
    
    Simulates a pipeline with:
    1. Code analysis
    2. Security scan
    3. Test execution
    4. Final summary (with context from all prior stages)
    """
    print("CI/CD Pipeline with MCR Context")
    print("=" * 50)
    
    # In real CI/CD, use pipeline ID as workflow ID
    pipeline_id = os.getenv("CI_PIPELINE_ID", "demo-pipeline-123")
    
    async with MCRClient() as mcr:
        # Stage 0: Code Analysis
        print("\n[Stage 0] Code Analysis")
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=0,
            role="user",
            content="Analyze code changes in PR #456: Modified auth.py, added rate limiting",
            workflow_type="ci",
            metadata={"stage": "code_analysis", "pr": 456},
        )
        
        # Simulate analysis result
        analysis_result = {
            "files_changed": 3,
            "lines_added": 127,
            "lines_removed": 45,
            "complexity_delta": "+2",
            "findings": ["New function lacks docstring", "Consider edge case handling"],
        }
        
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=0,
            role="assistant",
            content=json.dumps(analysis_result),
            workflow_type="ci",
            event_type="response",
        )
        print(f"  Published: {analysis_result}")
        
        # Stage 1: Security Scan
        print("\n[Stage 1] Security Scan")
        
        # Reconstruct context from prior stages
        context = await mcr.reconstruct(
            workflow_id=pipeline_id,
            current_step=1,
            current_task="Security scan for auth.py changes",
            workflow_type="ci",
        )
        print(f"  Context from prior stages: {context['stats']['selected_events']} events")
        
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=1,
            role="user",
            content="Run security scan on modified files, focusing on auth changes",
            workflow_type="ci",
            metadata={"stage": "security_scan"},
        )
        
        security_result = {
            "vulnerabilities": [],
            "warnings": ["Rate limit may be bypassable via header manipulation"],
            "passed": True,
        }
        
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=1,
            role="assistant",
            content=json.dumps(security_result),
            workflow_type="ci",
            event_type="response",
        )
        print(f"  Published: {security_result}")
        
        # Stage 2: Test Execution
        print("\n[Stage 2] Test Execution")
        
        context = await mcr.reconstruct(
            workflow_id=pipeline_id,
            current_step=2,
            current_task="Run test suite for auth module",
            workflow_type="ci",
        )
        print(f"  Context from prior stages: {context['stats']['selected_events']} events")
        
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=2,
            role="user",
            content="Execute test suite for auth module with new rate limiting",
            workflow_type="ci",
            metadata={"stage": "test_execution"},
        )
        
        test_result = {
            "total": 47,
            "passed": 45,
            "failed": 2,
            "failures": [
                "test_rate_limit_concurrent: timeout exceeded",
                "test_auth_header_validation: assertion failed",
            ],
        }
        
        await mcr.publish_event(
            workflow_id=pipeline_id,
            step_index=2,
            role="assistant",
            content=json.dumps(test_result),
            workflow_type="ci",
            event_type="response",
        )
        print(f"  Published: {test_result}")
        
        # Stage 3: Final Summary
        print("\n[Stage 3] Final Summary")
        
        # Full context reconstruction for summary
        context = await mcr.reconstruct(
            workflow_id=pipeline_id,
            current_step=3,
            current_task="Generate pipeline summary with all findings",
            workflow_type="ci",
        )
        
        print(f"  Prior context: {context['stats']['prior_events']} events, "
              f"{context['stats']['prior_tokens']} tokens")
        print(f"  Selected: {context['stats']['selected_events']} events, "
              f"{context['stats']['selected_tokens']} tokens")
        print(f"  Tokens eliminated: {context['stats']['tokens_eliminated']}")
        
        # In real pipeline, send context to LLM for summary
        print("\n  Context messages for LLM summary:")
        for msg in context["messages"]:
            preview = msg["content"][:60] + "..." if len(msg["content"]) > 60 else msg["content"]
            print(f"    [{msg['role']}]: {preview}")
        
        # Get full history for audit
        print("\n[Audit] Full Pipeline History")
        history = await mcr.get_workflow_history(pipeline_id, "ci")
        print(f"  Total events: {len(history)}")
        for event in history:
            print(f"    Step {event.step_index} [{event.event_type}]: "
                  f"{event.content[:50]}...")
        
        # Stream stats
        stats = await mcr.stream_info()
        print(f"\n[Stream] JetStream status: {stats['messages']} messages, "
              f"{stats['bytes']:,} bytes")


async def github_actions_example():
    """
    Example: GitHub Actions integration.
    
    In your workflow YAML:
    
    jobs:
      analyze:
        steps:
          - name: Publish analysis to MCR
            run: |
              mcr publish \\
                --workflow-id ${{ github.run_id }} \\
                --step 0 \\
                --role user \\
                --content "$(cat analysis.json)" \\
                --type ci
      
      security:
        needs: analyze
        steps:
          - name: Get context from prior jobs
            run: |
              mcr reconstruct \\
                --workflow-id ${{ github.run_id }} \\
                --step 1 \\
                --task "Security scan" \\
                --type ci \\
                --messages-only > context.json
          
          - name: Run security scan with context
            run: |
              # Use context.json with your security tool
              security-scan --context context.json
    """
    print("\nGitHub Actions Integration Pattern")
    print("=" * 50)
    print(__doc__)


if __name__ == "__main__":
    asyncio.run(cicd_pipeline_example())
    asyncio.run(github_actions_example())
