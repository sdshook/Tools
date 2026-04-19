"""
mcp_integration.py
Example: Integrating MCR with an existing MCP server.

This example shows how to add MCR context persistence to any MCP server.
The pattern works with any MCP implementation (Python, TypeScript, etc.).

The key insight: MCR is not a replacement for MCP. It's an infrastructure
layer that MCP tools can publish to and reconstruct from.
"""

import asyncio
import json
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from mcr_client import MCRClient


class MCREnhancedMCPServer:
    """
    Example MCP server enhanced with MCR context persistence.
    
    This wraps your existing MCP server and adds:
    1. Automatic event publishing for all tool calls
    2. Context reconstruction before LLM calls
    3. Workflow correlation tracking
    """
    
    def __init__(self, your_existing_server=None):
        self.server = your_existing_server
        self.mcr = MCRClient()
        self.active_workflows = {}  # correlation_id -> workflow state
    
    async def start(self):
        """Initialize MCR connection."""
        await self.mcr.connect()
    
    async def stop(self):
        """Close MCR connection."""
        await self.mcr.close()
    
    async def handle_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        correlation_id: str,
        step_index: int,
    ) -> dict:
        """
        Handle a tool call with MCR context persistence.
        
        This method:
        1. Publishes the request to MCR
        2. Reconstructs relevant prior context
        3. Calls your existing tool implementation
        4. Publishes the response to MCR
        """
        # Get or create workflow
        if correlation_id not in self.active_workflows:
            self.active_workflows[correlation_id] = {
                "type": "mcp_workflow",
                "step_count": 0,
            }
        
        workflow = self.active_workflows[correlation_id]
        workflow_type = workflow["type"]
        
        # Build request content
        request_content = json.dumps({
            "tool": tool_name,
            "arguments": arguments,
        })
        
        # 1. Publish request to MCR
        await self.mcr.publish_event(
            workflow_id=correlation_id,
            step_index=step_index,
            role="user",
            content=request_content,
            workflow_type=workflow_type,
            event_type="request",
        )
        
        # 2. Reconstruct context (for tools that need prior context)
        context = await self.mcr.reconstruct(
            workflow_id=correlation_id,
            current_step=step_index,
            current_task=request_content,
            workflow_type=workflow_type,
        )
        
        # 3. Call your existing tool with context
        # Pass reconstructed context to tools that need it
        if self.server:
            result = await self.server.call_tool(
                tool_name,
                arguments,
                prior_context=context["messages"],
            )
        else:
            # Demo mode: return mock result
            result = {"status": "ok", "tool": tool_name, "context_events": len(context["messages"])}
        
        # 4. Publish response to MCR
        response_content = json.dumps(result)
        await self.mcr.publish_event(
            workflow_id=correlation_id,
            step_index=step_index,
            role="assistant",
            content=response_content,
            workflow_type=workflow_type,
            event_type="response",
        )
        
        workflow["step_count"] += 1
        
        return result
    
    async def get_context_for_llm(
        self,
        correlation_id: str,
        current_task: str,
        workflow_type: str = "mcp_workflow",
    ) -> list[dict]:
        """
        Get reconstructed context for an LLM call.
        
        Use this when your MCP server needs to make an LLM call
        and wants to include relevant prior context.
        """
        workflow = self.active_workflows.get(correlation_id, {"step_count": 0})
        
        context = await self.mcr.reconstruct(
            workflow_id=correlation_id,
            current_step=workflow["step_count"],
            current_task=current_task,
            workflow_type=workflow_type,
        )
        
        return context["messages"]


async def example_mcp_with_mcr():
    """
    Demonstrate MCR-enhanced MCP server.
    """
    print("MCR-Enhanced MCP Server Example")
    print("=" * 50)
    
    server = MCREnhancedMCPServer()
    await server.start()
    
    # Simulate a workflow
    workflow_id = server.mcr.start_workflow("mcp_workflow")
    print(f"Started workflow: {workflow_id}")
    
    # Step 0: First tool call
    result = await server.handle_tool_call(
        tool_name="analyze_alert",
        arguments={"host": "10.4.22.107", "alert_type": "outbound_traffic"},
        correlation_id=workflow_id,
        step_index=0,
    )
    print(f"Step 0 result: {result}")
    
    # Step 1: Second tool call (MCR provides context from step 0)
    result = await server.handle_tool_call(
        tool_name="correlate_intel",
        arguments={"ip": "185.220.101.45"},
        correlation_id=workflow_id,
        step_index=1,
    )
    print(f"Step 1 result: {result}")
    
    # Get context for an LLM call
    context = await server.get_context_for_llm(
        correlation_id=workflow_id,
        current_task="Summarize the incident",
    )
    print(f"Context for LLM: {len(context)} messages")
    
    # Get stream stats
    stats = await server.mcr.stream_info()
    print(f"Stream stats: {stats}")
    
    await server.stop()
    print("Done!")


if __name__ == "__main__":
    asyncio.run(example_mcp_with_mcr())
