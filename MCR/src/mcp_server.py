"""
mcp_server.py
Minimal MCP server implementing JSON-RPC 2.0 over asyncio stdio.
Exposes two tools: process_workflow_step and get_stream_status.

Note on transport: run_stdio() implements the full stdin/stdout pipe
transport for production use. The POC runner calls handle() in-process
to demonstrate the JSON-RPC message structure without subprocess overhead.
For a fully external MCP deployment, invoke this module as a subprocess
and wire stdio through the MCPClient's transport layer.
"""

import asyncio
import json
import sys
from typing import Any


def mcp_response(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}

def mcp_error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


TOOLS = [
    {
        "name": "process_workflow_step",
        "description": (
            "Route a workflow step through the MCR context plane. "
            "Publishes the request to NATS, selects a model provider via routing policy, "
            "reconstructs semantically relevant prior context from JetStream, "
            "and executes the AI task."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "correlation_id": {
                    "type": "string",
                    "description": "Workflow correlation identifier (UUID)"
                },
                "step_index": {
                    "type": "integer",
                    "description": "Zero-based step index within the workflow"
                },
                "task": {
                    "type": "string",
                    "description": "Task description for this workflow step"
                },
                "workflow_type": {
                    "type": "string",
                    "description": "Workflow classification (e.g., incident, credit, support)"
                },
                "step_type": {
                    "type": "string",
                    "description": (
                        "Step function label used to select the routing policy "
                        "(e.g., triage, correlation, intelligence, lateral_movement, remediation)"
                    )
                },
                "min_capability": {
                    "type": "string",
                    "enum": ["basic", "reasoning", "advanced"],
                    "description": "Minimum model capability tier required for this step"
                },
                "max_latency_ms": {
                    "type": "integer",
                    "description": "Maximum acceptable end-to-end latency in milliseconds"
                },
                "max_cost_per_mtok": {
                    "type": "number",
                    "description": "Maximum model input cost in USD per million tokens"
                },
                "data_class": {
                    "type": "string",
                    "enum": ["internal", "confidential"],
                    "description": "Data classification for compliance-based provider routing"
                },
            },
            "required": [
                "correlation_id", "step_index", "task",
                "workflow_type", "step_type",
                "min_capability", "max_latency_ms",
                "max_cost_per_mtok", "data_class",
            ],
        },
    },
    {
        "name": "get_stream_status",
        "description": "Return current JetStream stream statistics.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


class MCPServer:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.initialized  = False

    async def handle(self, message: dict) -> dict | None:
        method = message.get("method", "")
        req_id = message.get("id")

        if method == "initialize":
            self.initialized = True
            return mcp_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities":    {"tools": {}},
                "serverInfo":      {"name": "mcr-poc-server", "version": "0.2.0"},
            })

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return mcp_response(req_id, {"tools": TOOLS})

        if method == "tools/call":
            params    = message.get("params", {})
            tool_name = params.get("name")
            args      = params.get("arguments", {})
            result    = await self._dispatch(tool_name, args)
            return mcp_response(req_id, {
                "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": False,
            })

        if method == "ping":
            return mcp_response(req_id, {})

        return mcp_error(req_id, -32601, f"Method not found: {method}")

    async def _dispatch(self, name: str, args: dict) -> dict:
        if name == "process_workflow_step":
            from mcr_orchestrator import RoutingPolicy
            policy = RoutingPolicy(
                step_type         = args["step_type"],
                min_capability    = args["min_capability"],
                max_latency_ms    = args["max_latency_ms"],
                max_cost_per_mtok = args["max_cost_per_mtok"],
                data_class        = args["data_class"],
            )
            return await self.orchestrator.process_step_via_mcr(
                correlation_id = args["correlation_id"],
                step_index     = args["step_index"],
                task           = args["task"],
                workflow_type  = args["workflow_type"],
                routing_policy = policy,
            )
        if name == "get_stream_status":
            return await self.orchestrator.context_plane.stream_info()
        return {"error": f"Unknown tool: {name}"}

    async def run_stdio(self):
        """
        Production stdio transport. In the POC, handle() is called
        in-process; for a subprocess MCP deployment, invoke this instead.
        """
        reader = asyncio.StreamReader()
        proto  = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: proto, sys.stdin)
        _, writer = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.BaseProtocol, sys.stdout.buffer
        )
        async def send(obj: dict):
            writer.write((json.dumps(obj) + "\n").encode())
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                msg      = json.loads(line.decode().strip())
                response = await self.handle(msg)
                if response is not None:
                    await send(response)
            except (json.JSONDecodeError, EOFError):
                break
