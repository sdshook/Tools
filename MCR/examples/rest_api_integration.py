"""
rest_api_integration.py
Example: Exposing MCR via REST API for webhook integration.

This example shows how to create REST endpoints for MCR operations,
enabling integration with any system that can make HTTP requests.

Requires: pip install fastapi uvicorn
"""

import asyncio
import os
import sys
from typing import Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("FastAPI not installed. Run: pip install fastapi uvicorn")

from mcr_client import MCRClient


# ============================================================================
# API Models
# ============================================================================

if FASTAPI_AVAILABLE:
    class StartWorkflowRequest(BaseModel):
        workflow_type: str = "workflow"

    class StartWorkflowResponse(BaseModel):
        workflow_id: str
        workflow_type: str

    class PublishEventRequest(BaseModel):
        workflow_id: str
        step_index: int
        role: str  # "user" | "assistant" | "system"
        content: str
        workflow_type: str = "workflow"
        event_type: str = "request"
        metadata: Optional[dict] = None

    class PublishEventResponse(BaseModel):
        sequence: int
        workflow_id: str
        step_index: int

    class ReconstructRequest(BaseModel):
        workflow_id: str
        current_step: int
        current_task: str
        workflow_type: str = "workflow"
        relevance_ratio: Optional[float] = None

    class ReconstructResponse(BaseModel):
        messages: list[dict]
        stats: dict

    class HistoryResponse(BaseModel):
        workflow_id: str
        events: list[dict]

    class StreamStatusResponse(BaseModel):
        messages: int
        bytes: int
        first_seq: int
        last_seq: int


# ============================================================================
# FastAPI Application
# ============================================================================

def create_app() -> "FastAPI":
    if not FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not available")
    
    app = FastAPI(
        title="MCR REST API",
        description="REST API for Model Context Routing operations",
        version="1.0.0",
    )
    
    # Shared MCR client
    mcr_client: Optional[MCRClient] = None
    
    @app.on_event("startup")
    async def startup():
        nonlocal mcr_client
        mcr_client = MCRClient()
        await mcr_client.connect()
    
    @app.on_event("shutdown")
    async def shutdown():
        if mcr_client:
            await mcr_client.close()
    
    @app.post("/workflows", response_model=StartWorkflowResponse)
    async def start_workflow(request: StartWorkflowRequest):
        """Start a new workflow and return correlation ID."""
        workflow_id = mcr_client.start_workflow(request.workflow_type)
        return StartWorkflowResponse(
            workflow_id=workflow_id,
            workflow_type=request.workflow_type,
        )
    
    @app.post("/events", response_model=PublishEventResponse)
    async def publish_event(request: PublishEventRequest):
        """Publish an event to the MCR context plane."""
        seq = await mcr_client.publish_event(
            workflow_id=request.workflow_id,
            step_index=request.step_index,
            role=request.role,
            content=request.content,
            workflow_type=request.workflow_type,
            event_type=request.event_type,
            metadata=request.metadata,
        )
        return PublishEventResponse(
            sequence=seq,
            workflow_id=request.workflow_id,
            step_index=request.step_index,
        )
    
    @app.post("/reconstruct", response_model=ReconstructResponse)
    async def reconstruct_context(request: ReconstructRequest):
        """Reconstruct context for a workflow step."""
        result = await mcr_client.reconstruct(
            workflow_id=request.workflow_id,
            current_step=request.current_step,
            current_task=request.current_task,
            workflow_type=request.workflow_type,
            relevance_ratio=request.relevance_ratio,
        )
        return ReconstructResponse(
            messages=result["messages"],
            stats=result["stats"],
        )
    
    @app.get("/workflows/{workflow_id}/history", response_model=HistoryResponse)
    async def get_history(workflow_id: str, workflow_type: str = "workflow"):
        """Get complete workflow history for audit."""
        events = await mcr_client.get_workflow_history(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
        )
        return HistoryResponse(
            workflow_id=workflow_id,
            events=[{
                "step_index": e.step_index,
                "event_type": e.event_type,
                "role": e.role,
                "content": e.content,
                "token_count": e.token_count,
                "timestamp": e.timestamp,
            } for e in events],
        )
    
    @app.get("/status", response_model=StreamStatusResponse)
    async def get_status():
        """Get JetStream status."""
        info = await mcr_client.stream_info()
        return StreamStatusResponse(**info)
    
    return app


# ============================================================================
# Example Usage
# ============================================================================

EXAMPLE_CURL_COMMANDS = """
# Start a workflow
curl -X POST http://localhost:8000/workflows \\
  -H "Content-Type: application/json" \\
  -d '{"workflow_type": "incident"}'

# Publish a user request
curl -X POST http://localhost:8000/events \\
  -H "Content-Type: application/json" \\
  -d '{
    "workflow_id": "YOUR_WORKFLOW_ID",
    "step_index": 0,
    "role": "user",
    "content": "Analyze security alert for host 10.4.22.107",
    "workflow_type": "incident",
    "event_type": "request"
  }'

# Publish assistant response
curl -X POST http://localhost:8000/events \\
  -H "Content-Type: application/json" \\
  -d '{
    "workflow_id": "YOUR_WORKFLOW_ID",
    "step_index": 0,
    "role": "assistant",
    "content": "Severity: HIGH. Recommend immediate host isolation.",
    "workflow_type": "incident",
    "event_type": "response"
  }'

# Reconstruct context for next step
curl -X POST http://localhost:8000/reconstruct \\
  -H "Content-Type: application/json" \\
  -d '{
    "workflow_id": "YOUR_WORKFLOW_ID",
    "current_step": 1,
    "current_task": "Correlate with threat intelligence",
    "workflow_type": "incident"
  }'

# Get workflow history
curl http://localhost:8000/workflows/YOUR_WORKFLOW_ID/history?workflow_type=incident

# Get stream status
curl http://localhost:8000/status
"""


def print_usage():
    print("MCR REST API Server")
    print("=" * 50)
    print()
    print("Start the server:")
    print("  python rest_api_integration.py")
    print()
    print("Or with uvicorn directly:")
    print("  uvicorn rest_api_integration:app --reload")
    print()
    print("Example curl commands:")
    print(EXAMPLE_CURL_COMMANDS)


if FASTAPI_AVAILABLE:
    app = create_app()

if __name__ == "__main__":
    if not FASTAPI_AVAILABLE:
        print("FastAPI not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)
    
    print_usage()
    print("\nStarting server on http://localhost:8000")
    print("API docs at http://localhost:8000/docs")
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
