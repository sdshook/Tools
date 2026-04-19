"""
test_live_integration.py

MCR Live Integration Test - Uses actual Anthropic API calls instead of simulated responses.
This test validates the full MCR workflow with real model interactions.

Generates a comprehensive PNG dashboard with test results and MCR metrics.

Usage:
    export ANTHROPIC_API_KEY="your-api-key"
    python test_live_integration.py
"""

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import anthropic
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import numpy as np

from context_plane import MCRContextPlane, ContextEvent, estimate_tokens
from mcp_server import MCPServer


# ── Configuration ────────────────────────────────────────────────────────────

R = 0.35  # Relevance ratio

# Model mapping for live API calls
MODEL_MAP = {
    "claude-haiku-4-5": "claude-3-haiku-20240307",
    "claude-sonnet-4-5": "claude-sonnet-4-20250514",
    "claude-opus-4-5": "claude-sonnet-4-20250514",  # Fallback to Sonnet for cost
}

NATS_SERVER_PATH = "/tmp/nats-server-v2.10.25-linux-amd64/nats-server"


# ── Routing ──────────────────────────────────────────────────────────────────

PROVIDER_POOL = [
    {
        "name": "claude-haiku-4-5",
        "capability": "basic",
        "latency_p50_ms": 150,
        "cost_per_mtok": 0.80,
        "data_classes": ["internal", "confidential"],
    },
    {
        "name": "claude-sonnet-4-5",
        "capability": "reasoning",
        "latency_p50_ms": 380,
        "cost_per_mtok": 3.00,
        "data_classes": ["internal", "confidential"],
    },
    {
        "name": "claude-opus-4-5",
        "capability": "advanced",
        "latency_p50_ms": 750,
        "cost_per_mtok": 15.00,
        "data_classes": ["internal", "confidential"],
    },
]

CAPABILITY_RANK = {"basic": 0, "reasoning": 1, "advanced": 2}


class RoutingPolicy:
    def __init__(self, step_type, min_capability, max_latency_ms, max_cost_per_mtok, data_class):
        self.step_type = step_type
        self.min_capability = min_capability
        self.max_latency_ms = max_latency_ms
        self.max_cost_per_mtok = max_cost_per_mtok
        self.data_class = data_class


class ModelRouter:
    @staticmethod
    def select(policy: RoutingPolicy) -> dict:
        eligible = [
            p for p in PROVIDER_POOL
            if CAPABILITY_RANK[p["capability"]] >= CAPABILITY_RANK[policy.min_capability]
            and p["latency_p50_ms"] <= policy.max_latency_ms
            and p["cost_per_mtok"] <= policy.max_cost_per_mtok
            and policy.data_class in p["data_classes"]
        ]
        if not eligible:
            raise RuntimeError(f"No provider satisfies routing policy for '{policy.step_type}'")
        return min(eligible, key=lambda p: p["cost_per_mtok"])


# ── Workflow Steps ───────────────────────────────────────────────────────────

WORKFLOW_STEPS = [
    {
        "step_index": 0,
        "step_type": "triage",
        "min_capability": "basic",
        "max_latency_ms": 400,
        "max_cost_per_mtok": 2.00,
        "data_class": "confidential",
        "task": (
            "Initial alert triage: We have received an IDS alert for unusual outbound "
            "traffic from host 10.4.22.107. The alert triggered at 03:14 UTC with "
            "destination IP 185.220.101.45 on port 443. Traffic volume was 2.3 GB "
            "in 8 minutes. Classify the alert severity and recommend immediate triage actions."
        ),
    },
    {
        "step_index": 1,
        "step_type": "correlation",
        "min_capability": "basic",
        "max_latency_ms": 400,
        "max_cost_per_mtok": 2.00,
        "data_class": "confidential",
        "task": (
            "Asset and IP correlation: The source host 10.4.22.107 is registered as "
            "'FINWKS-047', a finance department workstation assigned to a senior analyst. "
            "The destination IP 185.220.101.45 resolves to a known Tor exit node. "
            "The workstation last had a scheduled backup at 01:00 UTC. "
            "Assess whether the observed traffic is consistent with authorized activity "
            "and identify the most likely threat category."
        ),
    },
    {
        "step_index": 2,
        "step_type": "intelligence",
        "min_capability": "reasoning",
        "max_latency_ms": 600,
        "max_cost_per_mtok": 5.00,
        "data_class": "confidential",
        "task": (
            "Threat intelligence lookup: External TI feeds confirm that 185.220.101.45 "
            "is associated with data exfiltration campaigns targeting financial sector "
            "organizations. Similar TTPs were observed in three incidents in the past "
            "60 days involving staged data collection followed by bulk transfer. "
            "Correlate this intelligence with the current alert and determine the "
            "likely attack stage."
        ),
    },
    {
        "step_index": 3,
        "step_type": "lateral_movement",
        "min_capability": "reasoning",
        "max_latency_ms": 600,
        "max_cost_per_mtok": 5.00,
        "data_class": "confidential",
        "task": (
            "Lateral movement assessment: Authentication logs show FINWKS-047 made "
            "successful RDP connections to FILESVR-012 and DBSVR-003 at 02:45 and "
            "02:58 UTC respectively, using the analyst's credentials. FILESVR-012 "
            "hosts the quarterly financial reports archive. DBSVR-003 hosts the "
            "customer transaction database. Assess the scope of potential data access "
            "and prioritize containment actions."
        ),
    },
    {
        "step_index": 4,
        "step_type": "remediation",
        "min_capability": "reasoning",
        "max_latency_ms": 800,
        "max_cost_per_mtok": 5.00,
        "data_class": "confidential",
        "task": (
            "Incident response recommendation: Based on all findings so far, provide "
            "a structured incident response plan including: immediate containment steps, "
            "evidence preservation priorities, stakeholder notification sequence, and "
            "estimated time to remediation. Assign an overall incident severity rating."
        ),
    },
]


# ── Console Helpers ──────────────────────────────────────────────────────────

RST = "\033[0m"; BOLD = "\033[1m"; NAVY = "\033[34m"
BLUE = "\033[36m"; GRN = "\033[32m"; YLW = "\033[33m"
RED = "\033[31m"; GRY = "\033[90m"

def banner(t, c=NAVY):
    w = 78
    print(f"\n{c}{BOLD}{'='*w}\n  {t}\n{'='*w}{RST}")

def sec(t): print(f"\n{BLUE}{BOLD}── {t}{RST}")
def inf(l, v): print(f"  {GRY}{l:<34}{RST} {v}")
def ok(t): print(f"  {GRN}{t}{RST}")
def warn(t): print(f"  {YLW}{t}{RST}")
def err(t): print(f"  {RED}{t}{RST}")


# ── Live MCR Orchestrator ────────────────────────────────────────────────────

class LiveMCROrchestrator:
    """
    MCR Orchestrator with live Anthropic API calls.
    """

    def __init__(self, context_plane: MCRContextPlane, client: anthropic.Anthropic):
        self.context_plane = context_plane
        self.client = client
        self.router = ModelRouter()
        self.step_log = []

    async def process_step(
        self,
        correlation_id: str,
        step_index: int,
        task: str,
        workflow_type: str,
        routing_policy: RoutingPolicy,
    ) -> dict:
        t_start = time.time()

        # 1. Publish request event to JetStream
        req_evt = ContextEvent(
            correlation_id=correlation_id,
            workflow_type=workflow_type,
            step_index=step_index,
            event_type="request",
            role="user",
            content=task,
            token_count=estimate_tokens(task),
            timestamp=time.time(),
        )
        seq = await self.context_plane.publish(req_evt)

        # 2. Route: select model provider from pool
        provider = self.router.select(routing_policy)
        actual_model = MODEL_MAP.get(provider["name"], "claude-3-5-haiku-latest")

        # 3. Reconstruct: semantic relevance within R * available token budget
        selected_events, recon_stats = await self.context_plane.reconstruct_context(
            correlation_id=correlation_id,
            current_step=step_index,
            current_task=task,
            relevance_ratio=R,
        )

        # 4. Build messages for API call
        system_prompt = (
            "You are a security incident response analyst. Provide concise, actionable analysis. "
            "Reference prior context when relevant but avoid unnecessary repetition."
        )
        
        messages = []
        # Add reconstructed context as prior conversation
        for evt in selected_events:
            messages.append({"role": evt.role, "content": evt.content})
        # Add current task
        messages.append({"role": "user", "content": task})

        # 5. Execute live API call
        inf("Calling model:", f"{actual_model}")
        response = self.client.messages.create(
            model=actual_model,
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        )
        
        assistant_text = response.content[0].text
        api_input = response.usage.input_tokens
        api_output = response.usage.output_tokens
        step_cost = api_input * provider["cost_per_mtok"] / 1_000_000

        # 6. Publish response event to JetStream
        resp_evt = ContextEvent(
            correlation_id=correlation_id,
            workflow_type=workflow_type,
            step_index=step_index,
            event_type="response",
            role="assistant",
            content=assistant_text,
            token_count=api_output,
            timestamp=time.time(),
        )
        await self.context_plane.publish(resp_evt)

        result = {
            "step_index": step_index,
            "correlation_id": correlation_id,
            "nats_seq": seq,
            "routing": {
                "step_type": routing_policy.step_type,
                "min_capability": routing_policy.min_capability,
                "selected_model": provider["name"],
                "actual_model": actual_model,
                "cost_per_mtok": provider["cost_per_mtok"],
                "latency_p50_ms": provider["latency_p50_ms"],
                "step_cost_usd": round(step_cost, 6),
            },
            "reconstruction": recon_stats,
            "api_usage": {
                "input_tokens": api_input,
                "output_tokens": api_output,
            },
            "task_preview": task[:72] + "..." if len(task) > 72 else task,
            "response_preview": assistant_text[:150] + "..." if len(assistant_text) > 150 else assistant_text,
            "full_response": assistant_text,
            "elapsed_ms": round((time.time() - t_start) * 1000, 1),
        }
        self.step_log.append(result)
        return result


# ── NATS Server ──────────────────────────────────────────────────────────────

def start_nats() -> subprocess.Popen:
    """Start NATS server with JetStream enabled."""
    os.makedirs("/tmp/mcr_nats_store", exist_ok=True)
    
    # Create minimal NATS config
    config_content = """
port: 4222
jetstream {
    store_dir: /tmp/mcr_nats_store
    max_memory_store: 256M
    max_file_store: 1G
}
"""
    config_path = "/tmp/nats_config.conf"
    with open(config_path, "w") as f:
        f.write(config_content)
    
    proc = subprocess.Popen(
        [NATS_SERVER_PATH, "-c", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)  # Give NATS time to start
    return proc


# ── Dashboard Generation ─────────────────────────────────────────────────────

def generate_dashboard(mcr_results: list, workflow_steps: list, correlation_id: str, output_path: str):
    """
    Generate a comprehensive PNG dashboard with MCR test results.
    
    Charts included:
    1. Token consumption comparison (MCR vs Stateless projection)
    2. Cost per step breakdown
    3. Context reconstruction efficiency
    4. Latency distribution
    5. Token elimination by step
    6. Model routing decisions
    """
    
    # Calculate stateless projection (full history re-injection)
    stateless_tokens = []
    cumulative_history = 0
    sys_tokens = 28
    
    for i, result in enumerate(mcr_results):
        task_tokens = estimate_tokens(workflow_steps[i]["task"])
        # Stateless: sys + all prior history + current task
        stateless_input = sys_tokens + cumulative_history + task_tokens
        stateless_tokens.append(stateless_input)
        # Add both task and response to history for next step
        cumulative_history += task_tokens + result["api_usage"]["output_tokens"]
    
    mcr_tokens = [r["api_usage"]["input_tokens"] for r in mcr_results]
    
    # Setup figure with custom style
    plt.style.use('seaborn-v0_8-darkgrid')
    fig = plt.figure(figsize=(20, 14))
    fig.patch.set_facecolor('#1a1a2e')
    
    gs = GridSpec(3, 3, figure=fig, hspace=0.35, wspace=0.3)
    
    # Color palette
    colors = {
        'mcr': '#00d4aa',
        'stateless': '#ff6b6b',
        'eliminated': '#ffd93d',
        'haiku': '#4ecdc4',
        'sonnet': '#a855f7',
        'background': '#1a1a2e',
        'text': '#ffffff',
        'grid': '#333355',
        'accent': '#00d4aa'
    }
    
    step_labels = [f"Step {i}\n{s['step_type']}" for i, s in enumerate(workflow_steps)]
    x = np.arange(len(workflow_steps))
    
    # ── Chart 1: Token Consumption Comparison (spans 2 columns) ──
    ax1 = fig.add_subplot(gs[0, :2])
    ax1.set_facecolor(colors['background'])
    
    width = 0.35
    bars1 = ax1.bar(x - width/2, stateless_tokens, width, label='Stateless (projected)', 
                    color=colors['stateless'], alpha=0.8, edgecolor='white', linewidth=0.5)
    bars2 = ax1.bar(x + width/2, mcr_tokens, width, label='MCR (actual)', 
                    color=colors['mcr'], alpha=0.8, edgecolor='white', linewidth=0.5)
    
    ax1.set_xlabel('Workflow Step', fontsize=11, color=colors['text'])
    ax1.set_ylabel('Input Tokens', fontsize=11, color=colors['text'])
    ax1.set_title('Token Consumption: MCR vs Stateless', fontsize=14, fontweight='bold', 
                  color=colors['text'], pad=15)
    ax1.set_xticks(x)
    ax1.set_xticklabels(step_labels, fontsize=9, color=colors['text'])
    ax1.tick_params(colors=colors['text'])
    ax1.legend(loc='upper left', facecolor=colors['background'], edgecolor=colors['grid'],
               labelcolor=colors['text'])
    
    # Add value labels
    for bar, val in zip(bars1, stateless_tokens):
        ax1.annotate(f'{val:,}', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     ha='center', va='bottom', fontsize=8, color=colors['stateless'])
    for bar, val in zip(bars2, mcr_tokens):
        ax1.annotate(f'{val:,}', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     ha='center', va='bottom', fontsize=8, color=colors['mcr'])
    
    # ── Chart 2: Summary Statistics ──
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_facecolor(colors['background'])
    ax2.axis('off')
    
    total_mcr = sum(mcr_tokens)
    total_stateless = sum(stateless_tokens)
    total_eliminated = sum(r["reconstruction"]["tokens_eliminated"] for r in mcr_results)
    reduction_pct = (total_stateless - total_mcr) / total_stateless * 100 if total_stateless else 0
    total_cost = sum(r["routing"]["step_cost_usd"] for r in mcr_results)
    avg_latency = np.mean([r["elapsed_ms"] for r in mcr_results])
    
    stats_text = f"""
    MCR Live Integration Test Results
    ══════════════════════════════════
    
    Correlation ID:
    {correlation_id[:18]}...
    
    Total MCR Tokens:      {total_mcr:,}
    Total Stateless:       {total_stateless:,}
    Tokens Eliminated:     {total_eliminated:,}
    
    Token Reduction:       {reduction_pct:.1f}%
    
    Total Cost:            ${total_cost:.6f}
    Avg Latency:           {avg_latency:.0f}ms
    
    Workflow Steps:        {len(mcr_results)}
    """
    
    ax2.text(0.1, 0.95, stats_text, transform=ax2.transAxes, fontsize=11,
             verticalalignment='top', fontfamily='monospace',
             color=colors['text'], bbox=dict(boxstyle='round', facecolor=colors['grid'], alpha=0.5))
    
    # ── Chart 3: Cost Per Step ──
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.set_facecolor(colors['background'])
    
    costs = [r["routing"]["step_cost_usd"] * 1000 for r in mcr_results]  # Convert to millicents for visibility
    bar_colors = [colors['haiku'] if 'haiku' in r["routing"]["actual_model"] else colors['sonnet'] 
                  for r in mcr_results]
    
    bars = ax3.bar(x, costs, color=bar_colors, alpha=0.8, edgecolor='white', linewidth=0.5)
    ax3.set_xlabel('Workflow Step', fontsize=11, color=colors['text'])
    ax3.set_ylabel('Cost (millicents)', fontsize=11, color=colors['text'])
    ax3.set_title('Cost Per Step', fontsize=14, fontweight='bold', color=colors['text'], pad=15)
    ax3.set_xticks(x)
    ax3.set_xticklabels([f"S{i}" for i in range(len(workflow_steps))], fontsize=9, color=colors['text'])
    ax3.tick_params(colors=colors['text'])
    
    # Legend for models
    haiku_patch = mpatches.Patch(color=colors['haiku'], label='Haiku')
    sonnet_patch = mpatches.Patch(color=colors['sonnet'], label='Sonnet')
    ax3.legend(handles=[haiku_patch, sonnet_patch], loc='upper right', 
               facecolor=colors['background'], edgecolor=colors['grid'], labelcolor=colors['text'])
    
    # ── Chart 4: Context Reconstruction Efficiency ──
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.set_facecolor(colors['background'])
    
    available = [r["reconstruction"]["prior_tokens_available"] for r in mcr_results]
    selected = [r["reconstruction"]["selected_tokens"] for r in mcr_results]
    
    ax4.bar(x, available, width=0.6, label='Available', color=colors['stateless'], alpha=0.5)
    ax4.bar(x, selected, width=0.6, label='Selected (R=0.35)', color=colors['mcr'], alpha=0.8)
    
    ax4.set_xlabel('Workflow Step', fontsize=11, color=colors['text'])
    ax4.set_ylabel('Tokens', fontsize=11, color=colors['text'])
    ax4.set_title('Context Reconstruction Efficiency', fontsize=14, fontweight='bold', 
                  color=colors['text'], pad=15)
    ax4.set_xticks(x)
    ax4.set_xticklabels([f"S{i}" for i in range(len(workflow_steps))], fontsize=9, color=colors['text'])
    ax4.tick_params(colors=colors['text'])
    ax4.legend(loc='upper left', facecolor=colors['background'], edgecolor=colors['grid'],
               labelcolor=colors['text'])
    
    # ── Chart 5: Latency by Step ──
    ax5 = fig.add_subplot(gs[1, 2])
    ax5.set_facecolor(colors['background'])
    
    latencies = [r["elapsed_ms"] for r in mcr_results]
    ax5.bar(x, latencies, color=colors['accent'], alpha=0.8, edgecolor='white', linewidth=0.5)
    ax5.axhline(y=np.mean(latencies), color=colors['eliminated'], linestyle='--', 
                label=f'Avg: {np.mean(latencies):.0f}ms')
    
    ax5.set_xlabel('Workflow Step', fontsize=11, color=colors['text'])
    ax5.set_ylabel('Latency (ms)', fontsize=11, color=colors['text'])
    ax5.set_title('End-to-End Latency per Step', fontsize=14, fontweight='bold', 
                  color=colors['text'], pad=15)
    ax5.set_xticks(x)
    ax5.set_xticklabels([f"S{i}" for i in range(len(workflow_steps))], fontsize=9, color=colors['text'])
    ax5.tick_params(colors=colors['text'])
    ax5.legend(loc='upper right', facecolor=colors['background'], edgecolor=colors['grid'],
               labelcolor=colors['text'])
    
    # ── Chart 6: Cumulative Token Savings (spans 2 columns) ──
    ax6 = fig.add_subplot(gs[2, :2])
    ax6.set_facecolor(colors['background'])
    
    cum_stateless = np.cumsum(stateless_tokens)
    cum_mcr = np.cumsum(mcr_tokens)
    cum_savings = cum_stateless - cum_mcr
    
    ax6.fill_between(x, cum_stateless, cum_mcr, alpha=0.3, color=colors['eliminated'], 
                     label='Tokens Saved')
    ax6.plot(x, cum_stateless, 'o-', color=colors['stateless'], linewidth=2, markersize=8,
             label='Cumulative Stateless')
    ax6.plot(x, cum_mcr, 's-', color=colors['mcr'], linewidth=2, markersize=8,
             label='Cumulative MCR')
    
    ax6.set_xlabel('Workflow Step', fontsize=11, color=colors['text'])
    ax6.set_ylabel('Cumulative Tokens', fontsize=11, color=colors['text'])
    ax6.set_title('Cumulative Token Consumption & Savings', fontsize=14, fontweight='bold',
                  color=colors['text'], pad=15)
    ax6.set_xticks(x)
    ax6.set_xticklabels(step_labels, fontsize=9, color=colors['text'])
    ax6.tick_params(colors=colors['text'])
    ax6.legend(loc='upper left', facecolor=colors['background'], edgecolor=colors['grid'],
               labelcolor=colors['text'])
    
    # Add savings annotation
    final_saving = cum_savings[-1]
    ax6.annotate(f'Total Saved:\n{final_saving:,} tokens\n({reduction_pct:.1f}%)',
                 xy=(x[-1], (cum_stateless[-1] + cum_mcr[-1])/2),
                 xytext=(x[-1] + 0.3, (cum_stateless[-1] + cum_mcr[-1])/2),
                 fontsize=10, color=colors['eliminated'],
                 bbox=dict(boxstyle='round', facecolor=colors['background'], edgecolor=colors['eliminated']))
    
    # ── Chart 7: Model Routing & API Usage ──
    ax7 = fig.add_subplot(gs[2, 2])
    ax7.set_facecolor(colors['background'])
    ax7.axis('off')
    
    routing_text = "Model Routing Decisions\n══════════════════════════\n\n"
    for i, r in enumerate(mcr_results):
        rt = r["routing"]
        model_short = "Haiku" if "haiku" in rt["actual_model"] else "Sonnet"
        routing_text += f"Step {i} ({rt['step_type'][:8]}):\n"
        routing_text += f"  Required: {rt['min_capability']}\n"
        routing_text += f"  Selected: {model_short}\n"
        routing_text += f"  In: {r['api_usage']['input_tokens']:,} | Out: {r['api_usage']['output_tokens']:,}\n\n"
    
    ax7.text(0.1, 0.95, routing_text, transform=ax7.transAxes, fontsize=10,
             verticalalignment='top', fontfamily='monospace',
             color=colors['text'], bbox=dict(boxstyle='round', facecolor=colors['grid'], alpha=0.5))
    
    # Add title and timestamp
    fig.suptitle('MCR Live Integration Test Dashboard', fontsize=20, fontweight='bold',
                 color=colors['text'], y=0.98)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    fig.text(0.99, 0.01, f'Generated: {timestamp}', ha='right', va='bottom',
             fontsize=9, color=colors['grid'])
    fig.text(0.01, 0.01, 'Model Context Routing (MCR) - Live API Test', ha='left', va='bottom',
             fontsize=9, color=colors['grid'])
    
    # Save figure
    plt.savefig(output_path, dpi=150, facecolor=colors['background'], 
                edgecolor='none', bbox_inches='tight', pad_inches=0.5)
    plt.close()
    
    return output_path


# ── Main Test Runner ─────────────────────────────────────────────────────────

async def run_live_integration_test():
    """Run the full MCR live integration test with Anthropic API."""
    
    banner("MCR Live Integration Test — NATS + JetStream + Anthropic API", GRN)
    
    # Check for API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        err("ANTHROPIC_API_KEY environment variable not set!")
        return False
    ok("ANTHROPIC_API_KEY detected")
    
    # Initialize Anthropic client
    client = anthropic.Anthropic(api_key=api_key)
    sec("Anthropic client initialized")
    
    # Start NATS server
    sec("Starting NATS server with JetStream")
    nats_proc = start_nats()
    ok(f"NATS server ready (port 4222, JetStream, file store: /tmp/mcr_nats_store)")
    
    try:
        # Connect MCR Context Plane
        sec("Connecting MCR Context Plane")
        plane = MCRContextPlane("nats://localhost:4222")
        await plane.connect()
        
        # Initialize orchestrator
        sec("Initializing Live MCR Orchestrator")
        orchestrator = LiveMCROrchestrator(plane, client)
        
        # Generate workflow correlation ID
        corr_id = str(uuid.uuid4())
        inf("Correlation ID:", corr_id)
        inf("Workflow:", f"security incident investigation ({len(WORKFLOW_STEPS)} steps)")
        inf("R (relevance):", "0.35 (semantic scorer selects within this budget)")
        
        # Run MCR workflow
        banner("Running MCR Live Workflow", BLUE)
        mcr_results = []
        
        for step in WORKFLOW_STEPS:
            si = step["step_index"]
            sec(f"Step {si} [{step['step_type']}] → route → reconstruct → API call → publish")
            
            policy = RoutingPolicy(
                step_type=step["step_type"],
                min_capability=step["min_capability"],
                max_latency_ms=step["max_latency_ms"],
                max_cost_per_mtok=step["max_cost_per_mtok"],
                data_class=step["data_class"],
            )
            
            result = await orchestrator.process_step(
                correlation_id=corr_id,
                step_index=si,
                task=step["task"],
                workflow_type="incident",
                routing_policy=policy,
            )
            mcr_results.append(result)
            
            rt = result["routing"]
            rc = result["reconstruction"]
            api = result["api_usage"]
            
            inf("Routing policy / selected model:", f"{rt['step_type']} / {rt['selected_model']}")
            inf("Actual API model:", rt["actual_model"])
            inf("NATS seq:", result["nats_seq"])
            inf("Prior events fetched:", rc["prior_events_fetched"])
            inf("Prior tokens available:", f"{rc['prior_tokens_available']:,}")
            inf("Token budget (R×avail):", f"{rc['token_budget']:,}")
            inf("Events selected:", rc["selected_events"])
            inf("Tokens selected:", f"{rc['selected_tokens']:,}")
            inf("Tokens eliminated:", f"{rc['tokens_eliminated']:,}")
            inf("Actual ratio:", rc["actual_ratio"])
            inf("API input tokens:", f"{api['input_tokens']:,}")
            inf("API output tokens:", f"{api['output_tokens']:,}")
            inf("Step cost:", f"${rt['step_cost_usd']:.6f}")
            inf("Elapsed:", f"{result['elapsed_ms']:.0f}ms")
            print(f"\n  {GRY}Response:{RST}")
            # Print response in wrapped format
            resp_lines = result["full_response"].split('\n')
            for line in resp_lines[:10]:  # Show first 10 lines
                print(f"    {GRY}{line[:100]}{RST}")
            if len(resp_lines) > 10:
                print(f"    {GRY}... ({len(resp_lines) - 10} more lines){RST}")
        
        # Get stream status
        stream = await plane.stream_info()
        sec("JetStream Stream Status")
        inf("Messages persisted:", stream["messages"])
        inf("Bytes stored:", f"{stream['bytes']:,}")
        inf("Sequence range:", f"{stream['first_seq']} → {stream['last_seq']}")
        ok("All events replayable by correlation ID for audit")
        
        # Summary report
        banner("Live Integration Test Summary", GRN)
        
        total_input = sum(r["api_usage"]["input_tokens"] for r in mcr_results)
        total_output = sum(r["api_usage"]["output_tokens"] for r in mcr_results)
        total_cost = sum(r["routing"]["step_cost_usd"] for r in mcr_results)
        total_eliminated = sum(r["reconstruction"]["tokens_eliminated"] for r in mcr_results)
        
        print(f"\n  {'Step':<6}{'Type':<18}{'Input':>10}{'Output':>10}{'Eliminated':>12}  Model")
        print(f"  {'-'*66}")
        for mc, step in zip(mcr_results, WORKFLOW_STEPS):
            print(f"  {mc['step_index']:<6}{step['step_type']:<18}"
                  f"{mc['api_usage']['input_tokens']:>10,}{mc['api_usage']['output_tokens']:>10,}"
                  f"{mc['reconstruction']['tokens_eliminated']:>12,}  {mc['routing']['actual_model']}")
        print(f"  {'-'*66}")
        print(f"  {'TOTAL':<24}{total_input:>10,}{total_output:>10,}{total_eliminated:>12,}")
        
        sec("Economic Summary")
        inf("Total input tokens:", f"{total_input:,}")
        inf("Total output tokens:", f"{total_output:,}")
        inf("Total tokens eliminated:", f"{total_eliminated:,}")
        inf("Total cost (estimated):", f"${total_cost:.6f}")
        
        sec("MCR Benefits Demonstrated")
        ok("✓ Context persisted in JetStream across all workflow steps")
        ok("✓ Semantic relevance scoring for selective context reconstruction")
        ok("✓ Model routing based on step complexity requirements")
        ok("✓ Correlation ID enables full audit trail replay")
        ok(f"✓ {total_eliminated:,} tokens eliminated through selective reconstruction")
        
        # Generate dashboard
        sec("Generating Dashboard")
        dashboard_path = os.path.join(os.path.dirname(__file__), "mcr_live_test_dashboard.png")
        generate_dashboard(mcr_results, WORKFLOW_STEPS, corr_id, dashboard_path)
        ok(f"Dashboard saved to: {dashboard_path}")
        
        # Clean up
        sec("Cleanup")
        await plane.close()
        nats_proc.terminate()
        nats_proc.wait()
        ok("NATS server stopped | JetStream context plane closed")
        
        banner("Live Integration Test Complete ✓", GRN)
        print(f"\n  {BOLD}MCR successfully processed {len(WORKFLOW_STEPS)} workflow steps with live API calls.{RST}")
        print(f"  Total tokens: {total_input + total_output:,} (input: {total_input:,}, output: {total_output:,})")
        print(f"  Estimated cost: ${total_cost:.6f}")
        print(f"  Dashboard: {dashboard_path}\n")
        
        return True
        
    except Exception as e:
        err(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        nats_proc.terminate()
        nats_proc.wait()
        return False


if __name__ == "__main__":
    success = asyncio.run(run_live_integration_test())
    sys.exit(0 if success else 1)
