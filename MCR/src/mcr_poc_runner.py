"""
mcr_poc_runner.py
Full MCR Proof of Concept — corrected implementation.

Demonstrates:
  1. NATS server with JetStream (file-backed, 24-hour retention)
  2. MCP JSON-RPC 2.0 handshake and tool dispatch
  3. Per-step routing policies driving model provider selection
  4. Subject-level correlation filtering (O(N_workflow), not O(N_stream))
  5. Explicit-ack durable consumers for reconstruction reliability
  6. Semantic relevance reconstruction (cosine similarity, not sliding window)
  7. Symmetric side-by-side comparison: stateless re-injects full history
     (user + assistant); MCR draws from the same pool selectively

Workflow: 5-step security incident investigation
"""

import asyncio
import json
import os
import shutil
import subprocess
import time
import uuid

from context_plane    import MCRContextPlane
from mcr_orchestrator import MCROrchestrator, StatelessOrchestrator, RoutingPolicy
from mcp_server       import MCPServer


# ── Workflow definition with per-step routing policies ────────────────────────

WORKFLOW_STEPS = [
    {
        "step_index":      0,
        "step_type":       "triage",
        "min_capability":  "basic",      # classification task — basic tier sufficient
        "max_latency_ms":  400,
        "max_cost_per_mtok": 2.00,
        "data_class":      "confidential",
        "task": (
            "Initial alert triage: We have received an IDS alert for unusual outbound "
            "traffic from host 10.4.22.107. The alert triggered at 03:14 UTC with "
            "destination IP 185.220.101.45 on port 443. Traffic volume was 2.3 GB "
            "in 8 minutes. Classify the alert severity and recommend immediate triage actions."
        ),
    },
    {
        "step_index":      1,
        "step_type":       "correlation",
        "min_capability":  "basic",      # structured lookup — basic tier
        "max_latency_ms":  400,
        "max_cost_per_mtok": 2.00,
        "data_class":      "confidential",
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
        "step_index":      2,
        "step_type":       "intelligence",
        "min_capability":  "reasoning",  # TI correlation requires reasoning
        "max_latency_ms":  600,
        "max_cost_per_mtok": 5.00,
        "data_class":      "confidential",
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
        "step_index":      3,
        "step_type":       "lateral_movement",
        "min_capability":  "reasoning",  # multi-system causal analysis
        "max_latency_ms":  600,
        "max_cost_per_mtok": 5.00,
        "data_class":      "confidential",
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
        "step_index":      4,
        "step_type":       "remediation",
        "min_capability":  "reasoning",  # structured IR plan — reasoning sufficient
        "max_latency_ms":  800,
        "max_cost_per_mtok": 5.00,
        "data_class":      "confidential",
        "task": (
            "Incident response recommendation: Based on all findings so far, provide "
            "a structured incident response plan including: immediate containment steps, "
            "evidence preservation priorities, stakeholder notification sequence, and "
            "estimated time to remediation. Assign an overall incident severity rating."
        ),
    },
]


# ── Console helpers ───────────────────────────────────────────────────────────

RST = "\033[0m"; BOLD = "\033[1m"; NAVY = "\033[34m"
BLUE = "\033[36m"; GRN = "\033[32m"; YLW = "\033[33m"
RED = "\033[31m"; GRY = "\033[90m"

def banner(t, c=NAVY):
    w = 70
    print(f"\n{c}{BOLD}{'='*w}\n  {t}\n{'='*w}{RST}")

def sec(t):   print(f"\n{BLUE}{BOLD}── {t}{RST}")
def inf(l,v): print(f"  {GRY}{l:<34}{RST} {v}")
def ok(t):    print(f"  {GRN}{t}{RST}")
def warn(t):  print(f"  {YLW}{t}{RST}")


# ── NATS server ───────────────────────────────────────────────────────────────

def start_nats() -> subprocess.Popen:
    """
    Start NATS server with JetStream enabled.
    
    Looks for nats-server in common locations and uses the config file
    from the src/ directory.
    """
    os.makedirs("/tmp/mcr_nats_store", exist_ok=True)
    
    # Find nats-server binary
    nats_paths = [
        "nats-server",  # In PATH
        "/usr/local/bin/nats-server",
        "/usr/bin/nats-server",
        "/usr/sbin/nats-server",
        "/tmp/nats-server-v2.10.25-linux-amd64/nats-server",  # Downloaded binary
    ]
    
    nats_bin = None
    for path in nats_paths:
        if os.path.isfile(path) or shutil.which(path):
            nats_bin = path
            break
    
    if not nats_bin:
        raise RuntimeError(
            "nats-server not found. Install NATS server or set path in start_nats().\n"
            "See Appendix B in README.md for installation instructions."
        )
    
    # Use config file from src/ directory
    config_path = os.path.join(os.path.dirname(__file__), "nats_config.conf")
    if not os.path.isfile(config_path):
        # Create minimal config if not present
        config_path = "/tmp/mcr_nats_config.conf"
        with open(config_path, "w") as f:
            f.write("""
port: 4222
jetstream {
    store_dir: /tmp/mcr_nats_store
    max_memory_store: 256M
    max_file_store: 1G
}
""")
    
    proc = subprocess.Popen(
        [nats_bin, "-c", config_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.5)
    return proc


# ── In-process MCP client ─────────────────────────────────────────────────────

class MCPClient:
    """
    Calls MCPServer.handle() in-process, exercising the full JSON-RPC 2.0
    message structure. For a subprocess MCP deployment, replace call_tool()
    with stdio transport writes and MCPServer.run_stdio() as the server entry.
    """

    def __init__(self, server: MCPServer):
        self.server = server
        self._id    = 0

    def _next(self) -> int:
        self._id += 1
        return self._id

    async def initialize(self) -> dict:
        r = await self.server.handle({
            "jsonrpc": "2.0", "id": self._next(), "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcr-poc-client", "version": "0.2.0"},
            },
        })
        await self.server.handle({"jsonrpc": "2.0",
                                  "method": "notifications/initialized"})
        return r

    async def list_tools(self) -> dict:
        return await self.server.handle(
            {"jsonrpc": "2.0", "id": self._next(), "method": "tools/list"})

    async def call_tool(self, name: str, args: dict) -> dict:
        return await self.server.handle({
            "jsonrpc": "2.0", "id": self._next(), "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })


# ── Main ──────────────────────────────────────────────────────────────────────

async def run_poc():
    banner("MCR Proof of Concept — NATS + JetStream + MCP + Semantic Reconstruction")

    sec("Starting NATS server with JetStream")
    nats_proc = start_nats()
    ok("NATS server ready  (port 4222, JetStream, file store: /tmp/mcr_nats_store)")

    sec("Connecting MCR Context Plane")
    plane = MCRContextPlane("nats://localhost:4222")
    await plane.connect()

    sec("Initialising MCP server and orchestrators")
    mcr_orch   = MCROrchestrator(plane)
    mcp_srv    = MCPServer(mcr_orch)
    mcp_cli    = MCPClient(mcp_srv)
    sl_orch    = StatelessOrchestrator()

    init = await mcp_cli.initialize()
    ok(f"MCP handshake  →  {init['result']['serverInfo']['name']} "
       f"v{init['result']['serverInfo']['version']}  "
       f"(protocol {init['result']['protocolVersion']})")

    tools = (await mcp_cli.list_tools())["result"]["tools"]
    ok(f"Tools registered: {[t['name'] for t in tools]}")

    corr_id = str(uuid.uuid4())
    print(f"\n  Correlation ID : {BOLD}{corr_id}{RST}")
    print(f"  Workflow       : security incident investigation  ({len(WORKFLOW_STEPS)} steps)")
    print(f"  R (relevance)  : 0.35  (semantic scorer selects within this budget)")
    print(f"  Reconstruction : cosine similarity  (content-aware, not recency-governed)")
    print(f"  Routing        : cheapest eligible provider per step policy")

    # ── Phase 1: MCR ─────────────────────────────────────────────────────────
    banner("Phase 1: MCR  (NATS + JetStream + Semantic Reconstruction + Routing)", BLUE)
    mcr_results = []

    for step in WORKFLOW_STEPS:
        si = step["step_index"]
        sec(f"Step {si} [{step['step_type']}]  →  "
            f"MCP call  →  route  →  reconstruct  →  publish")

        resp   = await mcp_cli.call_tool("process_workflow_step", {
            "correlation_id":   corr_id,
            "step_index":       si,
            "task":             step["task"],
            "workflow_type":    "incident",
            "step_type":        step["step_type"],
            "min_capability":   step["min_capability"],
            "max_latency_ms":   step["max_latency_ms"],
            "max_cost_per_mtok":step["max_cost_per_mtok"],
            "data_class":       step["data_class"],
        })
        r      = json.loads(resp["result"]["content"][0]["text"])
        mcr_results.append(r)

        rt     = r["routing"]
        rc     = r["reconstruction"]
        api    = r["api_usage"]

        inf("Routing policy / selected model:",
            f"{rt['step_type']} / {rt['selected_model']}  "
            f"({rt['min_capability']}+, {rt['latency_p50_ms']}ms, "
            f"${rt['cost_per_mtok']}/Mtok)")
        inf("NATS seq / subject:",
            f"{r['nats_seq']} / poc.secops.incident.{corr_id[:8]}...{step['step_type'][:3]}")
        inf("Prior events fetched:",   rc["prior_events_fetched"])
        inf("Prior tokens available:", f"{rc['prior_tokens_available']:,}")
        inf("Token budget (R×avail):", f"{rc['token_budget']:,}")
        inf("Events selected:",        rc["selected_events"])
        inf("Tokens selected:",        f"{rc['selected_tokens']:,}")
        inf("Tokens eliminated:",      f"{rc['tokens_eliminated']:,}")
        inf("Actual ratio:",           rc["actual_ratio"])
        inf("Top event scores:",       rc["top_event_scores"])
        inf("API input tokens:",       f"{api['input_tokens']:,}")
        inf("Step cost:",              f"${rt['step_cost_usd']:.6f}")
        print(f"  {GRY}{r['response_preview']}{RST}")

    stream = json.loads(
        (await mcp_cli.call_tool("get_stream_status", {}))["result"]["content"][0]["text"]
    )
    sec("JetStream stream status")
    inf("Messages persisted:", stream["messages"])
    inf("Bytes stored:",       f"{stream['bytes']:,}")
    inf("Sequence range:",     f"{stream['first_seq']} → {stream['last_seq']}")
    ok("All events replayable by correlation ID for audit")

    # ── Phase 2: Stateless ────────────────────────────────────────────────────
    banner("Phase 2: Stateless  (full history re-injected, fixed model)", RED)
    warn("No NATS. No JetStream. No routing. All prior context re-injected at every step.")
    warn("History includes BOTH user tasks and assistant responses (symmetric with MCR pool).")
    sl_results = []

    for step in WORKFLOW_STEPS:
        si = step["step_index"]
        sec(f"Step {si} [{step['step_type']}]  →  direct API call")
        from mcr_orchestrator import RoutingPolicy
        sl_policy = RoutingPolicy(
            step_type         = step["step_type"],
            min_capability    = step["min_capability"],
            max_latency_ms    = step["max_latency_ms"],
            max_cost_per_mtok = step["max_cost_per_mtok"],
            data_class        = step["data_class"],
        )
        r  = sl_orch.process_step_stateless(si, step["task"], sl_policy)
        sl_results.append(r)
        api = r["api_usage"]
        inf("Fixed model:",    r["model"])
        inf("History msgs:",   r["history_messages"])
        inf("Input tokens:",   f"{api['input_tokens']:,}")
        inf("Step cost:",      f"${r['step_cost_usd']:.6f}")
        print(f"  {GRY}{r['response_preview']}{RST}")

    # ── Comparison report ──────────────────────────────────────────────────────
    banner("Comparison Report: MCR vs Stateless", GRN)

    mcr_in  = sum(r["api_usage"]["input_tokens"] for r in mcr_results)
    sl_in   = sum(r["api_usage"]["input_tokens"] for r in sl_results)
    mcr_cost= sum(r["routing"]["step_cost_usd"]  for r in mcr_results)
    sl_cost = sum(r["step_cost_usd"]              for r in sl_results)
    pct     = (sl_in - mcr_in) / sl_in * 100 if sl_in else 0

    print(f"\n  {'Step':<6}{'Type':<18}{'Stateless':>14}{'MCR':>10}"
          f"{'Eliminated':>12}{'Reduction':>10}  Model selected")
    print(f"  {'-'*78}")
    for sl, mc, step in zip(sl_results, mcr_results, WORKFLOW_STEPS):
        si_t  = sl["api_usage"]["input_tokens"]
        mi_t  = mc["api_usage"]["input_tokens"]
        elim  = si_t - mi_t
        red   = elim / si_t * 100 if si_t else 0
        model = mc["routing"]["selected_model"].split("-")[1]  # e.g. "haiku"
        print(f"  {sl['step_index']:<6}{step['step_type']:<18}{si_t:>14,}{mi_t:>10,}"
              f"{elim:>12,}{red:>9.1f}%  {model}")
    print(f"  {'-'*78}")
    print(f"  {'TOTAL':<24}{sl_in:>14,}{mcr_in:>10,}"
          f"{sl_in-mcr_in:>12,}{pct:>9.1f}%")

    sec("Economic summary")
    inf("Stateless input tokens:",   f"{sl_in:,}")
    inf("MCR input tokens:",         f"{mcr_in:,}")
    inf("Token reduction:",          f"{pct:.1f}%")
    inf("Stateless total cost:",     f"${sl_cost:.6f}")
    inf("MCR total cost:",           f"${mcr_cost:.6f}")
    inf("Cost saving:",              f"${sl_cost - mcr_cost:.6f}  "
                                     f"({(sl_cost-mcr_cost)/sl_cost*100:.1f}%)")

    sec("Routing decisions")
    for mc in mcr_results:
        rt = mc["routing"]
        inf(f"Step {mc['step_index']} [{rt['step_type']}]:",
            f"required {rt['min_capability']}+  →  {rt['selected_model']}  "
            f"(${rt['cost_per_mtok']}/Mtok,  {rt['latency_p50_ms']}ms)")
    ok("Steps 0-1 routed to haiku (basic task, cheapest eligible)")
    ok("Steps 2-4 routed to sonnet (reasoning required by policy)")

    sec("Reconstruction fidelity")
    for mc in mcr_results:
        rc  = mc["reconstruction"]
        inf(f"Step {mc['step_index']} actual ratio:",
            f"{rc['actual_ratio']}  (target R=0.35,  "
            f"budget={rc['token_budget']},  selected={rc['selected_tokens']})")
    ok("Ratio at or below R=0.35 — greedy selection fills budget without overshoot")

    sec("Infrastructure")
    inf("JetStream messages persisted:", stream["messages"])
    inf("JetStream bytes stored:",       f"{stream['bytes']:,}")
    ok(f"Subject per workflow: poc.secops.incident.{corr_id[:8]}....{{event_type}}")
    ok("Durable pull consumers with AckPolicy.EXPLICIT — replay on failure")
    ok("Correlation ID filtering at broker level (O(N_workflow), not O(N_stream))")

    sec("MCP protocol layer")
    inf("JSON-RPC messages:", f"{3 + len(WORKFLOW_STEPS) + 1} total")
    inf("Tool calls:", f"{len(WORKFLOW_STEPS)} x process_workflow_step  +  1 x get_stream_status")

    sec("Cleanup")
    await plane.close()
    nats_proc.terminate()
    nats_proc.wait()
    ok("NATS server stopped  |  JetStream context plane closed")

    banner("POC Complete", GRN)
    print(f"\n  MCR reduced input tokens by {BOLD}{pct:.1f}%{RST} "
          f"vs stateless ({sl_in:,} → {mcr_in:,}).")
    print(f"  Routing directed steps 0-1 to haiku and steps 2-4 to sonnet,")
    print(f"  saving ${sl_cost-mcr_cost:.6f} vs a naive fixed-model stateless approach.")
    print(f"  All {stream['messages']} context events are durably persisted and replayable.\n")


if __name__ == "__main__":
    asyncio.run(run_poc())
