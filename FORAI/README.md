# FORAI - Forensic AI Analysis Tool
(c) 2025 Shane D. Shook, PhD - All Rights Reserved

## What It Is

FORAI is a **graph-based forensic analysis system** that combines deterministic evidence extraction with AI-guided investigation. It builds a **temporal knowledge graph** from forensic artifacts, uses a **world model** to score anomalies against expected Windows behavior, and employs an **RL agent** to navigate the investigation while an analyst supervises.

**Core capabilities:**
- **12 Standard Questions**: Deterministic answers with confidence scores and source attribution—the baseline report every investigation needs before diving deeper
- **Temporal Knowledge Graph**: Artifacts become nodes (Process, File, Network, Registry, User, Service) connected by edges (spawned_by, wrote_to, precedes, anomalous_delta)
- **World Model**: Predicts P(next_state|current_state) to quantify how unexpected each artifact sequence is
- **RL Agent**: Learns productive investigation paths; actions include pivot_to_node, expand_subgraph, flag_IOC, request_LLM_explanation
- **Graph-Grounded LLM**: Local LLM (Ollama/llama.cpp) explains findings using only evidence from the graph—no hallucination
- **Defensible Output**: Every LLM prompt/response hashed, RL trajectory logged, model versions recorded

## Architecture

```
Forensic Image (read-only mount)
        │
        ▼
┌───────────────────────────────────┐
│  Deterministic Extraction Layer   │  forai/extraction/
│  • Plaso timeline parsing         │
│  • Hayabusa/Volatility (planned)  │
│  • 12 standard question answers   │
│  • SQLite evidence database       │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Temporal Knowledge Graph         │  forai/graph/
│  Nodes: Process|File|Network|     │
│         Registry|User|Service     │
│  Edges: spawned_by|wrote_to|      │
│         connected_to|modified|    │
│         precedes|anomalous_delta  │
│  Props: timestamp, confidence,    │
│         artifact_source, hash     │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  World Model Layer                │  forai/world_model/
│  • Trained on baseline telemetry  │
│  • P(next_state | current_state)  │
│  • Anomaly scoring per edge/node  │
│  • Causal plausibility output     │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  RL Agent                         │  forai/agent/
│  State: graph neighborhood +      │
│         world model belief        │
│  Actions: pivot_to_node |         │
│           expand_subgraph |       │
│           flag_IOC | request_LLM |│
│           mark_benign | finish    │
│  Reward: anomaly confirmation,    │
│          analyst approval,        │
│          causal chain completion  │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Local LLM                        │  forai/llm/
│  • Ollama / llama-cpp-python      │
│  • Receives: subgraph context +   │
│              RL agent findings    │
│  • Graph-grounded explanations    │
│  • Every response logged with     │
│    graph state hash               │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Analyst Review Gate              │
│  • Approve/reject/redirect agent  │
│  • Annotate nodes with reasoning  │
│  • Interactive question mode      │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Defensible Report                │  forai/report/
│  • Full graph provenance          │
│  • LLM prompt/response hashes     │
│  • RL trajectory (what was seen)  │
│  • Model version, seed, temp      │
│  • Chain of custody logs          │
└───────────────────────────────────┘
```

## The 12 Standard Forensic Questions

These are answered deterministically from parsed artifacts:

| # | Question | Data Source |
|---|----------|-------------|
| Q1 | What is the computer name? | Registry, hostname artifacts |
| Q2 | Computer make/model/serial? | SMBIOS, registry |
| Q3 | What internal hard drives? | Disk signatures, MBR/GPT |
| Q4 | What user accounts exist? | SAM, security logs |
| Q5 | Who is the primary user? | Activity volume analysis |
| Q6 | Anti-forensic activity? | Log clearing, timestamp manipulation |
| Q7 | USB devices connected? | USBSTOR, setupapi logs |
| Q8 | Files transferred to USB? | Shellbags, LNK files, USN journal |
| Q9 | Cloud storage usage? | Browser history, sync artifacts |
| Q10 | Screenshot artifacts? | File system scan |
| Q11 | Documents printed? | Print spooler logs |
| Q12 | Software installed/modified? | Amcache, registry uninstall keys |

Each answer includes:
- **Confidence score** (based on artifact completeness)
- **Source attribution** (which files/registry keys)
- **Timestamp range** (when applicable)

## Package Structure

```
FORAI/
├── main.py                 # Entry point
├── requirements.txt
├── README.md
└── forai/
    ├── config.py           # ForaiConfig dataclass
    ├── cli.py              # CLI interface (argparse)
    │
    ├── db/                 # Database layer
    │   ├── schema.py       # Table definitions
    │   └── evidence.py     # EvidenceStore class
    │
    ├── graph/              # Temporal knowledge graph
    │   ├── nodes.py        # NodeType enum, GraphNode
    │   ├── edges.py        # EdgeType enum, GraphEdge
    │   ├── graph.py        # TemporalGraph class
    │   └── builder.py      # GraphBuilder (events → graph)
    │
    ├── extraction/         # Deterministic extraction
    │   ├── extractors.py   # 12 forensic questions + extractors
    │   └── plaso.py        # PlasoParser (timeline → events)
    │
    ├── bhsm/               # Bio-Hierarchical Sequence Memory
    │   ├── memory.py       # BHSMMemory class
    │   └── embedder.py     # EventEmbedder
    │
    ├── world_model/        # Anomaly detection
    │   ├── encoder.py      # StateEncoder (graph → vector)
    │   └── predictor.py    # TransitionPredictor
    │
    ├── agent/              # RL investigation agent
    │   ├── actions.py      # ForensicAction enum
    │   ├── rewards.py      # RewardCalculator
    │   └── agent.py        # ForensicAgent class
    │
    ├── llm/                # Graph-grounded LLM
    │   ├── provider.py     # LLMProvider (Ollama/llama.cpp)
    │   └── grounding.py    # GraphGrounder (context builder)
    │
    └── report/             # Output generation
        └── generator.py    # ReportGenerator (PDF/JSON/text)
```

## Installation

```bash
pip install -r requirements.txt
```

**Required:**
- Python 3.9+
- numpy, fpdf2, tqdm

**Optional:**
- `llama-cpp-python` - Local LLM inference
- `plaso` - Timeline parsing (log2timeline, psort)
- `kuzu` - Native graph database (SQLite fallback included)
- `stable-baselines3` - PPO-based RL (simple policy included)

**External tools (Windows forensics):**
- KAPE.exe (artifact collection)
- Plaso (log2timeline, psort)
- Hayabusa (Windows event log analysis)

## Usage

### List the 12 Standard Questions
```bash
python main.py list-questions
```

### Analyze a Forensic Image
```bash
python main.py analyze --case-id CASE001 --image-path /mnt/evidence/disk.E01
```

### Answer a Specific Question
```bash
python main.py question --case-id CASE001 --question-id Q7  # USB devices
```

### Interactive Mode (Analyst Review Gate)
```bash
python main.py interactive --case-id CASE001
```

### With Local LLM
```bash
python main.py analyze --case-id CASE001 --image-path /mnt/evidence --llm-model ./models/llama3.gguf
```

## Key Design Decisions

### Why Local LLM?
- **Reproducibility**: Same model file = same output
- **Offline**: Works without network
- **Defensible**: Model version on record for court

### Why Graph Database?
- Forensic artifacts have relationships (process spawned file, user owns process)
- Temporal edges capture "what happened when"
- Enables causal chain reconstruction

### Why RL Agent?
- Learns which evidence paths are productive
- Incorporates analyst feedback
- Documents investigation trajectory for reports

### Why World Model?
- Baseline Windows behavior lets us detect deviations
- P(next_state|current_state) quantifies "unexpectedness"
- Causal plausibility helps filter false positives

## Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| 12 standard questions | ✅ Complete | Deterministic extractors with confidence scores |
| Temporal knowledge graph | ✅ Complete | 6 node types, 7 edge types, SQLite backend |
| Graph builder | ✅ Complete | Events → nodes/edges with temporal ordering |
| World model encoder | ✅ Complete | Graph neighborhood → state vector |
| Transition predictor | ✅ Complete | P(next\|current), anomaly scoring |
| RL agent | ✅ Complete | 6 actions, reward calculator |
| BHSM memory | ✅ Complete | Temporal sequences, embeddings |
| LLM provider | ✅ Complete | Ollama + llama-cpp-python support |
| Graph grounding | ✅ Complete | Context builder for LLM |
| Report generator | ✅ Complete | PDF/JSON/text output |
| Plaso integration | 🔄 Interface | Parser ready, needs runtime testing |
| World model training | ❌ Not yet | Needs baseline Windows telemetry |
| RL agent training | ❌ Not yet | Needs analyst feedback sessions |
| Kuzu native graph | ❌ Planned | SQLite fallback works |

## Limitations

- **Windows-focused**: KAPE and many parsers target Windows artifacts
- **No memory forensics**: Volatility integration not implemented
- **World model untrained**: Needs baseline Windows telemetry data
- **RL agent untrained**: Needs analyst feedback sessions
- **Graph building**: Currently infers edges from timestamps, not full causal analysis

## Example Output

```
=== FORAI Forensic Analysis Report ===
Case ID: CASE001
Generated: 2025-03-17T14:30:00

Q1: Computer Name
Answer: DESKTOP-ABC123
Confidence: 0.95
Sources: SYSTEM registry hive, hostname artifact
Attribution: HKLM\SYSTEM\CurrentControlSet\Control\ComputerName

Q7: USB Devices
Answer: 3 devices found
  - Kingston DataTraveler (S/N: 001234) - First: 2025-01-15, Last: 2025-03-10
  - SanDisk Cruzer (S/N: 567890) - First: 2025-02-20, Last: 2025-02-20
  - WD Elements (S/N: WDABCD) - First: 2025-03-01, Last: 2025-03-15
Confidence: 0.88
Sources: USBSTOR, setupapi.dev.log
...
```

## License

Copyright (c) 2025 Shane D. Shook. All Rights Reserved.
