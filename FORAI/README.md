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

## System Requirements

### Recommended Hardware

| Component | Minimum | Recommended | Notes |
|-----------|---------|-------------|-------|
| **CPU** | 4 cores | 8+ cores | RL training benefits from parallelization |
| **RAM** | 8 GB | 32 GB | Large forensic images need memory for graph operations |
| **Storage** | 50 GB SSD | 500 GB NVMe | Kuzu graph DB and evidence storage; SSD required for performance |
| **GPU** | None | NVIDIA 8GB+ VRAM | Optional: accelerates local LLM inference and world model training |

### Recommended Configurations

**Analyst Workstation (Interactive Analysis)**
- 16 GB RAM, 8-core CPU, 256 GB SSD
- Sufficient for small-medium cases (<100K events)
- Local LLM via Ollama with 7B parameter models

**Investigation Server (Large Cases)**
- 64 GB RAM, 16-core CPU, 1 TB NVMe
- Handles large forensic images (1M+ events)
- GPU recommended for faster LLM inference
- PPO agent training with stable-baselines3

**Air-Gapped Forensic Lab**
- Same as above, fully offline capable
- Pre-download LLM models (GGUF format)
- All dependencies installed from local mirrors

## Build & Setup

### Prerequisites (All Platforms)

1. **Python 3.9+** (3.11 recommended)
2. **Git** for version control
3. **Plaso** for timeline parsing (optional but recommended)
4. **Ollama** for local LLM (optional)

---

### Windows Setup

```powershell
# 1. Install Python (if not installed)
# Download from https://python.org or use winget:
winget install Python.Python.3.11

# 2. Clone the repository
git clone https://github.com/sdshook/Tools.git
cd Tools/FORAI

# 3. Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# 4. Install core dependencies
pip install -r requirements.txt

# 5. Install optional features (choose what you need)
# For PPO agent (RL):
pip install "stable-baselines3[extra]" gymnasium

# For Kuzu graph database:
pip install kuzu

# For local LLM (llama.cpp):
pip install llama-cpp-python

# 6. Install Plaso (for timeline parsing)
# Option A: Pre-built release from https://github.com/log2timeline/plaso/releases
# Option B: pip install plaso (may require additional setup)

# 7. Install Ollama (for local LLM chat)
# Download from https://ollama.com/download/windows
# Then pull a model:
ollama pull llama3

# 8. Verify installation
python main.py list-questions
```

**Windows-Specific Notes:**
- Use PowerShell or Windows Terminal (not cmd.exe)
- For GPU acceleration with llama-cpp-python, install CUDA toolkit first
- KAPE.exe runs natively for artifact collection

---

### Linux Setup (Ubuntu/Debian)

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip git

# 2. Clone the repository
git clone https://github.com/sdshook/Tools.git
cd Tools/FORAI

# 3. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 4. Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Install optional features
# For PPO agent (RL):
pip install "stable-baselines3[extra]" gymnasium

# For Kuzu graph database:
pip install kuzu

# For local LLM (llama.cpp):
pip install llama-cpp-python
# With CUDA support:
# CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python

# 6. Install Plaso
sudo apt install -y plaso-tools
# Or via pip:
pip install plaso

# 7. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3

# 8. Verify installation
python main.py list-questions
```

**Linux-Specific Notes:**
- For forensic imaging, install `ewf-tools` for E01 support
- Mount forensic images read-only: `mount -o ro,loop image.dd /mnt/evidence`
- Use `tmux` or `screen` for long-running analysis sessions

---

### macOS Setup

```bash
# 1. Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python
brew install python@3.11

# 3. Clone the repository
git clone https://github.com/sdshook/Tools.git
cd Tools/FORAI

# 4. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 5. Install core dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 6. Install optional features
# For PPO agent (RL):
pip install "stable-baselines3[extra]" gymnasium

# For Kuzu graph database:
pip install kuzu

# For local LLM (llama.cpp) - Apple Silicon optimized:
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python

# 7. Install Plaso
brew install log2timeline/plaso/plaso
# Or via pip:
pip install plaso

# 8. Install Ollama
brew install ollama
ollama pull llama3

# 9. Verify installation
python main.py list-questions
```

**macOS-Specific Notes:**
- Apple Silicon (M1/M2/M3) provides excellent local LLM performance via Metal
- For Intel Macs, GPU acceleration requires different llama-cpp-python build flags
- Use `hdiutil` to mount forensic disk images

---

### Docker Setup (All Platforms)

```bash
# Build the container
docker build -t forai .

# Run with mounted evidence directory
docker run -it --rm \
  -v /path/to/evidence:/evidence:ro \
  -v /path/to/output:/output \
  forai analyze --case-id CASE001 --image-path /evidence

# With GPU support (NVIDIA)
docker run -it --rm --gpus all \
  -v /path/to/evidence:/evidence:ro \
  forai analyze --case-id CASE001 --image-path /evidence
```

---

### Quick Verification

After setup, verify all components:

```bash
python -c "
from forai.graph import create_graph, ForensicGraph
from forai.agent import create_agent, ForensicAgent, Action
from forai.extraction import STANDARD_QUESTIONS
from forai.llm import LLMProvider
print(f'✓ Graph backends available')
print(f'✓ Agent types available')
print(f'✓ {len(STANDARD_QUESTIONS)} forensic questions loaded')
print(f'✓ LLM provider ready')
print('\\nFORAI is ready for use!')
"
```

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
| Temporal knowledge graph (SQLite) | ✅ Complete | 6 node types, 7 edge types |
| Temporal knowledge graph (Kuzu) | ✅ Complete | Native graph traversal, faster path queries |
| Graph builder | ✅ Complete | Events → nodes/edges with temporal ordering |
| World model encoder | ✅ Complete | Graph neighborhood → state vector |
| Transition predictor | ✅ Complete | P(next\|current), anomaly scoring |
| RL agent (policy gradient) | ✅ Complete | Simple REINFORCE, epsilon-greedy |
| RL agent (PPO) | ✅ Complete | stable-baselines3, gymnasium env |
| BHSM memory | ✅ Complete | Temporal sequences, embeddings |
| LLM provider (Ollama) | ✅ Complete | Full API integration |
| LLM provider (llama.cpp) | ✅ Complete | Local GGUF model support |
| Graph grounding | ✅ Complete | Context builder for LLM |
| Report generator | ✅ Complete | PDF/JSON/text output |
| Plaso integration | 🔄 Interface | Parser ready, needs runtime testing |
| World model training | ❌ Not yet | Needs baseline Windows telemetry |
| RL agent training | ❌ Not yet | Needs analyst feedback sessions |

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
