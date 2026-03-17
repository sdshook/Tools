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
- LLM: Ollama with Llama-3-8B (see [Local LLM Setup](#local-llm-setup))

**Investigation Server (Large Cases)**
- 64 GB RAM, 16-core CPU, 1 TB NVMe
- Handles large forensic images (1M+ events)
- GPU recommended for faster LLM inference
- LLM: Llama-3-70B or GPU-accelerated 8B model
- PPO agent training with stable-baselines3

**Air-Gapped Forensic Lab**
- Same hardware as Investigation Server
- Fully offline capable—no network required
- LLM: Pre-downloaded GGUF models (see [llama.cpp setup](#option-2-llamacpp-with-gguf-models-air-gapped--offline))
- All Python dependencies installed from local mirrors

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

## Local LLM Setup

FORAI uses local LLMs for graph-grounded explanations. There are two options:

| Option | Best For | Pros | Cons |
|--------|----------|------|------|
| **Ollama** | Most users, networked environments | Easy setup, auto-updates, simple API | Requires Ollama daemon running |
| **llama.cpp (GGUF)** | Air-gapped labs, maximum control | Fully offline, reproducible | Manual model management |

### Option 1: Ollama (Recommended for Most Users)

Ollama is a local LLM server that manages model downloads and provides a simple API.

**Install Ollama:**
```bash
# Linux
curl -fsSL https://ollama.com/install.sh | sh

# macOS
brew install ollama

# Windows
# Download from https://ollama.com/download/windows
```

**Pull a model:**
```bash
# Recommended for 16GB RAM systems
ollama pull llama3:8b

# Smaller model for 8GB RAM systems
ollama pull llama3.2:3b

# Larger model for 32GB+ RAM or GPU systems
ollama pull llama3:70b
```

**Start Ollama (if not auto-started):**
```bash
ollama serve
```

**Verify:**
```bash
ollama list
# Should show: llama3:8b or your chosen model
```

**Use with FORAI:**
```bash
# Ollama is auto-detected when running on localhost:11434
python main.py interactive CASE001

# Or specify explicitly
python main.py analyze CASE001 --plaso-file timeline.plaso --llm-provider ollama
```

### Option 2: llama.cpp with GGUF Models (Air-Gapped / Offline)

For forensic labs without network access, download GGUF model files directly.

**Install llama-cpp-python:**
```bash
# CPU only
pip install llama-cpp-python

# With NVIDIA GPU acceleration
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python

# With Apple Silicon acceleration
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python
```

**Download GGUF Models:**

Models are available from Hugging Face. Recommended models for forensic analysis:

| Model | Size | RAM Required | Download |
|-------|------|--------------|----------|
| Llama-3.2-3B-Instruct | 2.0 GB | 8 GB | [Q4_K_M](https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF) |
| Llama-3-8B-Instruct | 4.7 GB | 16 GB | [Q4_K_M](https://huggingface.co/bartowski/Meta-Llama-3-8B-Instruct-GGUF) |
| Llama-3-70B-Instruct | 40 GB | 64 GB | [Q4_K_M](https://huggingface.co/bartowski/Meta-Llama-3-70B-Instruct-GGUF) |
| Mistral-7B-Instruct | 4.1 GB | 16 GB | [Q4_K_M](https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF) |

**Download example (using wget or browser):**
```bash
# Create models directory
mkdir -p models

# Download Llama 3 8B (recommended)
wget -O models/llama3-8b-instruct-q4_k_m.gguf \
  "https://huggingface.co/bartowski/Meta-Llama-3-8B-Instruct-GGUF/resolve/main/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf"

# Or download via browser and place in models/ directory
```

**Use with FORAI:**
```bash
python main.py analyze CASE001 --plaso-file timeline.plaso \
  --llm-model ./models/llama3-8b-instruct-q4_k_m.gguf
```

### Model Selection Guide

**Choose based on your hardware and use case:**

| Scenario | Recommended Model | Why |
|----------|-------------------|-----|
| **Laptop (8GB RAM)** | Llama-3.2-3B or Mistral-7B Q4 | Fits in memory, reasonable speed |
| **Workstation (16GB RAM)** | Llama-3-8B Q4_K_M | Best balance of quality and speed |
| **Server (32GB+ RAM)** | Llama-3-8B Q8 or Llama-3-70B Q4 | Higher quality responses |
| **GPU (8GB+ VRAM)** | Llama-3-8B Q4_K_M | Fast inference with GPU offload |
| **Air-gapped lab** | Any GGUF model | Pre-download, fully offline |

**Quantization levels (in GGUF filenames):**
- `Q4_K_M`: Good balance of size and quality (recommended)
- `Q5_K_M`: Slightly better quality, ~25% larger
- `Q8_0`: Near full quality, ~2x size of Q4
- `F16`: Full precision, largest size

### Why Local LLM?

FORAI requires local LLMs (not cloud APIs) for forensic defensibility:

1. **Reproducibility**: Same model file = same outputs given same inputs
2. **Offline operation**: Works in air-gapped forensic labs
3. **Evidence integrity**: No case data sent to external servers
4. **Auditability**: Model version recorded in every report
5. **Cost**: No per-token API charges

### LLM Configuration in Code

```python
from forai.llm import create_provider

# Auto-detect (tries Ollama first, then llama.cpp)
provider = create_provider()

# Explicit Ollama
provider = create_provider(provider_type="ollama", model="llama3:8b")

# Explicit llama.cpp with GGUF file
provider = create_provider(
    provider_type="llama_cpp",
    model_path="./models/llama3-8b-instruct-q4_k_m.gguf",
    n_ctx=4096,      # Context window
    n_gpu_layers=35  # GPU offload (0 for CPU only)
)

# Check availability
if provider.is_available():
    response = provider.generate("Explain this process execution...")
```

### Troubleshooting LLM Issues

**Ollama not responding:**
```bash
# Check if running
curl http://localhost:11434/api/tags

# Restart Ollama
ollama serve
```

**Out of memory with GGUF:**
```bash
# Use smaller quantization
# Instead of Q8_0, use Q4_K_M

# Or reduce context window
python main.py analyze CASE001 --llm-context 2048
```

**Slow inference:**
```bash
# Enable GPU offload (if available)
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install --force-reinstall llama-cpp-python

# Or use smaller model
ollama pull llama3.2:3b
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
python main.py analyze CASE001 --plaso-file timeline.plaso
```

### Specify Custom Output Directory
```bash
python main.py analyze CASE001 --plaso-file timeline.plaso --output-dir /path/to/reports
```

### Answer a Specific Question
```bash
python main.py question CASE001 Q7  # USB devices
```

### Interactive Mode (Analyst Review Gate)
```bash
python main.py interactive CASE001
```

### With Local LLM
```bash
python main.py analyze CASE001 --plaso-file timeline.plaso --llm-model ./models/llama3.gguf
```

## Report Output

Reports are saved to a timestamped directory:

```
{output_dir}/{case_id}_{YYMMDDHHMMSS}/
```

**Default output directory:** `./Reports`

### Report Directory Contents

```
Reports/CASE001_250317143052/
├── report.json       # Full report with all question answers
├── report.pdf        # PDF version for printing/sharing
├── provenance.json   # Separate provenance data for verification
└── manifest.txt      # File listing with SHA-256 hashes
```

### Report Files

| File | Purpose |
|------|---------|
| `report.json` | Complete forensic report with answers, confidence scores, sources |
| `report.pdf` | Formatted PDF for human review and legal proceedings |
| `provenance.json` | Graph state hash, RL trajectory, LLM interaction log |
| `manifest.txt` | Integrity verification with file hashes |

### Example manifest.txt

```
FORAI Report Manifest
Case ID: CASE001
Generated: 2025-03-17T14:30:52
Report Hash: a3b8f29c1e5d7a42

Files:
  provenance.json: 8f2c1a9e3b7d5f40
  report.json: a3b8f29c1e5d7a42
  report.pdf: 5d9f2c8a1b3e7f60
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
| World model training | 🔄 Incremental | Learns from each investigation (see below) |
| RL agent training | 🔄 Incremental | Learns from analyst feedback (see below) |

### Continuous Learning & Knowledge Export

Both the **World Model** and **RL Agent** are designed for **incremental learning**—they improve with each investigation performed:

| Component | Learns From | What Improves |
|-----------|-------------|---------------|
| **World Model** | Each case's artifact sequences | P(next_state\|current_state) predictions; anomaly detection accuracy |
| **RL Agent** | Analyst approve/reject/redirect actions | Investigation navigation; which paths yield actionable findings |

**Knowledge Export for Cross-Investigation Use:**

Learned model weights can be exported and imported into future investigations via BHSM/PSI (Bio-Hierarchical Sequence Memory / Pattern Sequence Index):

```python
# Export learned knowledge (anonymized, no case-specific data)
world_model.export_weights("baseline_windows_v1.pth")
agent.export_policy("analyst_trained_policy_v1.npz")

# Import into new investigation
world_model.import_weights("baseline_windows_v1.pth")
agent.import_policy("analyst_trained_policy_v1.npz")
```

**Privacy Guarantees:**
- Exported weights contain **only statistical patterns**, not raw evidence
- No file paths, usernames, IP addresses, or case identifiers in exports
- Transition probabilities are aggregated—individual sequences cannot be reconstructed
- Policy weights encode action preferences, not investigation specifics
- Exports are safe for sharing across teams or organizations without exposing protected information

**Recommended Workflow:**
1. Start new cases with pre-trained baseline models
2. Models refine during investigation based on analyst feedback
3. After case closure, export improved weights (optional)
4. Import aggregated knowledge into team's shared baseline

## Limitations

- **Windows-focused**: KAPE and many parsers target Windows artifacts
- **No memory forensics**: Volatility integration not implemented
- **Cold start**: World model and RL agent start with random initialization; accuracy improves after processing multiple investigations (or import pre-trained weights)
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
