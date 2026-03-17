# FORAI - Forensic AI Analysis Tool
(c) 2025 Shane D. Shook, PhD - All Rights Reserved

## What It Is

FORAI is a forensic analysis tool that:
- Collects Windows artifacts using KAPE
- Creates timelines using Plaso (log2timeline + psort)
- Stores events in SQLite for analysis
- Answers 12 standard forensic backgrounding questions
- Optionally uses local LLMs for follow-up analysis

## Architecture

```
Forensic Image (read-only)
        │
        ▼
┌───────────────────────────────────┐
│  Deterministic Extraction Layer   │
│  • KAPE artifact collection       │
│  • Plaso timeline parsing         │
│  • SQLite evidence database       │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Temporal Knowledge Graph         │  ← NEW: forensic_graph.py
│  Nodes: Process|File|Network|     │
│         Registry|User|Service     │
│  Edges: spawned_by|wrote_to|      │
│         precedes|anomalous_delta  │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  World Model Layer                │  ← NEW: world_model.py
│  • P(next_state | current_state)  │
│  • Anomaly scoring                │
│  • Causal plausibility            │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  RL Agent                         │  ← NEW: rl_agent.py
│  Actions: pivot|expand|flag_IOC|  │
│           request_LLM|mark_benign │
│  Rewards: anomaly confirmation,   │
│           analyst approval        │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Local LLM (Optional)             │
│  • llama-cpp-python (TinyLlama)   │
│  • Graph-grounded explanations    │
│  • Responses logged with hashes   │
└───────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────┐
│  Defensible Report                │
│  • Chain of custody logs          │
│  • LLM prompt/response hashes     │
│  • RL trajectory (what was seen)  │
│  • Model version on record        │
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

## Components

### Core (Existing)
- `FORAI.py` - Main analysis tool
- `eq_iq_regulator.py` - EQ/IQ balanced reward system (synced from BHSM)

### New Modules
- `forensic_graph.py` - Temporal knowledge graph with SQLite backend
- `world_model.py` - State transition prediction and anomaly scoring
- `rl_agent.py` - RL agent for investigation navigation
- `bhsm_advanced.py` - Advanced BHSM with temporal sequences, CognitiveMesh

## Installation

```bash
pip install -r requirements.txt
```

Required:
- Python 3.9+
- numpy, sqlite3, fpdf2, tqdm, psutil

Optional:
- llama-cpp-python (for local LLM)
- torch (for CognitiveMesh neural reasoning)
- kuzu (for native graph database)
- stable-baselines3 (for PPO-based RL)

External tools (Windows):
- KAPE.exe
- Plaso (log2timeline, psort)

## Usage

### Full Analysis (One Command)
```bash
python FORAI.py --case-id CASE001 --full-analysis --target-drive C: --chain-of-custody
```

### Answer All 12 Questions
```bash
python FORAI.py --case-id CASE001 --autonomous-analysis --report pdf
```

### Import Existing Plaso File
```bash
python FORAI.py --case-id CASE001 --plaso-file timeline.plaso
```

### Interactive Analysis
```bash
python FORAI.py --case-id CASE001 --interactive
```

### With Local LLM
```bash
python FORAI.py --case-id CASE001 --autonomous-analysis --llm-folder ./LLM
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

## What's Implemented vs Planned

| Component | Status |
|-----------|--------|
| KAPE integration | ✅ Working |
| Plaso parsing | ✅ Working |
| 12 standard questions | ✅ Working |
| Chain of custody | ✅ Working |
| Local LLM (llama-cpp) | ✅ Working |
| BHSM (basic) | ✅ Working |
| BHSM (advanced with temporal) | ✅ New module |
| Knowledge graph | ✅ New module |
| World model | ✅ New module |
| RL agent | ✅ New module |
| Ollama support | ❌ Not yet |
| Kuzu native graph | ❌ SQLite fallback |
| stable-baselines3 PPO | ❌ Simple policy gradient |

## File Structure

```
FORAI/
├── FORAI.py              # Main tool
├── eq_iq_regulator.py    # EQ/IQ reward balance
├── bhsm_advanced.py      # Advanced BHSM components
├── forensic_graph.py     # Temporal knowledge graph
├── world_model.py        # State prediction
├── rl_agent.py           # RL investigation agent
├── requirements.txt
└── README.md
```

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
