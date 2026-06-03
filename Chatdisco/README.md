<!--
  Chatdisco - AI Chat Forensics Tool
  Copyright (c) 2026 Shane D. Shook, PhD
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
  3. Neither the name of the author nor the names of contributors may be used
     to endorse or promote products derived from this software without specific
     prior written permission.

  THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
  THE AUTHOR ASSUMES NO LIABILITY FOR USE IN LEGAL, REGULATORY, OR
  INVESTIGATIVE PROCEEDINGS. ALL FORENSIC CONCLUSIONS REMAIN THE
  RESPONSIBILITY OF THE QUALIFIED EXAMINER.
-->

# Chatdisco

**AI Chat Forensics Tool**
*Copyright &copy; 2026 Shane D. Shook, PhD. All rights reserved.*

---

Chatdisco extracts and reconstructs AI chat sessions from memory dumps,
process dumps, network captures, and disk artifacts. It produces
CASE/UCO-format evidence bundles with full chain of custody documentation
including an embedded Software Bill of Materials (SBOM) listing every tool
version that processed the evidence.

---

## Table of Contents

1. [Background and Problem Statement](#1-background-and-problem-statement)
2. [Forensic Challenge](#2-forensic-challenge)
3. [What Chatdisco Recovers](#3-what-chatdisco-recovers)
4. [Architecture](#4-architecture)
5. [Supported AI Services](#5-supported-ai-services)
6. [TLS Key Recovery Waterfall](#6-tls-key-recovery-waterfall)
7. [Installation](#7-installation)
8. [CLI Reference and Examples](#8-cli-reference-and-examples)
9. [Chain of Custody](#9-chain-of-custody)
10. [Output Files](#10-output-files)
11. [References](#11-references)

---

## 1. Background and Problem Statement

### The Scale of AI Chat Adoption

AI conversational systems have achieved mainstream adoption at an
extraordinary pace. As of early 2026, ChatGPT alone serves over 800
million weekly active users, with more than 92% of Fortune 500 companies
holding ChatGPT licenses and over 7 million enterprise workplace seats
deployed [1]. Broader measures of the generative AI market show ChatGPT
commanding approximately 68% of global generative-AI web traffic, with
Gemini, Claude, Copilot, Perplexity, and Grok collectively accounting for
the remainder of a market that grew 76% year-over-year through late 2025
[2]. McKinsey's 2025 data found 78% of organizations using AI in at least
one business function and 71% regularly using generative AI [3].

In parallel with these cloud services, local AI deployments via tools
such as Ollama, LM Studio, Jan, and llama.cpp have proliferated, offering
users the ability to run capable large language models entirely
on-premises, with conversations stored in plaintext on local drives and
no cloud telemetry to subpoena.

### Why This Matters for Investigations

This ubiquity creates a new class of digital evidence. AI chat
conversations frequently contain:

- **Intellectual property disclosures** — employees pasting confidential
  source code, trade secrets, financial projections, or M&A strategy into
  cloud AI systems for drafting or analysis assistance.
- **Insider threat evidence** — queries that reveal intent, knowledge, or
  planning that would not otherwise appear in corporate communications.
- **Fraud and deception artefacts** — AI-assisted drafting of phishing
  content, false documentation, or fabricated communications.
- **Legal and regulatory exposure** — privileged legal strategy, regulated
  personal data, or export-controlled technical specifications disclosed
  to third-party AI systems in violation of applicable law or contractual
  obligation.
- **Harassment and misconduct** — AI-assisted communications constituting
  actionable conduct.
- **Criminal planning** — operational planning communicated to AI
  assistants, sometimes in the mistaken belief that such conversations
  are not retained or recoverable.

Despite this investigative relevance, no purpose-built forensic tool
existed to systematically acquire, reconstruct, and produce court-ready
documentation of AI chat activity. Commercial forensic platforms such as
Magnet AXIOM, Cellebrite UFED, and Oxygen Forensic Detective have begun
to incorporate AI artifact modules, but these typically target mobile
applications and disk artifacts, not memory-resident or network-layer
reconstruction.

### The Academic Gap

Early peer-reviewed forensic work on conversational AI artifacts
established that significant evidence exists across multiple storage
surfaces. Cho et al. (2025) performed a systematic case study across
ChatGPT, Gemini, Copilot, and Claude, demonstrating that browser-based
sessions leave recoverable artifacts in cache, IndexedDB, localStorage,
network logs, and system memory, and proposing a forensic investigation
framework for these services [4]. Parallel work on mobile platforms found
that ChatGPT and Copilot store conversation data in plaintext on both
Android and iOS, while Gemini relies primarily on cloud-side storage [5].
A study of the ChatGPT Windows application demonstrated that RAM
snapshots retained conversation evidence even after deletion from disk
[6]. None of these studies produced a practical tool that could be
deployed by a working examiner against a collected image or PCAP.

Chatdisco is the practical implementation of the investigative methodology
implied by this body of research.

---

## 2. Forensic Challenge

### Evidence Distribution Across Multiple Surfaces

A single AI chat session may leave traces simultaneously in:

| Surface | Persistence | Typical content |
|---------|-------------|-----------------|
| Process heap (live RAM) | Volatile | Full conversation, auth tokens, TLS keys |
| PCAP / network capture | Durable if captured | Complete API exchanges (encrypted) |
| TLS session keys | Volatile | Decrypt all captured traffic |
| Browser IndexedDB | Semi-persistent | Conversation history (ChatGPT, Claude) |
| Browser localStorage | Semi-persistent | Session state, partial conversation data |
| Browser cookies | Semi-persistent | Session tokens, authentication |
| Browser cache | Semi-persistent | API response bodies |
| Windows Prefetch (.pf) | Durable | Memory-mapped region content including TLS keys |
| pagefile.sys / swapfile.sys | Durable | Evicted heap pages, TLS key material |
| hiberfil.sys | Durable | Complete RAM snapshot at hibernation |
| Crash dumps | Durable | Process heap at crash time |
| App data files | Durable | Plaintext for local LLMs; encrypted for cloud apps |

The critical intersection is memory and network: the heap contains
session keys, and the PCAP contains the encrypted conversation. Neither
is sufficient alone. Together, they reconstruct the complete exchange.

### The TLS Problem

All major cloud AI services communicate exclusively over TLS 1.3, which
uses Perfect Forward Secrecy (PFS). The server's private key cannot
decrypt captured traffic. Decryption requires the per-session key
material generated by the client, which is written to an
`SSLKEYLOGFILE` by browsers and applications using NSS or BoringSSL [7].

This key material is ephemeral and volatile — it exists in process heap
memory during the session and may persist in pagefile or prefetch
residue afterwards. Recovering it is the central technical challenge of
AI chat network forensics. Chatdisco implements a five-stage key
recovery waterfall specifically to address this.

---

## 3. What Chatdisco Recovers

### Evidence Surfaces

| Input type | Primary engines | What is recovered |
|------------|----------------|-------------------|
| Raw memory dump (.raw, .lime, AVML) | bulk_extractor, Volatility 3 | Messages, tokens, keys, process context |
| Process dump (.dmp, .mdmp) | bulk_extractor, Volatility 3 | Heap content for targeted process |
| PCAP / pcapng | tshark, bulk_extractor | Reconstructed conversations from SSE streams |
| hiberfil.sys | bulk_extractor (after decompression) | Full RAM equivalent |
| pagefile.sys / swapfile.sys | bulk_extractor | Evicted pages, key material |
| Windows Prefetch directory | bulk_extractor (after MAM decompression) | TLS keys, heap residue |
| Crash dump (MEMORY.DMP) | bulk_extractor, Volatility 3 | Process state at crash |
| Chrome / Edge profile | Browser parsers | Cookies, IndexedDB, localStorage, history |
| Ollama data directory | Local LLM parser | Plaintext conversation JSON |
| LM Studio conversations | Local LLM parser | OpenAI-format conversation JSON |
| Jan threads | Local LLM parser | JSONL message files |
| llama.cpp server logs | Local LLM parser | Request/response log extraction |
| Evidence directory (from `collect`) | All engines | Full multi-surface reconstruction |

### Normalised Output

Every recovered artifact — regardless of source — is normalised into a
`ConversationRecord` containing:

- Service identification (ChatGPT, Claude, Gemini, Copilot, Ollama, etc.)
- Full message history with roles (user / assistant / system) and timestamps
- Session identity: username, email, conversation ID, session tokens
- Provenance: source type, file path, byte offset, extraction method
- Network context: IP addresses, stream ID, protocol, TLS metadata
- Confidence rating: HIGH / MEDIUM / LOW / TRACE
- Reconstruction notes documenting any gaps or assumptions

---

## 4. Architecture

Three third-party forensic engines are orchestrated by Chatdisco's
analysis pipeline:

```
Input artifact
      │
      ├─── bulk_extractor ──────────────────────────────────────
      │    Garfinkel (2013) [9]                                 │
      │    Byte-stream carving (no filesystem required):        │
      │    JSON fragments, URLs, JWTs, base64, x509 certs,     │
      │    cookie files, HTTP logs, TLS key labels,            │
      │    carved network packets                              │
      │                                                         │
      ├─── tshark (Wireshark) ─────────────────────────────────│
      │    Protocol-aware stream reconstruction:                │
      │    HTTP/2 HPACK decompression, TCP reassembly,         │
      │    SSE stream parsing, TLS decryption via keylog        │
      │    editcap --inject-secrets for key embedding [7]      │
      │                                                         │
      ├─── Volatility 3 ────────────────────────────────────────│
      │    Hale Ligh, Case, Levy, Walters (2014) [10]          │
      │    OS structure analysis: pstree, netscan,             │
      │    envars, cmdline, dumpfiles                          │
      │                                                         │
      └─── Chatdisco analysis pipeline ────────────────────────┘
                    │
                    ├─ TLS key resolver (5-stage waterfall)
                    ├─ SSE stream reconstructor (per-service parsers)
                    ├─ Browser artifact parsers (Chrome IndexedDB,
                    │  localStorage, cookies, network cache)
                    ├─ Local LLM parsers (Ollama, LM Studio, Jan,
                    │  llama.cpp)
                    ├─ ConversationRecord normalisation
                    └─ Output layer
                              ├─ conversations.json
                              ├─ case_bundle.jsonld (CASE/UCO)
                              ├─ chain_of_custody.json + SBOM
                              ├─ hash_manifest.json
                              ├─ examiner_log.json
                              └─ reports/report.html
```

### Why These Three Engines

**bulk_extractor** operates without parsing filesystem structures, making
it effective against fragmented, compressed, or encrypted inputs. It
processes inputs in parallel 16 MB pages and applies recursive
decompressor stages (zlib, LZMA, Base64, XPRESS Huffman) before applying
feature scanners. The 2022 refactor to C++17 yielded approximately 75%
throughput improvement [11]. For AI chat forensics, the `find` scanner
configured with TLS key log labels is the primary key recovery mechanism.

**tshark** is required because bulk_extractor lacks TCP session state and
HTTP/2 stream ID tracking. Accurate SSE stream reconstruction — where an
assistant response arrives as hundreds of incremental `data:` events
across a single HTTP/2 stream — requires protocol-aware reassembly that
only a full network stack can provide. TLS key injection via `editcap
--inject-secrets` embeds recovered keys into a working copy of the
pcapng, enabling Wireshark-compatible analysis and a clear audit trail.

**Volatility 3** provides the OS structural layer: process trees
associate captured network connections with specific browser PIDs; the
`envars` plugin locates `SSLKEYLOGFILE` paths set in process environment;
`dumpfiles` extracts process memory for targeted heap scanning.

### SBOM in Every Case Bundle

Every tool version is captured at startup and embedded in the chain of
custody record. This documents exactly what software, at what version,
processed a specific piece of evidence — a requirement for any
examination that may face adversarial challenge.

---

## 5. Supported AI Services

| Service | Detection method | Conversation source |
|---------|-----------------|-------------------|
| OpenAI ChatGPT | API endpoint, SSE schema, session cookie, sk-... key pattern | PCAP SSE, browser IndexedDB, Windows app |
| Anthropic Claude | API endpoint, SSE event types, sk-ant- key pattern | PCAP SSE, browser IndexedDB |
| Google Gemini | API endpoint, SSE schema, AIza key pattern | PCAP SSE, Google Takeout export |
| Microsoft Copilot | Endpoint, conversation structure, MUID cookie | PCAP WebSocket, browser |
| Perplexity | API endpoint, pplx- key pattern | PCAP SSE |
| xAI Grok | API endpoint, xai- key pattern | PCAP SSE |
| GitHub Copilot | Endpoint, ghu_/ghp_ token patterns | PCAP |
| Cursor | Endpoint pattern | PCAP |
| Ollama | localhost:11434, JSON response schema | PCAP (unencrypted), disk JSON |
| LM Studio | localhost:1234, OpenAI-compat schema | PCAP (unencrypted), disk JSON |
| Jan | JSONL thread files | Disk (~/jan/threads/) |
| llama.cpp | Server log parsing | Disk |
| Open WebUI | SQLite conversation tables | Disk (~/.ollama/ollama.db) |

---

## 6. TLS Key Recovery Waterfall

Chatdisco attempts the following in priority order, stopping at the first
successful recovery:

| Stage | Method | Notes |
|-------|--------|-------|
| 1 | Explicit `--keylog` parameter | User supplies pre-captured key file |
| 2 | `SSLKEYLOGFILE` env var → disk file | File read directly if still present |
| 3 | bulk_extractor `find` carve | TLS key labels in memory/disk scan output |
| 4 | Direct memory string scan | Python chunked read of target file |
| 5 | Prefetch files (.pf, AgGlFaultHistory.db) | Memory-mapped region content |

If no keys are recovered, Chatdisco proceeds without decryption.
Encrypted streams are classified `PCAP_ENCRYPTED` in the
`ConversationRecord` and fully documented in the chain of custody,
including all available metadata: SNI, server certificate fingerprint,
traffic volume, and connection timing.

Keys are injected into a **working copy** of the PCAP using `editcap
--inject-secrets tls,keylog.txt`. The original PCAP file is never
modified. The injected working copy path is recorded in the COC.

---

## 7. Installation

### Python package

```bash
pip install chatdisco
# or from source:
git clone https://github.com/example/chatdisco.git
cd chatdisco && pip install -e .
```

Requires Python 3.9+.

### Required third-party tools

All three are hard dependencies. Chatdisco will refuse to run without
them and will print a formatted dependency table with SBOM identifiers.

**bulk_extractor**
```bash
# Ubuntu/Debian
sudo apt install bulk-extractor

# macOS
brew install bulk_extractor

# Windows: signed binary at
# https://github.com/simsong/bulk_extractor/releases
```

**tshark + editcap** (ships with Wireshark)
```bash
# Ubuntu/Debian
sudo apt install tshark wireshark-common
sudo usermod -aG wireshark $USER   # for live capture

# macOS
brew install wireshark

# Windows: installer at https://www.wireshark.org/download.html
# Select "TShark" under command-line tools during installation
```

**Volatility 3**
```bash
pip install volatility3
# Symbol tables for Windows memory analysis:
# https://downloads.volatilityfoundation.org/volatility3/symbols/
```

See `docs/INSTALL.md` for platform-specific memory acquisition tools
(WinPmem, AVML, LiME, osxpmem) and optional tools (friTap for live
TLS key capture).

### Dependency check

```bash
python3 -c "
from chatdisco.core.dependency_check import (
    check_dependencies, print_dependency_table)
print_dependency_table(check_dependencies(require_collection=True))
"
```

---

## 8. CLI Reference and Examples

### `chatdisco analyze` — offline analysis

```
chatdisco analyze [OPTIONS]

Options:
  -i, --input PATH         Input: memory dump, process dump, PCAP,
                           disk image, or evidence directory  [required]
  -o, --output PATH        Output directory for analysis results  [required]
  -e, --examiner TEXT      Examiner name for chain of custody  [required]
  -c, --case-id TEXT       Case identifier  [required]
  --org TEXT               Examiner organisation
  --keylog PATH            TLS key log file (NSS/SSLKEYLOGFILE format)
  --memory PATH            Memory dump to pair with PCAP for key extraction
  --services TEXT          Comma-separated service filter (default: all)
                           e.g. openai,anthropic,ollama
  --report-format          html|json|all  [default: all]
  -v, --verbose            Verbose output
```

**Analyse a raw memory dump**

```bash
chatdisco analyze \
  --input /evidence/memory.raw \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Analyse a PCAP with an explicit TLS key log**

```bash
chatdisco analyze \
  --input /evidence/capture.pcapng \
  --keylog /evidence/tls-keys.log \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Analyse a PCAP paired with a memory dump (Chatdisco carves keys
from memory automatically)**

```bash
chatdisco analyze \
  --input /evidence/capture.pcapng \
  --memory /evidence/memory.raw \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Analyse a Chatdisco live collection evidence directory**

```bash
chatdisco analyze \
  --input /media/usb/CASE-2026-001 \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Analyse a hibernation file**

```bash
chatdisco analyze \
  --input C:/hiberfil.sys \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Analyse Windows Prefetch directory**

```bash
chatdisco analyze \
  --input "C:/Windows/Prefetch" \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

**Target specific services only**

```bash
chatdisco analyze \
  --input /evidence/memory.raw \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001" \
  --services "openai,anthropic,ollama"
```

**Target a process dump**

```bash
chatdisco analyze \
  --input /evidence/chrome_pid_4812.dmp \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

---

### `chatdisco collect` — live acquisition

**Must be run as Administrator (Windows) or root (Linux/macOS) on the
target system.** Follows the order of volatility: PCAP starts
immediately and runs throughout; memory is dumped before disk.

```
chatdisco collect [OPTIONS]

Options:
  -o, --output PATH        Output directory for collected artifacts  [required]
  -e, --examiner TEXT      Examiner name for chain of custody  [required]
  -c, --case-id TEXT       Case identifier  [required]
  --org TEXT               Examiner organisation
  --mode [full|triage|targeted]
                           Collection mode  [default: triage]
  --target-pids TEXT       Comma-separated PIDs (targeted mode)
  --pcap-duration INTEGER  Capture duration in seconds; 0=until stopped
                           [default: 300]
  --no-disk                Skip disk artifact collection
```

**Triage collection (5 min PCAP, AI app data, prefetch, process dumps)**

```bash
# Run on the target system as Administrator / root
chatdisco collect \
  --output /media/usb/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001" \
  --org "Shook Consulting" \
  --mode triage
```

**Full collection including RAM acquisition**

```bash
chatdisco collect \
  --output /media/usb/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001" \
  --mode full
```

**Targeted collection of specific PIDs (e.g., a known browser PID)**

```bash
chatdisco collect \
  --output /media/usb/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001" \
  --mode targeted \
  --target-pids 4812,7340
```

**Then analyse the collection from a forensic workstation**

```bash
chatdisco analyze \
  --input /media/usb/CASE-2026-001 \
  --output ./results/CASE-2026-001 \
  --examiner "S. D. Shook" \
  --case-id "CASE-2026-001"
```

---

## 9. Chain of Custody

Chatdisco's chain of custody model is designed for legal admissibility.
Every step is documented, every file is hashed, and all tooling is
identified with version precision.

### Intake hashing (before anything else)

The first action Chatdisco performs is cryptographic hashing of the
primary input before any analysis tool touches it. Three algorithms are
computed in a single buffered pass:

- **SHA-256** — primary evidential hash
- **SHA-1** — legacy compatibility
- **MD5** — legacy compatibility

For directories (evidence collections), a sorted manifest of all
contained files and their individual hashes is computed and itself
hashed. No analysis begins until this step is complete.

### `chain_of_custody.json`

Written immediately at intake, then updated with SBOM and TLS
resolution details at analysis completion. Contains:

```json
{
  "case_id": "CASE-2026-001",
  "examiner": "S. D. Shook",
  "org": "Shook Consulting",
  "tool_name": "Chatdisco",
  "tool_version": "0.1.0",
  "acquisition_timestamp": "2026-06-01T14:23:11Z",
  "examiner_system": "FORENSICS-WS-01",
  "examiner_platform": "Windows-11-10.0.26100",
  "input_path": "/evidence/memory.raw",
  "input_type": "MEMORY_DUMP",
  "input_hash": {
    "sha256": "a3f4c...",
    "sha1":   "8d2e1...",
    "md5":    "b1c7a...",
    "size_bytes": 17179869184
  },
  "notes": "",
  "sbom": [
    {
      "name": "bulk_extractor",
      "version": "Bulk Extractor version 2.1.1",
      "path": "/usr/bin/bulk_extractor",
      "required": true,
      "purpose": "Byte-stream carving: JSON, URLs, base64, x509, cookies...",
      "sbom_id": "pkg:generic/bulk_extractor",
      "type": "binary"
    },
    {
      "name": "tshark",
      "version": "TShark (Wireshark) 4.4.3",
      "path": "/usr/bin/tshark",
      "required": true,
      "purpose": "Network protocol dissection: HTTP/2, SSE reconstruction...",
      "sbom_id": "pkg:generic/wireshark",
      "type": "binary"
    },
    {
      "name": "editcap",
      "version": "Editcap (Wireshark) 4.4.3",
      "path": "/usr/bin/editcap",
      "required": true,
      "purpose": "Inject TLS secrets into pcapng for decryption",
      "sbom_id": "pkg:generic/wireshark",
      "type": "binary"
    },
    {
      "name": "volatility3",
      "version": "2.11.0",
      "required": true,
      "purpose": "Memory structure analysis: processes, network, registry",
      "sbom_id": "pkg:pypi/volatility3",
      "type": "python-package"
    }
  ]
}
```

### `hash_manifest.json`

Produced after analysis is complete. Contains SHA-256 hashes of every
output file. The manifest JSON itself is then hashed and the hash
appended to the manifest, making tampering detectable.

```json
{
  "chatdisco_version": "0.1.0",
  "manifest_created": "2026-06-01T14:47:33Z",
  "case_id": "CASE-2026-001",
  "source_evidence": {
    "path": "/evidence/memory.raw",
    "sha256": "a3f4c...",
    "sha1":   "8d2e1...",
    "md5":    "b1c7a...",
    "size_bytes": 17179869184
  },
  "output_files": [
    {
      "path": "conversations.json",
      "sha256": "c9d2e...",
      "size_bytes": 284110
    },
    {
      "path": "case_bundle.jsonld",
      "sha256": "f1a8b...",
      "size_bytes": 891204
    }
  ],
  "file_count": 12,
  "sbom": [],
  "manifest_sha256": "7e3f1..."
}
```

### `examiner_log.json`

An append-only timestamped log of every significant action taken during
analysis. Documents when each engine was invoked, what input was
provided, what was produced, and any warnings or exceptions.

### `case_bundle.jsonld`

CASE/UCO JSON-LD output [12] linking every extracted artifact to:

- The investigation record (case ID, examiner)
- The source evidence node (with hashes)
- The analysis action (tool, timestamp, parameters)
- The SBOM tool nodes (one per dependency)
- TLS resolution record (method, key count, keyed PCAP path)
- Each `ConversationRecord` (service, messages, identity, network context)

This format is the output of choice for court filings, cross-tool
interoperability, and regulatory reporting. CASE/UCO was developed in
collaboration with the Netherlands Forensic Institute (NFI) and is in
active use by government and law enforcement agencies internationally
[13].

### Live collection manifest

During `chatdisco collect`, an `acquisition_manifest.json` is written
in real-time, updated after each artifact is acquired. Each entry
records the artifact type, acquisition method, SHA-256/SHA-1/MD5, size,
and timestamp. The manifest is re-written after every artifact — so if
collection is interrupted, the partial manifest accurately reflects what
was acquired before interruption.

### Evidence integrity principles

| Principle | Implementation |
|-----------|---------------|
| Hash before analysis | Intake hashing is the first action, before any engine runs |
| Original files never modified | Working copies made for TLS injection; sources are read-only |
| SBOM in every case | All tool versions captured at startup and embedded in COC |
| Real-time manifest | Acquisition manifest updated after each artifact in `collect` |
| Self-hashing manifest | `hash_manifest.json` contains its own SHA-256 |
| Full provenance chain | CASE/UCO links every artifact to source, tool, and action |

---

## 10. Output Files

```
output_directory/
├── conversations.json        ← Normalised ConversationRecords (all sources)
├── case_bundle.jsonld        ← CASE/UCO JSON-LD evidence bundle
├── chain_of_custody.json     ← COC record with full SBOM
├── hash_manifest.json        ← SHA-256 of all output files (self-hashed)
├── examiner_log.json         ← Append-only action log with timestamps
├── evidence/
│   └── conversations.json    ← Intermediate per-stage conversations
├── reports/
│   └── report.html           ← Human-readable investigation report
└── work/                     ← Working files (not evidence; internal use)
    ├── be/                   ← bulk_extractor feature files
    ├── volatility/           ← Volatility plugin output
    └── tls/                  ← TLS key log, keyed PCAP working copy
```

---

## 11. Third-Party Tools: References and Licenses

Chatdisco is a Python orchestration layer that invokes or imports the
following third-party tools. Each is used as an external process or
imported library; Chatdisco does not modify or redistribute any of
these tools' source code. Exact versions of all tools present at
analysis time are captured in the `chain_of_custody.json` SBOM.

Compliance note: tshark/Wireshark and LiME are licensed under
GPL-2.0-or-later. Chatdisco invokes both exclusively as external
processes (subprocess, not linked code), so the GPL distribution
requirements do not extend to Chatdisco itself. Volatility 3 is
imported as a Python library and is licensed under the Volatility
Software License (VSL v1.0), which requires that any additions or
modifications be made publicly available. Chatdisco makes no
modifications to Volatility internals.

---

### Required runtime tools

**bulk_extractor**
- Author: Simson L. Garfinkel, Naval Postgraduate School / Digital
  Corpora Project
- License: **MIT License**
  https://github.com/simsong/bulk_extractor/blob/main/LICENSE
- Source: https://github.com/simsong/bulk_extractor
- Releases: https://github.com/simsong/bulk_extractor/releases
- Role in Chatdisco: byte-stream carving of JSON fragments, URLs,
  JWTs, x509 certificates, cookie material, network packets, and
  TLS key log labels from memory dumps, PCAP, and disk artifacts.
- Primary citation: Garfinkel, S. L. "Digital Media Triage with Bulk
  Data Analysis and bulk_extractor." *Computers and Security*, 32:
  56-72, 2013. https://doi.org/10.1016/j.cose.2012.09.011
  Full text: https://simson.net/clips/academic/2013.COSE.bulk_extractor.pdf
- Update citation: Garfinkel, S. & Stewart, J. "Sharpening Your Tools:
  Updating bulk_extractor for the 2020s." arXiv:2208.01639, 2022.
  https://arxiv.org/pdf/2208.01639

---

**tshark** (part of Wireshark)
- Authors: Gerald Combs and the Wireshark contributors
- Copyright: Copyright 1998-2026 Gerald Combs and contributors
- License: **GNU General Public License v2.0 or later (GPL-2.0-or-later)**
  https://github.com/wireshark/wireshark/blob/master/COPYING
  Full GPL-2.0 text: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
- Source: https://gitlab.com/wireshark/wireshark
  Mirror: https://github.com/wireshark/wireshark
- Download: https://www.wireshark.org/download.html
- Role in Chatdisco: HTTP/2 frame dissection with HPACK header
  decompression, TCP stream reassembly with retransmission handling,
  SSE stream reconstruction, TLS decryption via keylog file.

**editcap** (part of Wireshark — same license as tshark above)
- License: **GPL-2.0-or-later** (same as tshark)
- Role in Chatdisco: injects TLS session secrets into pcapng working
  copy via `editcap --inject-secrets tls,keylog.txt`. The original
  PCAP is never modified.

---

**Volatility 3**
- Authors: The Volatility Foundation and contributors
- Copyright: Copyright 2019-2026 Volatility Foundation and contributors
- License: **Volatility Software License v1.0 (VSL-v1.0)**
  — a source-available license requiring that additions and
  modifications be publicly distributed; permits forensic use without
  restriction.
  Full text: https://www.volatilityfoundation.org/license/vsl-v1.0
  https://github.com/volatilityfoundation/volatility3/blob/stable/LICENSE.txt
- Source: https://github.com/volatilityfoundation/volatility3
- PyPI: https://pypi.org/project/volatility3/
- Docs: https://volatility3.readthedocs.io/
- Role in Chatdisco: OS structure analysis from memory images —
  process trees (pstree), network connections (netscan), environment
  variables (envars), command lines (cmdline), and process memory
  extraction (dumpfiles).
- Primary citation: Hale Ligh, M., Case, A., Levy, J., & Walters, A.
  *The Art of Memory Forensics: Detecting Malware and Threats in
  Windows, Linux, and Mac Memory.* Wiley, 2014.
  ISBN: 978-1-118-82509-3.
  https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098
  https://volatilityfoundation.org/the-volatility-framework/

---

### Optional tools (enhance capability)

**WinPmem** (Windows physical memory acquisition)
- Authors: Velocidex Enterprises (originally developed at Google)
- License: **Apache License 2.0**
  https://github.com/Velocidex/WinPmem/blob/master/README.md
  Full text: https://www.apache.org/licenses/LICENSE-2.0
- Source: https://github.com/Velocidex/WinPmem
- Releases (signed binaries): https://github.com/Velocidex/WinPmem/releases
- Role in Chatdisco: Windows RAM acquisition during `chatdisco collect`.
  Supports Win7–Win11, x86+x64, three independent reading methods.

---

**AVML** — Acquire Volatile Memory for Linux
- Authors: Microsoft Corporation
- License: **MIT License**
  https://github.com/microsoft/avml/blob/main/LICENSE
- Source: https://github.com/microsoft/avml
- Releases: https://github.com/microsoft/avml/releases
- Role in Chatdisco: Linux RAM acquisition during `chatdisco collect`.
  Preferred over LiME — userland tool, no kernel module required,
  no prior knowledge of target OS distribution needed.

---

**LiME** — Linux Memory Extractor
- Authors: 504ensics Labs (Joe Sylve and contributors)
- License: **GNU General Public License v2.0 (GPL-2.0)**
  https://github.com/504ensicsLabs/LiME/blob/master/LICENSE
  Full text: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
- Source: https://github.com/504ensicsLabs/LiME
- Role in Chatdisco: Linux RAM acquisition fallback via kernel module;
  also supported natively as an input format by Volatility 3.
  First tool to allow full memory capture from Android devices.

---

**YARA** — Pattern matching engine
- Author: Victor Alvarez, VirusTotal
- License: **BSD 3-Clause License**
  https://github.com/VirusTotal/yara/blob/master/LICENSE
- Source: https://github.com/VirusTotal/yara
- PyPI (yara-python): https://pypi.org/project/yara-python/
- Role in Chatdisco: AI service identification patterns
  (`chatdisco_ai_services.yar`) applied to memory dumps, process
  dumps, and disk artifacts. Detects API endpoints, session tokens,
  API keys, SSE response structures, and TLS key log material
  for all supported AI services.
- Note: YARA itself is in maintenance mode; successor project
  YARA-X (Rust rewrite, also BSD-3-Clause) available at
  https://github.com/VirusTotal/yara-x

---

**friTap** — Live TLS key extraction via Frida (optional)
- Authors: Daniel Baier et al., Fraunhofer FKIE
  (Fraunhofer Institute for Communication, Information Processing
  and Ergonomics)
- License: **GNU General Public License v3.0 (GPL-3.0-only)**
  https://github.com/fkie-cad/friTap/blob/main/LICENSE
  Full text: https://www.gnu.org/licenses/gpl-3.0.html
- Source: https://github.com/fkie-cad/friTap
- PyPI: https://pypi.org/project/friTap/
- Depends on: Frida dynamic instrumentation framework
  (https://frida.re, LGPL-2.1+)
- Role in Chatdisco: live TLS key extraction from running browser/AI
  processes during `chatdisco collect` when `SSLKEYLOGFILE` is not
  set. Hooks NSS, BoringSSL, OpenSSL, GnuTLS, and Schannel.
  Keys are written to a standard SSLKEYLOGFILE for injection via
  editcap.
- Citation: Baier, D. et al. "friTap: Decrypting TLS on the Fly."
  Fraunhofer FKIE / lolcads tech blog, August 2022.
  https://lolcads.github.io/posts/2022/08/fritap/

---

### Python dependencies

All Python packages are installed via `pip install chatdisco` and
listed in `requirements.txt`. Key packages and their licenses:

| Package | License | Role |
|---------|---------|------|
| volatility3 | VSL-v1.0 | Memory structure analysis |
| click | BSD-3-Clause | CLI framework |
| rich | MIT | Terminal formatting |
| jinja2 | BSD-3-Clause | HTML report templating |
| dpkt | BSD-3-Clause | Supplemental packet parsing |
| yara-python | BSD-3-Clause | YARA pattern matching |
| scapy | GPL-2.0 | Supplemental packet construction |
| python-dateutil | Apache-2.0 | Timestamp handling |
| pytz | MIT | Timezone handling |
| orjson | Apache-2.0 / MIT | High-performance JSON parsing |
| pycryptodome | BSD-2-Clause | Cryptographic operations |
| fritap | GPL-3.0 | Live TLS key extraction (optional) |

Full license texts are available via `pip show <package>` or at
https://pypi.org for each package.

---

## 12. Academic and Standards References

[1] OpenAI. "ChatGPT Usage and Adoption Patterns at Work."
    OpenAI Business Guides and Resources, 2025.
    https://openai.com/business/guides-and-resources/chatgpt-usage-and-adoption-patterns-at-work/

[2] Elfsight. "Chatbot Statistics: AI Chatbot Market Share and Trends."
    April 2026. Data sourced from Similarweb December 2025 analysis.
    https://elfsight.com/blog/chatbot-statistics-and-trends/

[3] McKinsey & Company. "The State of AI in 2025." McKinsey Global
    Survey on AI, 2025. Referenced in Panto.ai ChatGPT Statistics,
    2026. https://www.getpanto.ai/blog/chatgpt-statistics

[4] Cho, K., Park, Y., Kim, J., Kim, B., & Jeong, D.
    "Conversational AI Forensics: A Case Study on ChatGPT, Gemini,
    Copilot, and Claude." *Forensic Science International: Digital
    Investigation*, Vol. 52, 301855, March 2025.
    https://doi.org/10.1016/j.fsidi.2024.301855
    https://www.sciencedirect.com/science/article/abs/pii/S2666281724001823
    Preprint (SSRN): https://ssrn.com/abstract=4888688

[5] Nasir, A. et al. "Forensic Analysis and Privacy Implications of
    LLM Mobile Apps: A Case Study of ChatGPT, Copilot, and Gemini."
    *Forensic Science International: Digital Investigation*, 2025.
    https://www.sciencedirect.com/science/article/pii/S2666281725001131

[6] "Digital Forensic Investigation of the ChatGPT Windows
    Application." arXiv:2505.23938, May 2025.
    https://arxiv.org/abs/2505.23938
    https://arxiv.org/pdf/2505.23938

[7] Wireshark Foundation. "TLS — Wireshark Wiki." 2024.
    https://wiki.wireshark.org/TLS
    Stevens, D. "Decrypting TLS Streams With Wireshark: Part 3."
    Didier Stevens Blog, January 2021.
    https://blog.didierstevens.com/2021/01/11/decrypting-tls-streams-with-wireshark-part-3/
    NETRESEC. "SSLKEYLOGFILE Network Forensics." 2024.
    https://www.netresec.com/?page=Blog&tag=SSLKEYLOGFILE

[8] Magnet Forensics. "Forensic Analysis of Prefetch Files in Windows."
    June 2025.
    https://www.magnetforensics.com/blog/forensic-analysis-of-prefetch-files-in-windows/
    Salvation Data. "Prefetch Files in Windows Forensics."
    September 2025.
    https://www.salvationdata.com/knowledge/prefetch-files/
    Forensic Focus. "Windows Prefetch." Forum discussion, 2009.
    https://www.forensicfocus.com/forums/general/windows-prefetch/

[9] Garfinkel, S. L. "Digital Media Triage with Bulk Data Analysis and
    bulk_extractor." *Computers and Security*, 32: 56-72, 2013.
    https://doi.org/10.1016/j.cose.2012.09.011
    Full text: https://simson.net/clips/academic/2013.COSE.bulk_extractor.pdf

[10] Garfinkel, S. & Stewart, J. "Sharpening Your Tools: Updating
     bulk_extractor for the 2020s." arXiv:2208.01639, August 2022.
     Communications of the ACM, August 2023.
     https://arxiv.org/pdf/2208.01639

[11] Hale Ligh, M., Case, A., Levy, J., & Walters, A. *The Art of
     Memory Forensics: Detecting Malware and Threats in Windows, Linux,
     and Mac Memory.* Wiley, 2014. ISBN: 978-1-118-82509-3.
     https://memoryanalysis.net/amf/
     https://www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098

[12] Casey, E., Barnum, S., Griffith, R., Snyder, J., van Beek, H., &
     Nelson, A. "The Evolution of Expressing and Exchanging
     Cyber-Investigation Information in a Standardized Form." NIST, 2018.
     https://www.nist.gov/publications/evolution-expressing-and-exchanging-cyber-investigation-information-standardized-form
     CASE Ontology: https://caseontology.org/
     CASE specification: https://caseontology.org/resources/case_design_document.html
     CASE/UCO GitHub: https://github.com/casework/CASE

[13] Casey, E., Back, S., & Barnum, S. "Advancing Coordinated
     Cyber-Investigations and Tool Interoperability Using a Community
     Developed Specification Language." *Forensic Science International:
     Digital Investigation*, 2017.
     https://doi.org/10.1016/j.diin.2017.01.003
     https://www.sciencedirect.com/science/article/abs/pii/S1742287617301007

[14] Alvarez, V. "YARA: The Pattern Matching Swiss Knife."
     VirusTotal, 2013–2025.
     https://virustotal.github.io/yara/
     https://github.com/VirusTotal/yara

[15] Baier, D. et al. "friTap: Decrypting TLS on the Fly."
     Fraunhofer FKIE, 2022.
     https://lolcads.github.io/posts/2022/08/fritap/
     https://github.com/fkie-cad/friTap

---

## Legal Notice

Chatdisco is a digital forensics tool intended for use by qualified
examiners in lawful investigations conducted under appropriate
authorisation. Use only on systems and data for which you have proper
legal authority. The author makes no representation as to the
admissibility of output in any legal or regulatory proceeding; all
forensic conclusions remain the responsibility of the qualified examiner.

Third-party tools referenced and used by Chatdisco are the property of
their respective authors and are governed by their own licenses as
listed in Section 11. Use of those tools is subject to their respective
license terms.

*Copyright &copy; 2026 Shane D. Shook, PhD. All rights reserved.*
