# Security Audit Toolkit

A comprehensive collection of security auditing and forensic analysis tools developed by Shane Shook (c) 2025.

## Overview

This repository contains various PowerShell and Python scripts designed to automate security assessments, incident response, and forensic analysis across different platforms and cloud services. It also includes advanced AI-powered cognitive architectures for enhanced forensic analysis and memory-augmented intelligence systems.

## Tool Categories

### Software Intellectual Property Analysis
Advanced forensic code similarity analysis for IP theft detection:

* **[SIPCompare.py](SIPCompare/SIPCompare.py)** - SIPCompare v2.0: Advanced Forensic Code Similarity Analysis Tool
  - Multi-dimensional analysis combining token-based, semantic, structural, and control-flow similarity
  - Obfuscation resistance with advanced normalization techniques
  - Industry-standard Type 1-4 clone detection
  - Cross-language support for 15+ programming languages
  - Statistical significance testing with confidence intervals
  - Forensic-quality reporting with evidence packages
  - Parallel processing for large repositories

### WebGuard - Adaptive Cybersecurity Web Service Protection Agent
Neuromorphic cybersecurity system combining Hebbian learning with reinforcement learning:

* **[WebGuard/](WebGuard/)** - Adaptive Cybersecurity Web Service Protection Agent
  - **Neuromorphic Defense** with Reinforced Hebbian Learning architecture
  - **Bidirectional Hebbian Learning** with real-time reinforcement signals
  - **Persistent Semantic Index (PSI)** for unlimited time horizon memory
  - **Mesh-Mediated Cognition** creating emergent defensive behavior
  - **Local, autonomous learning** without cloud dependencies
  - **Cross-platform support** for IIS, Apache, and NGINX web servers
  - **Embodied defense** that actively modifies attack surfaces
  - **Operator integration** with real-time feedback loops
  - Represents a new class of cognitive, self-adaptive cybersecurity system
  - Transforms endpoint protection from static defense to dynamic, learning organism

### Bi-directional Hebbian Synaptic Memory (BHSM) Project
Advanced biologically-inspired cognitive architecture for AI systems:

* **[BHSM.py](BHSM/BHSM.py)** - Bidirectional Hebbian Memory System with synaptic plasticity
  - Biologically-inspired cognitive architecture with adaptive memory formation
  - Reward-gated Hebbian learning with eligibility traces and memory consolidation
  - Cognitive Mesh Neural Network (CMNN) for distributed reasoning
  - PSI (Persistent Semantic Index) for long-term declarative memory
  - BDH (Bidirectional Hebbian Memory) for procedural memory and learned patterns
  - Self-regulation mechanisms with empathy and arrogance factors
  - Integration capabilities with existing LLM architectures (TinyLLaMA demonstrated)
* **[tinyllama_bhsm_integration.py](BHSM/tinyllama_bhsm_integration.py)** - TinyLLaMA integration with BHSM memory systems
* **[tests/](BHSM/tests/)** - Comprehensive test suite with cognitive architecture demos and performance reports

### Cloud Services Reports (CSR)
Scripts to automate collection of cloud services activities for security posture assessment and incident triage:

* **[AzUAR.ps1](CRA/AzUAR.ps1)** - PowerShell script to pull Azure Active Directory authentication activities by user(s)  
  *Requires PowerShell 7 and .NET 8*

* **[o365UAR.ps1](CRA/o365UAR.ps1)** - PowerShell script to pull Unified Audit Logs from Office 365 by user(s)

* **[o365AppsChanges.ps1](AdminCreds/o365AppsChanges.ps1)** - PowerShell script to pull changes made to applications by user(s)

* **[GUAR.py](CRA/GUAR.py)** - Python script to pull Unified Activity Logs from Google Workspace by user(s)

### Cyber Risk Assessments (CRA)
Scripts to automate collection of security posture information:

* **[CRA_Win.ps1](CRA/CRA_Win.ps1)** - Windows assessment (run on each host)
* **[CRA_LM.sh](CRA/CRA_LM.sh)** - Linux & Mac assessment (run on each host)  
* **[CRA_AD.ps1](CRA/CRA_AD.ps1)** - Active Directory assessment (for on-premise AD, run only once from any domain-connected host)
* **[NEW_CRA_Win.ps1](CRA/NEW_CRA_Win.ps1)** - Updated Windows cyber risk assessment script
* **[GBCRA_Win.ps1](CRA/GBCRA_Win.ps1)** - Group-based cyber risk assessment for Windows

### Cyber Breach Assessment (CBA)
Scripts to automate collection of security posture information for incident triage:

* **[CBA_Win.ps1](CRA/CBA_Win.ps1)** - Cyber Breach Assessment script for Windows systems
* **[CBT.ps1](CRA/CBT.ps1)** - Cyber Breach Triage script to quickly collect active communicating processes for incident triage

### FORAI - Forensic AI Analysis Tool
Comprehensive digital forensic analysis platform with multi-LLM AI integration:

* **[FORAI.py](FORAI/FORAI.py)** - Complete Forensic Analysis Platform (6,700+ lines)
  - **Complete Forensic Workflow**: Target Drive → KAPE → log2timeline → psort → SQLite → AI Analysis
  - **Plaso File Import**: Direct import of existing .plaso files (skips KAPE + log2timeline)
  - **ML-Enhanced Analysis**: Machine learning behavioral pattern detection with 95% confidence
  - **Autonomous Analysis**: Automatically answers all 12 standard forensic questions
  - **Multi-LLM Support**: TinyLLaMA (local), OpenAI GPT-4, Anthropic Claude
  - **Advanced Evidence Processing**: SHA256 validation, chain of custody, timeline analysis
  - **Threat Detection**: Custom keywords files for IOC flagging and threat hunting
  - **Time Filtering**: Date range analysis and temporal correlation
  - **Professional Reporting**: Court-ready JSON/PDF reports with executive summaries
  - **Flexible Deployment**: Local LLM for air-gapped environments or cloud APIs

#### Key FORAI Capabilities:
- **🚀 End-to-End Analysis**: Single command complete forensic investigation
- **🤖 Autonomous LLM Analysis**: AI-powered evidence interpretation and reporting
- **🔍 Advanced Threat Hunting**: Custom keywords, IOCs, and temporal analysis
- **📊 Flexible Evidence Search**: Natural language queries with time filtering
- **📋 12 Standard Questions**: Computer ID, hardware, users, USB devices, network activity, anti-forensics, etc.
- **🔒 Chain of Custody**: Legal admissibility with complete audit trails
- **⚡ Multi-Provider LLM**: Local privacy or cloud AI with fallback support

#### Usage Examples:
```bash
# Complete autonomous analysis with local LLM
python FORAI.py --case-id CASE001 --autonomous-analysis --llm-folder "D:\FORAI\LLM" --report pdf

# Import existing plaso file with ML-enhanced analysis
python FORAI.py --case-id CASE001 --plaso-file "timeline.plaso" --autonomous-analysis --report pdf

# OpenAI GPT-4 powered investigation
python FORAI.py --case-id CASE001 --autonomous-analysis --llm-api-provider openai --llm-model "gpt-4"

# Threat hunting with custom IOCs
python FORAI.py --case-id CASE001 --full-analysis --target-drive C: --keywords-file threat_indicators.txt

# Time-filtered analysis
python FORAI.py --case-id CASE001 --search "malware execution" --date-from 20241201 --date-to 20241215
```

### Administrative Credentials & Risk Management
Tools for managing administrative access and assessing security risks:

* **[AdminCreds.py](AdminCreds/AdminCreds.py)** - Python-based administrative credentials management
* **[AdminCreds.ps1](AdminCreds/AdminCreds.ps1)** - PowerShell administrative credentials management
* **[UserRisk.ps1](CRA/UserRisk.ps1)** - User risk assessment script
* **[UserRisk_JITA.ps1](CRA/UserRisk_JITA.ps1)** - Just-in-time access user risk assessment
* **[PermissionRisk.ps1](AdminCreds/PermissionRisk.ps1)** - Permission risk analysis script
* **[AzRoleChanges.ps1](AdminCreds/AzRoleChanges.ps1)** - Azure role changes monitoring script
* **[AppSecretsChanges_JITA.ps1](AdminCreds/AppSecretsChanges_JITA.ps1)** - Application secrets changes monitoring (JITA)
* **[AppSecretsChanges_persistent.ps1](AdminCreds/AppSecretsChanges_persistent.ps1)** - Application secrets changes monitoring (persistent)

### ADVulture - Active Directory Vulnerability Intelligence
Advanced Active Directory security posture analysis with Graph Neural Networks:

* **[ADVulture/](ADVulture/)** - Active Directory Vulnerability Intelligence Platform
  - **Empirical Posture Analysis** through Graph Neural Networks and Markov Modelling
  - **Temporal Depth**: Fuses 30–90 days of authentication/authorization event logs for empirically weighted risk analysis
  - **Gradient-Ranked Remediation**: Computes partial derivatives of Tier 0 compromise probability to produce mathematically ordered remediation priorities
  - **Unified Risk Taxonomy**: Models six risk classes simultaneously (AuthN hygiene, AuthZ structure/behavior, privilege escalation, delegation overrides, AI agent surfaces)
  - **Regime Classification**: Identifies ordered, critical, or chaotic security posture states inspired by Sakana AI's Digital Ecosystems research
  - **Standalone Operation**: No dependency on BloodHound, Neo4j, or external graph databases
  - **Multi-Source Collection**: LDAP enumeration, Windows Event Logs, Entra ID/AAD, ADFS Federation, OAuth/PIM logs
  - Extends BloodHound paradigm with temporal analysis and mathematical remediation ranking

### MCR - Model Context Routing
Enterprise AI attention management infrastructure for reliable workflows:

* **[MCR/](MCR/)** - Model Context Routing Architecture
  - **Attention Maintenance**: Persistent context plane across arbitrary workflow depth and duration
  - **Deterministic Context Reconstruction**: Auditable and reproducible decision context
  - **Policy-Governed SLAs**: Define and enforce cost, latency, and output consistency requirements
  - **Defendable Reliability**: Exact replay capability for AI decision auditing
  - **Token Reduction**: 30-65% token savings through relevance-governed context reconstruction
  - **NATS/JetStream Backend**: Durable event-driven context persistence
  - **Protocol Agnostic**: Complements MCP, REST APIs, and CLI-based agent orchestration
  - Solves the fundamental enterprise AI problem: maintaining attention across stateless model invocations

### ModernCRA - Modern Cyber Risk Assessment
Comprehensive cyber risk assessment toolkit for cloud identity and MDR platforms:

* **[ModernCRA/](ModernCRA/)** - Modern Cyber Risk Assessment Platform
  - **[Entra/](ModernCRA/Entra/)** - Microsoft Entra ID Security Assessment
    - **[entra_assessment.py](ModernCRA/Entra/entra_assessment.py)** - Comprehensive Entra ID security posture analysis
    - **[setup_assessment_account.ps1](ModernCRA/Entra/setup_assessment_account.ps1)** - PowerShell script to configure assessment service accounts
    - **[REPORT_PROMPT.md](ModernCRA/Entra/REPORT_PROMPT.md)** - AI prompt template for generating Entra assessment reports
    - Analyzes authentication hygiene, MFA enrollment, privileged roles, and identity risks
    - Supports Graph API integration for comprehensive tenant analysis
  - **[MDR/](ModernCRA/MDR/)** - Managed Detection and Response Assessment
    - **[s1queries.txt](ModernCRA/MDR/s1queries.txt)** - SentinelOne Singularity XDR search queries organized by risk level (LVL1-5)
    - **[AnalysisPrompt.txt](ModernCRA/MDR/AnalysisPrompt.txt)** - AI prompt template for generating MDR assessment reports from query exports
    - Risk categories: Data Transfer (LVL1), User Activity (LVL2), Network (LVL3), Service Config (LVL4), Build Posture (LVL5)
    - Queries adaptable to CrowdStrike and other SIEM platforms
    - Professional reporting with OSINT correlation and remediation roadmaps

### PLoc - Physical Location to Shodan Scanner
Reconnaissance tool for discovering internet-connected devices near a physical address:

* **[PLoc/](PLoc/)** - Physical Location to Shodan Scanner
  - **Address Geocoding**: Converts physical addresses to latitude/longitude via Nominatim (OpenStreetMap)
  - **Shodan Integration**: Discovers nearby internet-connected devices using geographic coordinates
  - **BAS/BMS Filtering**: Optional filter for Building Automation and Building Management Systems
  - **Reverse DNS Lookup**: PTR record resolution for IP-to-hostname mapping
  - **RDAP/WHOIS Cross-Reference**: IP registrant details for property management and tenant identification
  - **TLS Certificate Analysis**: Extract CN, SANs, Organization, and emails from HTTPS services
  - **Certificate Transparency**: Query crt.sh for historical certificate issuance
  - **SecurityTrails Integration**: Optional domain intelligence lookup
  - **Correlation Analysis**: Confidence-scored associations between physical address and organizations
  - **Business Registration Lookup**: Query OpenCorporates for company registration details
  - **Building Management Detection**: Identify building management vs tenant companies
  - **JSON Export**: Timestamped JSON output for further analysis

### Chatdisco - AI Chat Forensics Tool
Extract and reconstruct AI chat sessions from memory dumps, network captures, and disk artifacts:

* **[Chatdisco/](Chatdisco/)** - AI Chat Forensics Tool
  - **Multi-Surface Recovery**: RAM dumps, process dumps, PCAPs, hiberfil.sys, pagefile.sys, Prefetch files
  - **CASE/UCO Output**: Court-admissible JSON-LD evidence bundles with full chain of custody
  - **SBOM Documentation**: Every tool version embedded in chain of custody for reproducibility
  - **TLS Key Recovery Waterfall**: 5-stage key recovery for encrypted traffic decryption
  - **Supported Services**: ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, GitHub Copilot, Cursor
  - **Local LLM Support**: Ollama, LM Studio, Jan, llama.cpp conversation recovery
  - **Browser Artifact Parsing**: Chrome/Edge IndexedDB, localStorage, cookies, network cache
  - **Three-Engine Architecture**: bulk_extractor (carving), tshark (protocol reconstruction), Volatility 3 (memory analysis)
  - **Live Collection Mode**: Triage, full, or targeted acquisition with real-time manifest
  - **Professional Reporting**: HTML reports with Jinja2 templating

### BAI - Browser Audit Inventory
Browser extension plug-in for AiTM and Infostealer evidence collection (requires Developer mode):

* **[BAI/](BAI/)** - Browser Audit Inventory v0.9.0
  - **Browser Extension**: Load as unpacked extension with Developer mode enabled
  - **AiTM Phishing Detection**: Identify Adversary-in-the-Middle attack artifacts via proxy settings, performance timing (redirects), WebAuthn capabilities, and cookies
  - **Infostealer Assessment**: Evaluate browser data exposure including localStorage, sessionStorage, IndexedDB (structure and full dump), and cache storage
  - **29 Artifact Collectors** in 4 categories:
    - Core Browser Data (8): History, cookies, downloads, tab snapshots, bookmarks, extensions, sessions, top sites
    - Security Settings (4): Proxy, privacy, content settings, search engines
    - Deep Collection (10): Web storage, IndexedDB structure, IndexedDB full dump, service workers, cache storage, storage estimates, performance timing, visit details, WebAuthn/FIDO, media devices
    - System and Account (7): Chrome account (email), system info (CPU/memory/storage), permissions, windows, detailed tabs, reading list, environment
  - **Content Script Collection**: Extracts origin-scoped data from open tabs (localStorage, IndexedDB, cache, performance timing, WebAuthn)
  - **One-Click Verifier**: Drop a package and get instant pass/fail verification
  - **Portable Signing Keys**: Export and import signing keys across machines for key continuity
  - **Forensic Packaging**: SHA-256 hashing, sealed manifests, chain of custody, ECDSA signatures
  - **Supported Browsers**: Chrome, Edge, Brave, Opera (Chromium-based); Firefox and Safari planned

### Other Security Utilities

* **[wildcard_xyz_hunter.py](Other/wildcard_xyz_hunter.py)** - Specialized security utility for wildcard domain hunting

## Acknowledgments

Special thanks to Brandon Pimentel for his valuable contributions to this project.
