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

### ShaneGuard - Adaptive Cybersecurity Web Service Protection Agent
Neuromorphic cybersecurity system combining Hebbian learning with reinforcement learning:

* **[ShaneGuard/](ShaneGuard/)** - Adaptive Cybersecurity Web Service Protection Agent
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

### Forensic Analysis Tools
Advanced forensic analysis and AI-assisted investigation tools:

* **[FORAI.py](FORAI/FORAI.py)** - An AI project for Computer Forensics
  - End-to-end Windows triage, analysis, and reporting pipeline
  - Automated collection using KAPE and Eric Zimmerman's Tools
  - Deterministic layer: CSV to SQLite with evidence indexing and FTS
  - Generative AI layer: LLM executive summaries and Q&A grounded in evidence
  - Answers 12 common DFIR questions via SQL views
  - Chain-of-custody logging and daily archive packaging
  - Supported by TinyLLaMA 1.1b for AI-assisted analysis
* **[New_FORAI.py](FORAI/New_FORAI.py)** - Updated version of FORAI with enhanced capabilities
* **[FORAI Workflow Documentation](FORAI/FORAI_Workflow.md)** - Detailed workflow and usage guide for FORAI.py

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

### Other Security Utilities

* **[wildcard_xyz_hunter.py](Other/wildcard_xyz_hunter.py)** - Specialized security utility for wildcard domain hunting

## Acknowledgments

Special thanks to Brandon Pimentel for his valuable contributions to this project.
