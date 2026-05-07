# ADVulture 🦅

**(c) 2025 Shane D. Shook, PhD - All Rights Reserved**

> **Active Directory Vulnerability Intelligence: Posture Analysis through Graph-Based Modeling and Markov Chain Analysis**

ADVulture is a standalone Active Directory security posture analysis tool that combines static AD configuration data with historical authentication and authorization event logs to produce prioritized remediation recommendations. It operates without dependency on BloodHound, Neo4j, or any external graph database.

**Note:** This tool provides detection and prioritization capabilities based on heuristic analysis. The ML components are experimental and require domain-specific tuning for production deployment.

---

## Why ADVulture?

### The Gap in Traditional Identity Risk Assessment

Domain identity risk evaluations have historically focused on two dimensions: **rights** and **architecture**. Security teams assess who has access to what, map group memberships, enumerate privilege escalation paths, and document the structural topology of trust relationships. This approach treats Active Directory as a static blueprint, a map of *potential* access rather than *actual* behavior.

The critical blind spot in this methodology is **use**.

When behavioral data is incorporated at all, it typically manifests as authentication event analysis interpreted *through the lens of existing rights*. A successful Kerberos ticket request is evaluated against the permissions that ticket grants. A failed logon is flagged if the target account holds elevated privileges. The analysis remains anchored to what rights *permit*, not what credentials *do*.

### Rights vs. Use: The Authorization Evidence Gap

Domain rights and domain use are fundamentally different phenomena, and the gap between them is where breaches live.

Authorization records (the granular logs of what accounts actually accessed, when, from where, and in what sequence) have repeatedly demonstrated this distinction in forensic evidence of compromise and credential abuse:

- **Dormant privileged accounts** that exist in architecture but never authenticate until an attacker discovers them
- **Service accounts** with broad permissions that historically accessed three systems but suddenly touch fifty
- **Lateral movement patterns** that follow paths technically available to any Domain Admin but never traversed by legitimate operations
- **Delegation chains** that are architecturally permitted but behaviorally anomalous when actually exercised
- **Authentication timing** that reveals credential theft, since legitimate users do not authenticate at 3 AM from foreign IP ranges, even if their accounts technically permit it

### The Agentic AI Dimension

Agentic AI introduces an entirely new category of IAM and IGA risk that traditional identity evaluation frameworks are not equipped to address.

AI agents are effectively delegated permissions by objects controlled by domain services: an OAuth application registration, a service principal, or an Entra ID managed identity. From a traditional rights-architecture perspective, the agent's permissions appear bounded by the scopes granted to its controlling identity. The evaluation stops there.

However, agents possess characteristics that fundamentally break this assumption:

- **System primitives access:** Agents with code execution capabilities (MCP tools, function calling, shell access) can invoke operating system primitives, file system operations, network calls, and API requests that extend far beyond their OAuth scopes. The agent's *effective* permission surface is the union of its delegated identity rights and the system capabilities of its execution environment.

- **Self-directed learning and adaptation:** Agents with memory, retrieval-augmented generation, or fine-tuning feedback loops can learn access patterns, discover available resources, and optimize their own lateral movement strategies. Unlike static service accounts, agents evolve their behavior based on what they encounter.

- **Autonomous lateral access:** An agent granted Mail.Read and a code execution tool can read an email containing credentials, then use those credentials to access systems entirely outside its delegated scope. The agent's authorization boundary is not its configured permissions; it is the transitive closure of everything reachable from its starting position plus its runtime capabilities.

- **Prompt injection as privilege escalation:** External content (emails, documents, web pages) processed by the agent can contain adversarial instructions that hijack agent behavior. The resulting actions execute with the agent's full delegated authority, but serve attacker objectives.

These dynamics mean that evaluation of authentication architecture alone, without review of authorization history, will not surface agentic risk. The agent's identity may authenticate correctly, its OAuth token may contain only approved scopes, and its service principal may appear properly constrained. Yet its actual resource accesses, lateral movements, and data exfiltration activities are invisible until authorization logs reveal what the agent actually did versus what its identity configuration appeared to permit.

ADVulture addresses this through its Risk Class F (AI Agent Surface), which models agent permissions, execution capabilities, and observed behavioral patterns as first-class elements of the posture graph.

Traditional tools see the rights. Forensic investigators see the use. The disconnect means security teams are perpetually reactive, discovering the gap only after breach evidence forces them to examine what credentials actually did versus what they were allowed to do.

### The Coincident Approach

ADVulture resolves this by treating rights architecture and credential behavior as **coincident data streams** that must be evaluated together, not sequentially.

Rather than asking "what could this account do?" and separately asking "what did this account do?", ADVulture fuses both questions into a unified analytical model:

- **Structural edges** representing configured permissions, group memberships, and delegation paths
- **Behavioral edges** weighted by actual authentication frequency, authorization patterns, and temporal distributions
- **Anomaly surfaces** where structural permissions exist but behavioral evidence is absent (dormant risk) or where behavioral patterns exceed structural expectations (active compromise indicators)

This coincident evaluation surfaces **hygiene weaknesses** (the gap between what your architecture permits and what your operations require) and **posture weaknesses** (the specific structural configurations that create exploitable paths whether or not they have been exercised).

The result is remediation intelligence grounded in empirical observation rather than theoretical topology. ADVulture does not just show you that a path to Domain Admin exists; it shows you which paths are behaviorally dormant (high-value targets for attackers who discover them), which paths show anomalous recent activity (potential active compromise), and which paths carry legitimate operational traffic (high disruption cost if remediated carelessly).

---

## Conceptual Foundations

### BloodHound

ADVulture draws conceptual inspiration from [BloodHound](https://github.com/BloodHoundAD/BloodHound), the widely adopted AD attack-path visualization tool developed by SpecterOps. BloodHound demonstrated that representing Active Directory as a graph and querying attack paths through it was a transformative approach to understanding privilege escalation risk.

ADVulture extends that paradigm in three ways:

1. **Temporal depth:** BloodHound provides a point-in-time graph snapshot. ADVulture fuses 30 to 90 days of authentication and authorization event logs to produce empirically weighted edges based on *actual observed behavior*, not theoretical topology alone.

2. **Gradient-ranked remediation:** BloodHound shows you attack paths. ADVulture computes `∂π_tier0/∂θ_control`, the partial derivative of steady-state Tier 0 compromise probability with respect to each deployable security control, producing a mathematically ordered remediation stack.

3. **Unified risk taxonomy:** ADVulture models six risk classes simultaneously: AuthN hygiene, AuthZ structure, AuthZ behavior, privilege escalation paths, delegation overrides, and AI agent surfaces. All classes contribute to the same GNN, the same Markov chain, and the same ranked output.

### Regime Classification

ADVulture classifies environments into three regimes based on aggregate risk indicators:

- **Ordered regime:** Controls are sufficient, attack paths are suppressed, and steady-state Tier 0 probability is low.
- **Critical regime:** The environment sits at the boundary; specific control failures could cascade into compromise.
- **Chaotic regime:** Multiple high-priority paths to Tier 0 exist simultaneously; immediate intervention is recommended.

This classification borrows the ORDERED/CRITICAL/CHAOTIC vocabulary from dynamical systems theory. The concept of systems transitioning between stability and chaos based on parameter tuning is well-established in complexity science (see: edge of chaos, self-organized criticality). The specific thresholds in ADVulture are heuristically defined based on steady-state probability, mean first passage time, and control gradient magnitudes.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     COLLECTION LAYER                         │
│  LDAP Enumerator    Windows Event Logs    Entra ID / AAD    │
│  ACL Parser         ADFS Federation       AI Agent Census   │
│  LPE Enumerator     Service Acct Audit    OAuth/PIM Logs    │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      GRAPH LAYER                             │
│  Heterogeneous AD Graph  +  Temporal Behavioral Tensors    │
│  AuthZ Dependency Graph  +  Override Surface Model          │
│  DuckDB Persistence (zero server)                           │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                       ML LAYER                               │
│                                                             │
│  Heterogeneous GNN ──edge probs──▶ Markov Stack             │
│  (HGT architecture)               ├─ Transition Matrix P    │
│                                   ├─ Steady-State π         │
│                                   ├─ Kill-Chain HMM         │
│                                   └─ 2nd-Order MC           │
│                                           │                 │
│                                    Gradient Engine          │
│                                    ∂π_tier0/∂θ              │
│                                           │                 │
│  Random Forest ◀──────────────────────────┘                 │
│  (scenario testing)                                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Regime Classification │ Trajectory │ Unified Finding Rank  │
└─────────────────────────────────────────────────────────────┘
                               │
              ┌────────────────┼─────────────────┐
              ▼                ▼                 ▼
           FastAPI          HTML Report      Streamlit UI
```

### Implementation Notes

**Current Limitations:**

- **GNN Training:** The GNN component requires labeled training data for optimal performance. Currently, edge weights are derived from heuristic rules based on AD object properties and event frequencies. Production deployments should consider fine-tuning with environment-specific labeled data.

- **Gradient Computation:** The `∂π_tier0/∂θ` gradient requires parameterizing how security controls affect Markov transition probabilities. ADVulture uses manually-defined suppression factors (e.g., MFA reduces lateral movement edge probability by a configurable amount). These factors should be calibrated to your environment.

- **Edge Weights:** "Empirically weighted edges" refers to edge probabilities computed from event log frequencies and temporal patterns. Edges traversed more frequently in logs receive higher weights. This is deterministic frequency counting, not learned embeddings.

---

## Security Scenarios ADVulture Detects

ADVulture detects the following compromise scenarios and risk conditions by combining AD configuration analysis with log correlation. Each scenario uses detection heuristics based on event patterns and graph reachability.

> **Note:** These are detection patterns, not predictive models. ADVulture identifies indicators that suggest an attack phase is occurring or that a configuration creates an exploitable condition. It does not predict future attacks that haven't begun.

### Scenario 1: Kerberoasting → Lateral Movement → Domain Compromise
**Risk Classes:** A (AuthN Hygiene) + E (Delegation)

ADVulture identifies service accounts with Service Principal Names (SPNs) set, correlates them with 4769 events showing RC4 encryption type (0x17 downgrade), and traces the downstream blast radius through the AD graph. Where a Kerberoastable account has AdminTo edges or delegation scope reaching Tier 0, ADVulture flags the compound path.

**Detection signal:** Spike in 4769/RC4 volume over 14-day baseline indicates active Kerberoasting. ADVulture correlates this with graph reachability to identify which accounts are being targeted and their potential blast radius.

---

### Scenario 2: ADCS Certificate Template Abuse (ESC1 / ESC2)
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

ESC1-vulnerable templates allow Subject Alternative Name specification, enabling any enrolling user to obtain a certificate authenticating as any other identity, including Domain Admin. ADVulture enumerates template flags (`msPKI-Certificate-Name-Flag`, enrollment rights ACLs) and correlates with 4886/4887 events to detect active enrollment against vulnerable templates.

**Detection signal:** Certificate requests (4886) from non-administrative accounts against templates with broad enrollment rights, combined with ESC1 flag configuration, indicates potential certificate-based impersonation.

---

### Scenario 3: Unconstrained Delegation → TGT Harvest → Domain Admin
**Risk Classes:** E (Delegation Override) + A (AuthN Hygiene)

Computers with unconstrained delegation (`TrustedForDelegation = True`) receive a copy of the TGT of every user authenticating to them. ADVulture identifies these machines, determines which privileged accounts have authenticated to them (via 4624 event correlation), and flags the exposure.

**Detection signal:** Tier 0 accounts (Domain Admins, Enterprise Admins) observed authenticating to unconstrained delegation machines via 4624 events indicates credential exposure risk.

---

### Scenario 4: Pass-the-Hash Lateral Movement Chains
**Risk Classes:** A (AuthN Hygiene) + C (AuthZ Behavior)

ADVulture detects PTH indicators: 4624 Type 3 events using NtLmSsp authentication package where Kerberos is expected, very short session durations (seconds), and 4648 explicit credential use patterns. It traces these through the graph to identify lateral movement patterns.

**Detection signal:** NTLM authentication on Kerberos-capable edges with session durations under 10 seconds indicates potential automated credential reuse.

---

### Scenario 5: Shadow Admin Privilege Escalation via ACL Chain
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

Shadow admins are accounts with effective administrative control over Tier 0 objects through ACL relationships (GenericAll, WriteDacl, WriteOwner) rather than direct group membership. ADVulture computes effective permission chains through nested ACL relationships and correlates with 4662/4670 events to detect active ACL manipulation.

**Detection signal:** 4670 (permissions changed) or 4662 (object operation) events on Tier 0 objects by accounts not in privileged groups indicates potential shadow admin activity.

---

### Scenario 6: Resource-Based Constrained Delegation (RBCD) Privilege Escalation
**Risk Classes:** E (Delegation Override) + B (AuthZ Structure)

RBCD allows any principal with write access to a computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to configure delegation, enabling impersonation of any domain user to that machine. ADVulture enumerates write rights to this attribute and models the resulting impersonation paths to Tier 0.

**Detection signal:** Modification of `msDS-AllowedToActOnBehalfOfOtherIdentity` (4662 with specific GUID) followed by S4U2Self/S4U2Proxy Kerberos ticket requests indicates RBCD exploitation.

---

### Scenario 7: LPE via SeImpersonatePrivilege → LSASS Dump → Domain Compromise
**Risk Classes:** D (Privilege Escalation) + C (AuthZ Behavior)

Service accounts running IIS application pools, SQL Server, or other services commonly hold `SeImpersonatePrivilege`. This enables Potato-family attacks (JuicyPotato, SweetPotato, PrintSpoofer) to escalate to SYSTEM, from which LSASS can be dumped. ADVulture correlates 4672 events (SeImpersonate at logon), Sysmon Event 10 (LSASS access), and cached credential analysis to predict which hosts are one exploit from full credential harvest.

**Detection signal:** SeImpersonate on a service account (4672) on a machine with observed Tier 0 credential sessions (4624 + 4672 by privileged account) and Sysmon LSASS access attempts (Sysmon 10) constitutes a critical predictive triple.

---

### Scenario 8: Golden SAML via ADFS Token Signing Certificate Theft
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

ADFS stores its token signing private key in a configuration database. Compromise of the ADFS server or its database enables forging of SAML assertions for any identity (a Golden SAML attack). ADVulture monitors ADFS server exposure, event 1007 (certificate operations), token issuance without corresponding authentication events (ADFS 299 without preceding 4624), and claim rules granting broad access to relying parties.

**Detection signal:** Token issuance (ADFS 299) from unexpected source IP or without preceding DC authentication, combined with claim rule modifications (403), indicates Golden SAML exploitation.

---

### Scenario 9: Cross-Domain Trust Exploitation → Enterprise Admin
**Risk Classes:** B (AuthZ Structure) + E (Delegation)

Misconfigured inter-domain and inter-forest trusts without SID filtering enabled allow SID history injection, enabling accounts from trusted domains to carry Tier 0 SIDs. ADVulture enumerates trust attributes (`trustAttributes`, `securityIdentifier`) and models cross-boundary attack paths.

**Detection signal:** 4768 Kerberos TGT requests from cross-domain accounts to Tier 0 services, combined with SID filtering disabled on the trust, indicates cross-domain compromise escalation.

---

### Scenario 10: AS-REP Roasting → Credential Cracking → Privileged Access
**Risk Classes:** A (AuthN Hygiene)

Accounts with `DONT_REQ_PREAUTH` set in `userAccountControl` allow unauthenticated retrieval of Kerberos AS-REP responses, which can be cracked offline. ADVulture identifies all such accounts, determines their group memberships and ACL-based reach, and ranks them by downstream blast radius.

**Detection signal:** 4768 events without pre-authentication for accounts with downstream Tier 0 reachability identifies active AS-REP roasting targets.

---

### Scenario 11: AI Agent Prompt Injection → Authorized Data Exfiltration
**Risk Classes:** F (AI Agent Surface)

AI agents (Microsoft Copilot, custom LangChain/AutoGen agents, MCP-enabled agents) authorized with broad OAuth scopes (Mail.ReadWrite, Files.ReadWrite.All) and code execution MCP tools can be weaponized via prompt injection through email, document, or web content. The resulting actions are fully authorized, with no ACL violation, no authentication anomaly.

**Detection signal:** AI agent with Mail.Read + action-capable MCP tools processing external content constitutes a structural prediction of injection risk regardless of whether exploitation has been observed.

---

### Scenario 12: Password Spray with Legacy Authentication MFA Bypass
**Risk Classes:** A (AuthN Hygiene) + C (AuthZ Behavior)

Legacy authentication protocols (Basic Auth, IMAP, POP3, SMTP AUTH) bypass Conditional Access policies including MFA requirements. ADVulture identifies accounts without legacy auth blocked, correlates with Entra sign-in logs showing legacy protocol authentication, and flags accounts targeted by spray patterns (distributed low-velocity failures across many usernames).

**Detection signal:** Multiple 4625/Entra signin failure events across >50 accounts within 60 minutes using legacy authentication protocols, followed by successful authentication on targeted accounts, indicates successful spray-and-authenticate.

---

### Scenario 13: Stale Service Account → Kerberoast → Lateral Movement
**Risk Classes:** A + E (Compound)

Service accounts with passwords unchanged for >365 days, SPNs set, and AdminTo or delegation rights represent the highest-confidence attack path prediction ADVulture generates. The old password increases cracking probability; the SPN enables offline hash retrieval; the downstream rights determine impact.

**Detection signal:** Service account with SPN + password age > 365 days + AdminTo or unconstrained delegation = near-certain eventual compromise path. Gradient contribution is typically among the top three findings in any environment.

---

### Scenario 14: Local Standing Privilege Abuse → Credential Harvest
**Risk Classes:** C (AuthZ Behavior) + D (LPE)

Users manually added to local Administrators groups on servers (not via domain GPO or domain group) are invisible to ACL analysis but discoverable through 4732 event correlation on member servers. These standing local admin rights enable credential harvesting even when domain group memberships appear clean.

**Detection signal:** 4732 events on non-DC hosts for accounts not in domain admin groups, combined with privileged sessions on the same host (4624 + 4672), indicates undocumented lateral movement paths.

---

## Installation

### Requirements

- Python 3.11+
- Network access to Domain Controllers (LDAP 389/636)
- Windows Event Log access (WinRM 5985/5986, or pre-exported EVTX files)
- For Entra ID / hybrid: Microsoft Graph API credentials
- For ADFS: Access to ADFS server event logs

### Install

```shell
git clone https://github.com/yourorg/advulture
cd advulture
pip install -e ".[dev]"
```

### Configuration

```shell
cp config.example.yaml config.yaml
# Edit config.yaml with your environment details
advulture configure
```

---

## Authentication

ADVulture supports three deployment scenarios with simple, interactive authentication for each:

| Scenario | Command | Data Sources |
|----------|---------|--------------|
| **Cloud-only** | `advulture analyze --entra-only` | Entra ID directory + sign-in logs |
| **On-prem only** | `advulture analyze --ad-only` | AD via LDAP + DC event logs (auto-discovered) |
| **Hybrid** | `advulture analyze --ad-auth kerberos --entra-auth device_code` | All of the above |

### Simplest Usage

```shell
# Cloud-only (Entra ID)
advulture analyze --entra-only

# On-prem only (AD + DC event logs)
advulture analyze --ad-only

# Hybrid (AD + Entra) - collects from both on-prem DC and Azure AD
advulture analyze --ad-auth kerberos --entra-auth device_code
```

That's it. No config file, no paths to specify. ADVulture will:
- **Auto-discover domain and DC** via DNS
- **Auto-discover EVTX files** from current directory or Windows default locations
- **Prompt for credentials** interactively (AD creds and/or Entra device code)

**Note:** For on-prem/hybrid, run from a directory containing exported EVTX files, or run directly on a DC where logs are in the default Windows location.

---

### On-Premises Active Directory Authentication

| Mode | Use Case | Credentials |
|------|----------|-------------|
| `prompt` | Interactive assessments (default) | Prompted at runtime |
| `kerberos` | Domain-joined machine | Current Kerberos ticket |
| `ntlm` | NTLM authentication | Prompted or config |
| `simple` | Automation with config file | From config.yaml |

```shell
# Interactive prompt (default) - auto-discovers domain and DC
advulture analyze --ad-only

# Specify domain if not auto-detected
advulture analyze --ad-only --domain corp.local

# Use current Kerberos ticket (domain-joined Windows/Linux)
advulture analyze --ad-only --ad-auth kerberos

# NTLM authentication
advulture analyze --ad-only --ad-auth ntlm
```

**Auto-discovery:**
- **Domain**: Detected from `USERDNSDOMAIN` env var or machine FQDN
- **Domain Controller**: DNS SRV lookup (`_ldap._tcp.dc._msdcs.DOMAIN`)
- **Base DN**: Derived from domain name

**Required permissions:** Domain Users + read access to AD objects (or Domain Admin for full analysis)

---

### Entra ID / Azure AD Authentication

| Mode | Use Case | App Registration |
|------|----------|-----------------|
| `device_code` | CLI/SSH assessments (default) | **Not required** |
| `interactive` | Desktop with browser | **Not required** |
| `client_secret` | Automation | Required |
| `certificate` | Secure automation | Required |
| `managed_identity` | Azure-hosted | Required |

```shell
# Interactive - just log in (no app registration needed)
advulture analyze --entra-only

# Browser popup instead of device code
advulture analyze --entra-only --entra-auth interactive

# For automation (requires app registration + config file)
advulture analyze --entra-only --config config.yaml
```

**How interactive auth works:**
1. ADVulture uses Microsoft's well-known Azure CLI client ID
2. You're prompted to visit a URL and enter a code
3. You sign in with your admin credentials (MFA enforced by your CA policies)
4. Your identity determines which tenant you access

**Required roles** for interactive auth: Global Reader, Security Reader, or Reports Reader

---

### Hybrid Environment (On-Prem + Entra)

For domain-joined environments synced to Entra ID via Azure AD Connect:

```shell
# Full hybrid analysis using Kerberos for AD + device code for Entra
advulture analyze --ad-auth kerberos --entra-auth device_code

# Specify domain explicitly if auto-discovery fails
advulture analyze --ad-auth kerberos --domain corp.local --entra-auth device_code

# Prompt for AD credentials instead of using Kerberos ticket
advulture analyze --ad-auth prompt --entra-auth device_code
```

**Exporting DC logs:** If not running directly on a DC, export logs first:
```shell
wevtutil epl Security Security.evtx
wevtutil epl System System.evtx
```
Then run ADVulture from the directory containing the exported files.

---

### Automation (App Registration Required)

For scheduled scans, create an app registration with **application** permissions:
- `Directory.Read.All`, `AuditLog.Read.All`, `IdentityProtection.Read.All`
- `Policy.Read.All`, `Reports.Read.All`, `RoleManagement.Read.Directory`

```shell
# Via environment variables
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-app-id"  
export AZURE_CLIENT_SECRET="your-secret"
advulture analyze --entra-only --entra-auth client_secret

# Or via config.yaml
advulture analyze --config config.yaml
```

**Security note:** App registrations create persistent high-privilege identities. Use interactive auth when possible.

---

## Usage

### Full Analysis

```shell
# Cloud-only (Entra ID)
advulture analyze --entra-only

# On-prem only (AD + DC logs auto-discovered)
advulture analyze --ad-only

# Hybrid (AD + Entra) — recommended for domain-joined environments
advulture analyze --ad-auth kerberos --entra-auth device_code

# Using config file (for automation)
advulture analyze --config config.yaml
```

### Offline Audit (NTDS.dit + SYSTEM + Logs)

For forensic analysis or environments where live access is not available, ADVulture can analyze extracted AD artifacts:

```shell
# Basic audit with NTDS.dit only
advulture audit --ntds ./ntds.dit --output reports/

# Full audit with SYSTEM hive and event logs
advulture audit \
  --ntds ./ntds.dit \
  --system ./SYSTEM \
  --evtx ./Security.evtx \
  --evtx ./System.evtx \
  --output reports/

# Extract password hashes (requires SYSTEM hive)
advulture audit \
  --ntds ./ntds.dit \
  --system ./SYSTEM \
  --extract-hashes \
  --output reports/
```

**Artifact Collection:** To obtain these files from a domain controller:

```shell
# Create VSS snapshot and extract NTDS.dit
ntdsutil "ac i ntds" "ifm" "create full C:\extract" q q

# Or use Volume Shadow Copy directly
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\extract\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\extract\

# Export event logs
wevtutil epl Security C:\extract\Security.evtx
wevtutil epl System C:\extract\System.evtx
```

The offline audit analyzes:
- **Kerberoastable accounts** (SPNs on user accounts)
- **AS-REP roastable accounts** (preauth disabled)
- **Password policy violations** (never expires, not required)
- **Privileged account hygiene** (stale passwords, dormant accounts)
- **Delegation misconfigurations** (unconstrained, RBCD)
- **Legacy operating systems**
- **Trust configurations** (SID filtering)
- **Authentication anomalies** from event logs (password spray, Kerberoasting activity)
- **Privilege use patterns** (SeDebugPrivilege, sensitive operations)

### API Server

```shell
advulture serve --host 0.0.0.0 --port 8000
# API documentation available at http://localhost:8000/docs
```

---

## Output

ADVulture produces:
- **Unified gradient-ranked finding list:** All six risk classes ordered by `∂π_tier0/∂θ`
- **Regime classification:** ORDERED / CRITICAL / CHAOTIC with supporting evidence
- **Kill-chain phase detection:** Current attacker phase inferred from log sequences
- **30/60/90-day trajectory projection:** Where is your posture heading
- **Scenario comparison:** RF-predicted risk reduction for proposed control sets
- **Dependency impact:** What breaks if a given permission is remediated
- **HTML executive and technical reports**
- **JSON output** for SOAR/SIEM integration

---

## Risk Class Reference

| Class | Name | Primary Sources |
|-------|------|-----------------|
| A | AuthN Hygiene | LDAP, 4624/4625/4769/4768/4771/4776 |
| B | AuthZ Structure | LDAP ACLs, GPO, ADCS template flags |
| C | AuthZ Behavior | 5140/4663/4670/4732, ADFS 299/403, Entra CA/OAuth |
| D | Privilege Escalation | 4672/4673/7045/4698, Sysmon 10 |
| E | Delegation Override | LDAP msDS-*, 4769 TransitedServices |
| F | AI Agent Surface | Entra app permissions, MCP manifests, Graph API logs |

---

## References

- Darlow, L. (2026). *Digital Ecosystems: Interactive Multi-Agent Neural Cellular Automata*. Sakana AI. https://pub.sakana.ai/digital-ecosystem/
- BloodHound Community Edition. SpecterOps. https://github.com/BloodHoundAD/BloodHound
- MITRE ATT&CK - Enterprise, Active Directory techniques. https://attack.mitre.org/
- Schroeder, W. et al. (2022). *Certified Pre-Owned: Abusing Active Directory Certificate Services*. SpecterOps.
- Metcalf, S. (2015). *Sneaky Active Directory Persistence Tricks*. ADSecurity.org.

---

## Disclaimer

ADVulture is an authorized security assessment tool. It must only be used against environments for which you have explicit written permission. The authors accept no liability for unauthorized use.

This software is proprietary. All rights reserved. Contact the author for licensing inquiries.
