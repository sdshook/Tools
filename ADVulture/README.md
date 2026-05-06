# ADVulture 🦅

**(c) 2025 Shane D. Shook, PhD - All Rights Reserved**

> **Active Directory Vulnerability Intelligence: Empirical Posture Analysis through Graph Neural Networks and Markov Modeling**

ADVulture is a standalone Active Directory security posture analysis platform that fuses static AD configuration data with historical authentication and authorization event logs to produce mathematically grounded, gradient-ranked remediation intelligence. It operates without dependency on BloodHound, Neo4j, or any external graph database.

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

### Digital Ecosystems (Sakana AI)

The regime classification and ecosystem dynamics model in ADVulture is directly inspired by **"Digital Ecosystems: Interactive Multi-Agent Neural Cellular Automata"** by Luke Darlow, Sakana AI (2026):

> https://pub.sakana.ai/digital-ecosystem/

That work introduced the concept of live parameter steering of competing neural species toward or away from the *edge of chaos*, a critical regime between frozen stability and turbulent collapse. ADVulture applies this framing to enterprise security posture:

- **Ordered regime:** Controls are sufficient, attack paths are suppressed, and steady-state Tier 0 probability is low.
- **Critical regime:** The environment sits at the edge of chaos; specific control failures would cascade into full compromise.
- **Chaotic regime:** Multiple active, high-gradient paths to Tier 0 exist simultaneously; the environment is functionally indefensible without immediate intervention.

The key insight borrowed from Sakana's work is that a single scalar parameter (in their case, growth-gate steepness; in ADVulture, the aggregate control deployment index) can move a complex system between these three regimes, and computing gradients over that parameter identifies the most efficient steering interventions.

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

---

## Security Scenarios ADVulture Can Predict

ADVulture's empirical analysis, combining AD configuration with actual log history, enables prediction of the following compromise scenarios. Each is derived from the gradient of steady-state Tier 0 compromise probability, weighted by observed behavioral signals.

### Scenario 1: Kerberoasting → Lateral Movement → Domain Compromise
**Risk Classes:** A (AuthN Hygiene) + E (Delegation)

ADVulture identifies service accounts with Service Principal Names (SPNs) set, correlates them with 4769 events showing RC4 encryption type (0x17 downgrade), and traces the downstream blast radius through the AD graph. Where a Kerberoastable account has AdminTo edges or delegation scope reaching Tier 0, ADVulture flags the compound path.

**Predictive signal:** Spike in 4769/RC4 volume over 14-day baseline indicates active Kerberoasting campaign. ADVulture correlates this with graph reachability to predict which accounts are being targeted and what they can reach.

---

### Scenario 2: ADCS Certificate Template Abuse (ESC1 / ESC2)
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

ESC1-vulnerable templates allow Subject Alternative Name specification, enabling any enrolling user to obtain a certificate authenticating as any other identity, including Domain Admin. ADVulture enumerates template flags (`msPKI-Certificate-Name-Flag`, enrollment rights ACLs) and correlates with 4886/4887 events to detect active enrollment against vulnerable templates.

**Predictive signal:** Unusual certificate requests (4886) from non-administrative accounts against templates with broad enrollment rights, combined with ESC1 flag configuration, predicts imminent certificate-based impersonation.

---

### Scenario 3: Unconstrained Delegation → TGT Harvest → Domain Admin
**Risk Classes:** E (Delegation Override) + A (AuthN Hygiene)

Computers with unconstrained delegation (`TrustedForDelegation = True`) receive a copy of the TGT of every user authenticating to them. ADVulture identifies these machines, determines which privileged accounts have authenticated to them (via 4624 event correlation), and computes the probability that a compromise of the delegation-capable machine yields Tier 0 credentials.

**Predictive signal:** Tier 0 accounts (Domain Admins, Enterprise Admins) observed authenticating to unconstrained delegation machines via 4624 events creates a concrete, time-bounded compromise prediction.

---

### Scenario 4: Pass-the-Hash Lateral Movement Chains
**Risk Classes:** A (AuthN Hygiene) + C (AuthZ Behavior)

ADVulture detects PTH indicators: 4624 Type 3 events using NtLmSsp authentication package where Kerberos is expected, very short session durations (seconds), and 4648 explicit credential use patterns. It traces these through the graph to identify the lateral movement chain and destination.

**Predictive signal:** NTLM authentication on Kerberos-capable edges with session durations under 10 seconds indicates automated credential reuse. Graph analysis predicts next-hop targets based on AdminTo edges from the compromise origin.

---

### Scenario 5: Shadow Admin Privilege Escalation via ACL Chain
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

Shadow admins are accounts with effective administrative control over Tier 0 objects through ACL relationships (GenericAll, WriteDacl, WriteOwner) rather than direct group membership. ADVulture computes effective permission chains through nested ACL relationships and correlates with 4662/4670 events to detect active ACL manipulation.

**Predictive signal:** 4670 (permissions changed) or 4662 (object operation) events on Tier 0 objects by accounts not in privileged groups indicates shadow admin exploitation in progress.

---

### Scenario 6: Resource-Based Constrained Delegation (RBCD) Privilege Escalation
**Risk Classes:** E (Delegation Override) + B (AuthZ Structure)

RBCD allows any principal with write access to a computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to configure delegation, enabling impersonation of any domain user to that machine. ADVulture enumerates write rights to this attribute and models the resulting impersonation paths to Tier 0.

**Predictive signal:** Modification of `msDS-AllowedToActOnBehalfOfOtherIdentity` (4662 with specific GUID) followed by S4U2Self/S4U2Proxy Kerberos ticket requests predicts imminent privilege escalation to any account on the target machine.

---

### Scenario 7: LPE via SeImpersonatePrivilege → LSASS Dump → Domain Compromise
**Risk Classes:** D (Privilege Escalation) + C (AuthZ Behavior)

Service accounts running IIS application pools, SQL Server, or other services commonly hold `SeImpersonatePrivilege`. This enables Potato-family attacks (JuicyPotato, SweetPotato, PrintSpoofer) to escalate to SYSTEM, from which LSASS can be dumped. ADVulture correlates 4672 events (SeImpersonate at logon), Sysmon Event 10 (LSASS access), and cached credential analysis to predict which hosts are one exploit from full credential harvest.

**Predictive signal:** SeImpersonate on a service account (4672) on a machine with observed Tier 0 credential sessions (4624 + 4672 by privileged account) and Sysmon LSASS access attempts (Sysmon 10) constitutes a critical predictive triple.

---

### Scenario 8: Golden SAML via ADFS Token Signing Certificate Theft
**Risk Classes:** B (AuthZ Structure) + C (AuthZ Behavior)

ADFS stores its token signing private key in a configuration database. Compromise of the ADFS server or its database enables forging of SAML assertions for any identity (a Golden SAML attack). ADVulture monitors ADFS server exposure, event 1007 (certificate operations), token issuance without corresponding authentication events (ADFS 299 without preceding 4624), and claim rules granting broad access to relying parties.

**Predictive signal:** Token issuance (ADFS 299) from unexpected source IP or without preceding DC authentication, combined with claim rule modifications (403), indicates Golden SAML exploitation.

---

### Scenario 9: Cross-Domain Trust Exploitation → Enterprise Admin
**Risk Classes:** B (AuthZ Structure) + E (Delegation)

Misconfigured inter-domain and inter-forest trusts without SID filtering enabled allow SID history injection, enabling accounts from trusted domains to carry Tier 0 SIDs. ADVulture enumerates trust attributes (`trustAttributes`, `securityIdentifier`) and models cross-boundary attack paths.

**Predictive signal:** 4768 Kerberos TGT requests from cross-domain accounts to Tier 0 services, combined with SID filtering disabled on the trust, predicts cross-domain compromise escalation.

---

### Scenario 10: AS-REP Roasting → Credential Cracking → Privileged Access
**Risk Classes:** A (AuthN Hygiene)

Accounts with `DONT_REQ_PREAUTH` set in `userAccountControl` allow unauthenticated retrieval of Kerberos AS-REP responses, which can be cracked offline. ADVulture identifies all such accounts, determines their group memberships and ACL-based reach, and ranks them by downstream blast radius.

**Predictive signal:** 4768 events without pre-authentication for accounts with downstream Tier 0 reachability identifies active AS-REP roasting targets.

---

### Scenario 11: AI Agent Prompt Injection → Authorized Data Exfiltration
**Risk Classes:** F (AI Agent Surface)

AI agents (Microsoft Copilot, custom LangChain/AutoGen agents, MCP-enabled agents) authorized with broad OAuth scopes (Mail.ReadWrite, Files.ReadWrite.All) and code execution MCP tools can be weaponized via prompt injection through email, document, or web content. The resulting actions are fully authorized, with no ACL violation, no authentication anomaly.

**Predictive signal:** AI agent with Mail.Read + action-capable MCP tools processing external content constitutes a structural prediction of injection risk regardless of whether exploitation has been observed.

---

### Scenario 12: Password Spray with Legacy Authentication MFA Bypass
**Risk Classes:** A (AuthN Hygiene) + C (AuthZ Behavior)

Legacy authentication protocols (Basic Auth, IMAP, POP3, SMTP AUTH) bypass Conditional Access policies including MFA requirements. ADVulture identifies accounts without legacy auth blocked, correlates with Entra sign-in logs showing legacy protocol authentication, and flags accounts targeted by spray patterns (distributed low-velocity failures across many usernames).

**Predictive signal:** Multiple 4625/Entra signin failure events across >50 accounts within 60 minutes using legacy authentication protocols, followed by successful authentication on targeted accounts, predicts successful spray-and-authenticate.

---

### Scenario 13: Stale Service Account → Kerberoast → Lateral Movement
**Risk Classes:** A + E (Compound)

Service accounts with passwords unchanged for >365 days, SPNs set, and AdminTo or delegation rights represent the highest-confidence attack path prediction ADVulture generates. The old password increases cracking probability; the SPN enables offline hash retrieval; the downstream rights determine impact.

**Predictive signal:** Service account with SPN + password age > 365 days + AdminTo or unconstrained delegation = near-certain eventual compromise path. Gradient contribution is typically among the top three findings in any environment.

---

### Scenario 14: Local Standing Privilege Abuse → Credential Harvest
**Risk Classes:** C (AuthZ Behavior) + D (LPE)

Users manually added to local Administrators groups on servers (not via domain GPO or domain group) are invisible to ACL analysis but discoverable through 4732 event correlation on member servers. These standing local admin rights enable credential harvesting even when domain group memberships appear clean.

**Predictive signal:** 4732 events on non-DC hosts for accounts not in domain admin groups, combined with privileged sessions on the same host (4624 + 4672), predicts undocumented lateral movement paths.

---

## Installation

### Requirements

- Python 3.11+
- Network access to Domain Controllers (LDAP 389/636)
- Windows Event Log access (WinRM 5985/5986, or pre-exported EVTX files)
- For Entra ID / hybrid: Microsoft Graph API credentials
- For ADFS: Access to ADFS server event logs

### Install

```bash
git clone https://github.com/yourorg/advulture
cd advulture
pip install -e ".[dev]"
```

### Configuration

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your environment details
advulture configure
```

---

## Usage

### Full Analysis

```bash
# Run complete posture analysis
advulture analyze --config config.yaml --output reports/

# Specify log window
advulture analyze --log-window 30 --authz-window 90

# Enumerate only (no ML analysis)
advulture collect --config config.yaml
```

### Scenario Testing

```bash
# Test specific remediation scenarios
advulture scenario \
  --deploy mfa_tier0=1.0 \
  --deploy adcs_hardened=1.0 \
  --deploy laps=1.0 \
  --compare-to current
```

### API Server

```bash
advulture serve --host 0.0.0.0 --port 8000
# Dashboard available at http://localhost:8000/ui
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

## License

Apache 2.0. See [LICENSE](LICENSE)

---

## Disclaimer

ADVulture is an authorized security assessment tool. It must only be used against environments for which you have explicit written permission. The authors accept no liability for unauthorized use.
