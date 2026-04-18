# Model Context Routing

**Externalizing Attention into a Persistent, Event-Driven Context Plane**

*Shane D. Shook, PhD*  
*April 18, 2026*

An architectural pattern for persistent, event-driven AI context management implemented on Synadia's NATS and JetStream infrastructure. MCR eliminates stateless context loss in multi-step enterprise AI workflows, providing measurable reductions in token consumption, inference cost, and latency while enabling deterministic service-level guarantees.

## Executive Summary

Large language models deployed in enterprise workflows fail not because of reasoning limitations but because of a structural mismatch in how they are invoked. Each model invocation is stateless. Context is reconstructed from scratch at every step. Instructions are repeated, prior decisions are re-established, and prior outputs must be re-injected, creating a compounding cycle of token waste, latency, and outcome variability.

This paper introduces Model Context Routing (MCR), a system-level architectural pattern that separates context management from model execution. Rather than relying on the model's context window to carry state across workflow steps, MCR externalizes state into a durable, event-driven infrastructure layer built on NATS messaging and JetStream persistence, governed by the Synadia control plane.

MCR is not a product. It is an architectural abstraction: a defined pattern for how enterprise systems should publish, persist, correlate, and selectively retrieve AI context across multi-step workflows. It is complementary to existing standards including Anthropic's Model Context Protocol (MCP), REST APIs, and CLI-based agent orchestration, all of which serve as ingress points that publish into the MCR context plane.

Section 5 presents a quantitative estimation framework demonstrating that MCR reduces per-workflow input token consumption by 30 to 65 percent under a relevance ratio of 0.35, depending on workflow depth and context density. For the three representative enterprise scenarios modeled in Section 5.5, reductions range from 55 to 62 percent. Combined with Synadia's SLA enforcement and deterministic context reconstruction, MCR provides a foundation for enterprise AI deployments where cost, latency, and output consistency can be governed by policy rather than accepted as inherent variability.

## 1. The Context Persistence Problem in Enterprise AI

### 1.1 The Two Levels of Context Loss

Context loss in deployed AI systems manifests at two distinct architectural levels, each requiring a different remediation strategy. Understanding both is essential for diagnosing the performance degradation that enterprise operators observe in production workflows.

**Level 1: Intra-Model Signal Dilution**

Recent architecture research from the Kimi/Moonshot AI team introduces Attention Residuals as a solution to a fundamental flaw in standard transformer residual connections. The paper identifies what it calls PreNorm dilution: in standard transformer architectures, residual connections aggregate all preceding layer outputs using fixed, uniform unit weights. Every layer therefore receives the same undifferentiated accumulation of all prior layer representations, with no mechanism to selectively emphasize or suppress individual layer contributions.

The consequence is that as network depth increases, hidden-state magnitude grows without bound, progressively attenuating each layer's individual contribution. Earlier layer signals, which often encode foundational semantic content, are diluted by the accumulation of later representations. The Attention Residuals paper proposes replacing this fixed accumulation with learned, input-dependent softmax attention over preceding layer outputs, allowing each layer to selectively weight which prior representations it draws from.

This confirms a structural tendency within transformer models toward progressive signal weakening over depth, a tendency that is independent of sequence length or context window size. Even within a single well-formed prompt, the internal representation of earlier content is subject to dilution relative to more recent content.

**Level 2: Inter-Call Statelessness in Enterprise Workflows**

Distinct from intra-model dilution, and compounded by it, is the operational problem of statelessness across separate model invocations. Enterprise workflows do not consist of single model calls. They consist of sequences of calls across multiple steps, systems, agents, and time intervals. Each API invocation to an LLM endpoint is stateless by design: no prior call's results, decisions, or established context persist into the next call unless the calling system explicitly re-injects them.

This creates what might be called the context reconstruction tax: the token overhead incurred by re-establishing workflow state at every step. In a ten-step workflow where each step requires context from three prior steps, token consumption and latency scale non-linearly. In a thirty-step workflow spanning multiple days, as is common in enterprise finance, security operations, and software delivery, the reconstruction tax becomes economically material.

The two levels interact. Because the model's internal attention tends to dilute earlier representations even within a single call, re-injected context is less reliably processed than context present at the start of the original call. Multi-step enterprise workflows are therefore subject to both architectural signal loss and operational context loss simultaneously.

The Attention Residuals research validates that selective, learned aggregation over prior representations outperforms uniform accumulation, even within a single forward pass. MCR applies this same principle at the infrastructure level: rather than re-injecting all prior context uniformly, MCR selectively reconstructs only the workflow state relevant to the current invocation.

### 1.2 Observed Failure Modes in Production Deployments

The combined effect of these two levels of context loss produces identifiable and recurring failure modes in enterprise AI deployments:

- **Instruction drift.** Multi-step workflows exhibit progressive deviation from original task specifications as the model deprioritizes earlier instructions in favor of more recent context. Operators compensate by repeating system instructions at each step, a direct token cost with diminishing returns.

- **Decision inconsistency.** Identical decision logic applied at different points in a workflow produces different outputs because the reconstructed context differs across invocations. This makes service-level enforcement for AI-driven processes extremely difficult.

- **Context overflow.** Long-running workflows eventually exceed practical context window limits. When truncation occurs it is typically not governed by relevance; the most recently injected content is retained, which is not necessarily the most important.

- **Latency cascades.** Each context reconstruction step introduces latency. In workflows where prior outputs are large, such as multi-document analysis, extended reasoning chains, or multi-agent outputs, re-injection can dominate inference latency.

- **Auditability gaps.** Because context is ephemeral, constructed and discarded per invocation, there is no durable record of what information the model had access to at each decision point. This creates compliance and audit exposure for regulated industries.

## 2. Model Context Routing: Architecture and Principles

### 2.1 Defining Model Context Routing

Model Context Routing (MCR) is a system-level architectural pattern that separates context management from model execution. It introduces a persistent, event-driven context plane positioned between the systems that initiate AI requests and the model providers that fulfill them. MCR does not modify how models work internally. It governs how context flows into, through, and out of model invocations at the infrastructure level.

The core principle of MCR mirrors the insight of the Attention Residuals research: selective, learned aggregation over prior representations outperforms uniform, undifferentiated accumulation. Where AttnRes implements this principle within a transformer's depth dimension, MCR implements it within the workflow's temporal dimension. At each workflow step, MCR reconstructs only the context elements relevant to the current task, not the entire prior history indiscriminately.

### 2.2 Relationship to MCP and Existing Protocols

MCR does not replace or compete with Anthropic's Model Context Protocol (MCP), REST API integrations, or CLI-based agent orchestration. These protocols define how a model receives context and returns a response within a single invocation. MCR operates at the workflow orchestration layer, defining how context is accumulated, persisted, and selectively delivered across multiple invocations over the lifetime of a workflow.

In an MCR-governed architecture, MCP endpoints, REST APIs, and CLI tools function as ingress mechanisms. They publish their requests and responses as events into the MCR context plane. MCR then governs persistence, correlation, and selective reconstruction. The model itself is unaware of MCR; it receives a well-formed context window assembled from the persisted event stream, identical in structure to any other caller-supplied context.

- **MCP / REST API / CLI.** Protocol for a single model invocation: what context is provided, how tools are called, and how the model responds.

- **MCR.** Infrastructure pattern for context persistence and selective reconstruction across multiple invocations throughout the lifetime of a workflow.

- **Interaction model.** MCP, API, and CLI interfaces act as ingress points that publish events into the MCR context plane. They are unmodified; MCR wraps around them at the infrastructure layer.

### 2.3 Architectural Components

MCR's context plane consists of four functional layers, each with a distinct responsibility.

**Ingress Normalization**

Events from heterogeneous sources, including MCP endpoints, REST API calls, CLI invocations, agent outputs, and webhook triggers, are normalized into a consistent event schema and published to NATS subjects organized by domain, workflow type, and tenant. This normalization ensures that downstream context reconstruction is deterministic regardless of the original event source.

**Context Persistence**

Published events are persisted in JetStream streams configured with appropriate retention, replay, and delivery semantics. Each event is tagged with a correlation identifier that links it to its parent workflow instance. JetStream provides exactly-once delivery semantics, configurable retention policies, and consumer acknowledgment, all prerequisites for reliable context management in enterprise workflows.

**Context Reconstruction**

When a new workflow step is initiated, MCR services subscribe to the relevant stream, filter by correlation identifier, and reconstruct the workflow state relevant to the current task. Reconstruction is governed by retrieval policies configured to include recency-weighted context, role-filtered context (for example, only prior model outputs rather than system events), or domain-specific context defined at workflow design time.

**Routing and Dispatch**

The reconstructed context, combined with the new task request, is used to select and dispatch to the appropriate model provider. Routing decisions are governed by SLA requirements, cost constraints, compliance policies, and current load conditions. The model receives a well-formed context window. Its response is captured and re-published as a new event into the context plane, completing the cycle.

## 3. Infrastructure: NATS, JetStream, and the Synadia Control Plane

### 3.1 Why NATS for the Context Plane

NATS is a lightweight, high-performance, cloud-native messaging system designed for distributed systems at scale. Its subject-based publish-subscribe model, sub-millisecond message delivery, and native support for multi-tenancy and geographic distribution make it well-suited as the transport layer for MCR's context plane.

- **Subject taxonomy.** NATS subjects are hierarchical and support wildcard subscription, enabling fine-grained routing of context events by domain, tenant, workflow type, and priority without requiring additional routing infrastructure.

- **Decoupled producers and consumers.** Context producers (ingress adapters) and consumers (context reconstruction services) are fully decoupled, enabling independent scaling and failure isolation.

- **Native multi-tenancy.** NATS accounts provide cryptographically enforced tenant isolation at the messaging layer, a prerequisite for enterprise deployments where multiple business units or customers share infrastructure.

- **Global distribution.** NATS supports multi-cluster topologies with geographic distribution, enabling context persistence to colocate with model endpoints and comply with data residency requirements.

### 3.2 JetStream Persistence Semantics for Context Management

JetStream extends core NATS with durable persistence, consumer acknowledgment, and stream management capabilities essential to MCR's context plane.

**Stream Configuration**

JetStream streams are configured per workflow domain with retention policies matched to business requirements. Time-based retention ensures context is available for the duration of long-running processes. Size-based retention provides cost control. Interest-based retention, which retains messages only while active consumers exist, is appropriate for ephemeral workflow types.

**Consumer Groups and Correlation**

JetStream consumers are configured to filter by subject and, through message headers, by correlation identifier. This allows MCR reconstruction services to retrieve only the events belonging to a specific workflow instance without scanning entire streams. Consumer acknowledgment policies ensure that reconstruction operations are idempotent and can be resumed on failure.

## 6. Enterprise Workflow Use Cases

### 6.1 Security Operations: Multi-Stage Incident Response

Security operations centers represent one of the highest-value MCR use cases because security incidents are inherently multi-stage, time-distributed processes. A security incident originating as an anomalous network alert may require dozens of analysis steps over hours or days before reaching resolution, involving threat intelligence correlation, asset inventory lookups, lateral movement analysis, forensic review, and stakeholder notification.

In a stateless architecture, each analysis step requires re-injecting prior context: the original alert, prior analysis conclusions, identified indicators of compromise, affected systems, and current response status. As the investigation grows, this context grows proportionally, eventually approaching context window limits, at which point prior context must be truncated with no relevance-governed selection.

With MCR, the incident is represented as a persistent event stream. Each analysis step, whether performed by a human analyst, an automated detection rule, or an AI model, publishes its output as an event tagged with the incident's correlation identifier. When the next step requires context, the MCR reconstruction service assembles only the relevant prior events: recent model outputs, current threat intelligence, and active indicators, without re-injecting the full incident history. The result is faster step execution, more consistent reasoning, and a complete, replayable audit trail of the investigation.

### 6.2 Financial Services: Multi-Step Credit and Risk Workflows

Credit underwriting and risk assessment workflows involve structured multi-step processes that combine data retrieval, model-assisted analysis, policy application, and human review. Each step builds on prior outputs: initial credit data retrieval informs the financial model parameters, which inform the risk analyst's review, which informs the approval decision.

The audit and compliance requirements in financial services make MCR particularly valuable. Regulators may require demonstration that a credit decision was made using specific data within specific policy constraints. In a stateless architecture, reconstructing the exact context that informed a model output at a specific decision point is at best an approximation. JetStream's immutable event log provides an exact, replayable record.

Credit and risk workflows also involve long processing windows; decisions may take hours or days to complete, involving back-and-forth between automated analysis and human review. MCR's persistent context plane is designed for exactly this pattern: long-running, asynchronous, multi-party workflows where context must survive across system restarts, personnel handoffs, and time gaps.

### 6.3 Customer Operations: Persistent Engagement Context

Customer support operations benefit from MCR differently from incident-based workflows: the process is not a single incident but an ongoing relationship across potentially hundreds of interactions over months or years. Each customer interaction carries implicit context, including prior issues, established preferences, product usage patterns, and prior resolutions, that should inform every subsequent interaction without requiring the customer to re-establish it.

With MCR, customer engagement history is maintained as a persistent event stream keyed by customer identifier. Each support interaction publishes its context as events. When the next interaction begins, the MCR reconstruction service assembles the relevant prior context, and the model receives a well-formed context window that reflects the customer's history.

### 6.4 Software Delivery: Incremental CI/CD Analysis

Continuous integration and delivery pipelines represent a high-frequency, structured application of multi-step AI workflows. Modern AI-assisted CI/CD systems perform code analysis, test generation, security scanning, dependency review, and deployment validation, each potentially involving multiple AI model calls across a pipeline run.

The key MCR advantage in CI/CD is incremental context management. Without MCR, each pipeline run re-analyzes the full relevant context from scratch. With MCR, the analysis context is accumulated incrementally; each commit's analysis events are appended to the repository's context stream. When a new commit is analyzed, the MCR reconstruction service delivers incremental context: recent commits, prior findings relevant to the changed files, and established baseline patterns. A one-line bug fix does not require re-ingesting the context of a decade-old codebase.

### 6.5 Multi-Agent Orchestration

Emerging multi-agent architectures, where multiple specialized AI agents collaborate on complex tasks, introduce a coordination challenge that MCR is well-positioned to address. In a multi-agent system, agents may operate asynchronously, produce outputs that other agents depend on, and need access to shared context without direct communication.

MCR's event-driven architecture provides a natural coordination primitive: agents publish their outputs as events into shared context streams, and the MCR routing layer assembles relevant cross-agent context for each subsequent agent invocation. This enables loosely coupled, asynchronous multi-agent coordination without requiring agents to maintain direct connections to each other, a significant reliability and scalability advantage in enterprise deployments.

## 7. Implementation Reference Architecture

### 7.1 Subject Taxonomy Design

The NATS subject taxonomy is the foundational design decision for an MCR deployment. Subjects should be structured to support both fine-grained filtering and broad subscription patterns. A recommended taxonomy follows a four-level hierarchy:

```
{tenant}.{domain}.{workflow-type}.{event-type}
```

For example: `acme.secops.incident.alert-triage` or `acme.finance.credit.data-retrieval`. A reconstruction service for a specific workflow type subscribes at level three; an audit service capturing all events for a tenant subscribes at level one with a wildcard.

### 7.2 Correlation Identifier Strategy

Every event published into an MCR context plane must carry a correlation identifier linking it to its parent workflow instance. The correlation ID should be generated at workflow initiation and propagated through all downstream events as a NATS message header. For hierarchical workflows where a parent spawns child workflows, a two-level scheme is recommended: a root workflow ID persisting for the lifetime of the top-level process, and a step ID scoping the child workflow's events.

### 7.3 Stream Configuration Patterns

- **Long-running, high-compliance workflows (finance, healthcare):** time-based retention of 90 to 365 days with a replication factor of 3.
- **Operational workflows (security operations, customer support):** time-based retention of 30 to 90 days with standard replication.
- **High-frequency, ephemeral workflows (CI/CD, real-time analytics):** interest-based or size-based retention; replicate only if audit is required.

### 7.4 Reconstruction Service Design

- **Idempotency.** Reconstruction must produce the same context given the same event stream state. This requires deterministic consumer filtering and no external state dependencies.
- **Relevance filtering.** Reconstruction policies should be workflow-type-specific. Define retrieval windows appropriate to each step: last N events, last T hours, or events matching specific type filters.
- **Graceful truncation.** When reconstructed context would exceed the target model's context window, truncation must be relevance-governed, not simply recency-governed.
- **Failure handling.** If the JetStream consumer fails mid-reconstruction, the service must restart from the last acknowledged position.

### 7.5 Routing Policy Configuration

Routing policies govern model selection and should be expressed as declarative configurations attached to workflow step definitions. A routing policy specifies:

- Minimum model capability tier required for the step.
- Maximum acceptable end-to-end latency, used to filter available providers.
- Maximum per-token cost, used to prefer less expensive providers when multiple options meet quality and latency requirements.
- Data residency requirements, approved provider lists, and prohibited data type handling rules.

## 8. Future Directions

**Adaptive Reconstruction Policies**

Current MCR reconstruction policies are statically configured at workflow design time. A natural evolution is adaptive reconstruction policies that use lightweight classification models to dynamically determine which prior context elements are most relevant to the current task. This would apply the AttnRes insight dynamically at the workflow level, eliminating the need for manual retrieval window configuration and improving reconstruction quality for workflows with highly variable context relevance profiles.

**Cross-Workflow Context Sharing**

The current architecture scopes context streams to individual workflow instances. In many enterprise scenarios, insights from one workflow instance are relevant to others: a security incident resolution informs future triage, and a successful credit decision informs risk model calibration. Cross-workflow context sharing, governed by Synadia's access control policies, would enable institutional knowledge to accumulate in the context plane rather than being siloed within individual workflow instances.

**Model Output Feedback Loops**

MCR's event stream provides a natural substrate for supervised fine-tuning data generation. Every context-response pair in the event stream is a labeled training example. Automated extraction of high-quality examples, governed by outcome feedback events, could support continuous model improvement at the enterprise level.

**Standards and Interoperability**

As MCR patterns mature, standardization of the event schema, correlation identifier format, and reconstruction policy language would enable interoperability between MCR implementations on different infrastructure providers. The relationship between MCR and MCP is an early example of this layering: a standard context protocol operating above a standard context persistence layer creates a complete, portable enterprise AI infrastructure stack.

## 9. Conclusion

Enterprise AI deployments face a structural problem that model capability improvements alone cannot resolve. The stateless API architecture underlying current LLM deployments creates a context reconstruction tax that scales with workflow complexity, driving up token costs, degrading service levels, and making SLA enforcement effectively impossible for multi-step processes.

Model Context Routing addresses this at the infrastructure layer. By externalizing context into a persistent, event-driven NATS/JetStream layer governed by the Synadia control plane, MCR transforms context from an ephemeral prompt artifact into a durable, queryable, tenant-isolated workflow resource. This enables selective context reconstruction, delivering only the relevant prior state to each model invocation rather than re-injecting the full workflow history uniformly.

The cost estimation framework in Section 5 demonstrates that this selective reconstruction, calibrated to a relevance ratio of 0.35, reduces per-workflow input token consumption by 55 to 62 percent across the three representative enterprise workflow profiles modeled. At enterprise model pricing, these reductions translate to six-figure annual savings for moderate deployment volumes, with the benefit scaling with workflow complexity and invocation frequency.

This approach applies at the infrastructure level the same principle that the Attention Residuals research validates at the model architecture level: selective, learned aggregation over prior representations outperforms uniform accumulation. MCR is an architectural abstraction, a pattern for how enterprise systems should manage AI context at scale. Its reference implementation on NATS, JetStream, and Synadia provides a production-ready foundation, and its relationship with MCP, REST APIs, and CLI tools is complementary: existing invocation protocols become the ingress mechanisms for an infrastructure layer that has, until now, been absent from the enterprise AI stack.

## References

- Kimi Team (Moonshot AI). Attention Residuals. arXiv:2603.15031, March 2026. https://arxiv.org/abs/2603.15031

- Liu, N. F., Lin, K., Hewitt, J., Paranjape, A., and Liang, P. Lost in the Middle: How Language Models Use Long Contexts. Transactions of the Association for Computational Linguistics, 2024.

- Anthropic. Model Context Protocol Specification. modelcontextprotocol.io, 2024.

- Synadia Communications. NATS.io Documentation. docs.nats.io, 2026.

- IDC. The Future of AI is Model Routing. IDC FutureScape 2026: AI and Automation Predictions, December 2025.

## Appendix A: Implementation Checklist

The following checklist summarizes the key implementation decisions for an MCR deployment on Synadia. Steps are ordered by dependency.

1. Define subject taxonomy aligned to tenant, domain, workflow type, and event type.
2. Configure JetStream streams per domain with retention policies matched to compliance requirements.
3. Implement correlation identifier generation and propagation for all workflow-initiating events.
4. Deploy ingress adapters for each protocol gateway: MCP endpoint normalization, REST webhook handlers, and CLI event publishers.
5. Implement context reconstruction services with workflow-type-specific retrieval policies and relevance-governed truncation.
6. Configure Synadia control plane access policies for per-tenant stream isolation and cross-workflow context sharing policies.
7. Implement routing policy configuration and model provider integration.
8. Deploy monitoring for token consumption, latency, and reconstruction efficiency metrics.

## Appendix B: Sample Source Code

The sample source code demonstrating the MCR proof of concept is available in the `src/` directory. The implementation consists of four production-structured modules:

- **context_plane.py** - Manages JetStream lifecycle, event publication with correlation ID embedded in subject hierarchy, and semantic relevance reconstruction
- **mcp_server.py** - Implements JSON-RPC 2.0 MCP server with tool dispatch
- **mcr_orchestrator.py** - Contains the routing engine and semantic reconstruction bridge
- **mcr_poc_runner.py** - End-to-end demonstration runner

To run against a live model, export `ANTHROPIC_API_KEY` and replace the `RESPONSES` list in `mcr_orchestrator.py` with calls to `client.messages.create()`.

## POC Results Summary

| Step | Stateless tokens | MCR tokens | Eliminated | Reduction | Model |
|------|------------------|------------|------------|-----------|-------|
| 0 | 101 | 101 | 0 | 0.0% | haiku |
| 1 | 273 | 200 | 73 | 26.7% | haiku |
| 2 | 449 | 204 | 245 | 54.6% | sonnet |
| 3 | 620 | 295 | 325 | 52.4% | sonnet |
| 4 | 788 | 333 | 455 | 57.7% | sonnet |
| **Total** | **2,231** | **1,133** | **1,098** | **49.2%** | |
