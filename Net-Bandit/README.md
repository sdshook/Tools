# net-bandit (proof of concept)

## Origin

net-bandit applies the method in **CPU-ARC: Agentic Reasoning Caching for on-CPU
Reasoning Reuse** (P. Belcak, G. Heinrich, S. Muralidharan, S. Diao and P. Molchanov,
NVIDIA, arXiv:2611.09891, November 2026, <https://arxiv.org/abs/2611.09891>).

The paper starts from the observation that large language models keep re-deriving the
same reasoning. It proposes **agentic reasoning caches (ARCs)**: a capable model's
reasoning trace for one problem is compiled into small, parameterized, CPU-executable
functions that can be reused on every new instance of the same problem class. An agent
consults the cache first and calls the full model only on a miss. The paper reports
caches matching or beating the source model's accuracy on 7 of 8 benchmarks, at 16–291x
lower cost per use, and building a cache costs 12–84x a single model query. Its
evaluation covers only math and science benchmarks. The authors describe security-style
agentic workloads, where the instructions repeat and the payloads vary, as a target but
don't test them.

## What this proof of concept demonstrates

net-bandit tests whether ARC transfers to cyber defense, using a deliberately simple
host intrusion detection system (HIDS) for Windows. The first time it sees a *class* of
event (a process start, logon, network connection or service install, with the variable
details abstracted away), it asks Claude to judge the event and to compile a small
`judge(e)` check for the class. Later events of the same class are judged locally by
that check, in microseconds, at no token cost. Only novel activity reaches the API.

It is meant to show four things:

1. **Feasibility.** A frontier model can compile its security reasoning about Windows
   event classes into small, readable checks that run on an ordinary CPU, and those
   checks reproduce its verdicts on later events of the same class.
2. **Economics.** Token spend follows *novelty*, not event volume. In sample replays, 85%
   of decisions came from the local cache. Over 8,000 replayed events, adaptive
   spot-checking ("the bandit") cut total tokens by about 18% compared with a flat
   re-check rate.
3. **Governance.** Compiled judgment can be made safe to rely on:
   - checks return "unknown" whenever they're outside what was reasoned about;
   - each check is self-tested before use, then signed, spot-checked and revoked on
     disagreement;
   - model-written code never runs with the agent's SYSTEM rights. It executes only in a
     sandboxed worker process, keeping instructions and data separate.
4. **Practicality.** All of this fits in a lightweight agent built on native Windows
   APIs. It reports through the standard Windows Security event log and stays out of
   the way of the OS and applications.

What it does **not** yet prove:
- **Detection accuracy against real attacks.** The replay figures above used a built-in
  stand-in for Claude, not live Claude calls.
- **That the Windows-native components work on real hosts.** They haven't been run on
  Windows yet; `net-bandit doctor` checks them.
- **Real per-host token costs.** These depend on how varied each machine's activity is.

The paper's caches also use a small fine-tuned language model for language-based steps.
net-bandit's checks are deterministic code only.

## How it works

```
native Windows APIs ──▶ normalize ──▶ class key ──▶ local entry? ──hit──▶ verdict
 (wevtapi, iphlpapi,                                     │
  kernel32, ntdll,                                      miss / "unknown"
  wintrust)                                              ▼
                                        Claude: analyze + compile judge(e)
                                                         │
                                validate (AST allowlist) → self-test → sign → store
```

## What it collects (all native, via ctypes)

| Source | DLL / API | Events |
| --- | --- | --- |
| Event Log subscriptions | `wevtapi.dll` EvtSubscribe / EvtNext / EvtRender | Security 4688, 4624, 4625, 4720, 4732, 4698, 1102 · System 7045 · Sysmon 1, 3 · PowerShell 4104 · Defender 1116/1117 |
| TCP tables | `iphlpapi.dll` GetExtendedTcpTable (IPv4 + IPv6) | New listeners and established connections, with owning PID |
| Process snapshots (fallback) | `kernel32` Toolhelp32, QueryFullProcessImageNameW; `ntdll` NtQueryInformationProcess; `advapi32` token user | New processes when neither Sysmon nor 4688 is available |
| Signature state | `wintrust.dll` WinVerifyTrust + CryptCATAdmin catalog lookup | embedded / catalog / unsigned / invalid for each new executable |

## Quick start (Windows, Python 3.11+ 64-bit)

For a full installation that runs as SYSTEM at startup, follow **[install.md](install.md)**.

```powershell
py -m venv .venv; .venv\Scripts\activate
pip install -e .[dev]

# 1. Offline demo: no API key, fake analyzer
net-bandit replay samples\windows_events.jsonl --fake-llm --passes 3

# 2. Check the native collectors (run from an elevated prompt)
net-bandit doctor

# 3. Live, with Claude
$env:ANTHROPIC_API_KEY = "sk-ant-..."
copy config.example.toml config.toml
net-bandit -c config.toml run
```

Run elevated: the Security and Sysmon channels need admin rights. For useful process
events, either install Sysmon or enable *Audit Process Creation* plus *Include command
line in process creation events* in Group Policy.

## Operating it

```powershell
net-bandit entries                 # compiled entries, hits, differential results
net-bandit show 3                  # an entry's class template and code
net-bandit approve 3               # promote a pending entry
net-bandit revoke 3                # remove an entry; its class goes back to Claude
net-bandit stats                   # hit rate, tokens used, tokens avoided, est. spend
```

Alerts (suspicious and malicious verdicts) are appended to `<data_dir>\alerts.jsonl`.

## How the token savings work

- **Class keys.** Events are reduced to a template: user names, IPs, numbers, GUIDs and
  base64 become placeholders, and paths become buckets such as `<SYSTEM32>` or
  `<USERTEMP>`. Fifty failed logons from different IPs and usernames are one class.
- **Compiled entries.** On a miss, Claude returns a verdict and, when the class is
  stable, a `judge(e)` function. The entry must return `unknown` for anything outside
  what was reasoned about, which sends that event back to Claude.
- **Cheaper calls where possible.** Verdict-only checks go to a smaller model. The
  system prompt is marked for prompt caching. Classes Claude declines to compile get
  verdict-only calls instead of repeated compile attempts.
- **Budget.** A daily token cap; over the cap, misses are recorded as `unknown`.
- `stats` estimates tokens avoided as cache hits × average tokens per verdict-only call.

## Lookup path and near-miss retrieval

- **Front cache.** Active entries are held in an in-memory LRU (4,096 classes) in front
  of SQLite, so a hit costs a dictionary lookup plus the entry's run time. SQLite stays
  the durable copy. When you run `approve` or `revoke` from another shell, the running
  agent notices within a second (via SQLite's `data_version`) and reloads.
- **Near-miss retrieval (advisory only).** Every judged class is indexed by the tokens
  in its template. On a miss, the three closest known classes and their verdicts go to
  Claude as context, and the decision records a **novelty** score: 1.0 means unlike
  anything seen before. Similarity never decides a verdict, because an attacker's
  lookalike would then inherit the benign verdict of the thing it imitates.

## Windows Security log output

net-bandit writes its detections to the standard **Security** log as a registered
third-party audit source named **net-bandit**, using the `authz.dll` audit API
(`AuthzInstallSecurityEventSource`, `AuthzRegisterSecurityEventSource`,
`AuthzReportSecurityEvent`). Windows protects the Security log, so there are three
requirements. `net-bandit doctor` checks all of them.

1. **Run as SYSTEM, or another account with "Generate security audits"
   (`SeAuditPrivilege`).** Administrators don't hold this right by default. The simplest
   route is `net-bandit -c C:\ProgramData\net-bandit\config.toml install-task`, which
   registers a startup task running as SYSTEM. Set an absolute `data_dir`, and put your API
   key in `api_key_file` (ACL'd to SYSTEM and Administrators), because SYSTEM can't see
   your user environment variables.
2. **Register the source once,** elevated. This happens automatically on the first run as SYSTEM.
3. **Enable "Application Generated" auditing,** or Windows silently drops the events:
   `auditpol /set /subcategory:"Application Generated" /success:enable`

Event IDs are in the 7100–7199 range. Windows' own security auditing uses 1100–1108 and
4608–6424, so SIEM rules keyed on event ID won't misfire.

| ID | Severity | Meaning |
| --- | --- | --- |
| 7100 | info | Agent started |
| 7101 | info | New compiled entry installed |
| 7102 | info | High-novelty observation (benign but unlike anything seen; threshold `log_novelty_above`) |
| 7110 | warning | Suspicious observation |
| 7111 | error | Malicious observation |
| 7120 | warning | Entry revoked (runtime error or repeated disagreement) |
| 7121 | warning | Entry disagreed with Claude on a spot-check |
| 7122 | error | Entry failed its integrity check (possible tampering) |
| 7123 | warning | Model produced an entry that failed validation |
| 7130 | warning | Daily token budget reached (logged once a day) |
| 7131 | warning | Claude analysis call failed |

Each record is an **audit success**. Severity is carried as a field, so "Audit Failure"
keeps its usual meaning of a failed access attempt. The insertion strings
(`EventData/Data[1..9]`) are, in order: message (summary plus JSON details), severity,
verdict, event kind, host, class key, entry ID, novelty, confidence. These fixed
positions make SIEM parsing simple. For example, collect Security events with provider
`net-bandit` and IDs 7110, 7111 and 7122 through Windows Event Forwarding.

net-bandit's own Security log subscription only asks for specific Windows event IDs,
so it never reads its own 71xx events.

If the Security log can't be written (missing privilege or policy), net-bandit says so
and carries on. Alerts still go to `alerts.jsonl`. Set `fallback_to_application = true`
to use the Application log instead, or `target = "application"` to choose it outright.

## Adaptive spot-checking (the "bandit")

A sample of cache hits from approved entries is re-judged by Claude to catch drift or a
bad entry. Rather than a flat rate, net-bandit uses Thompson sampling: each entry keeps a
Beta posterior over how often Claude would disagree with it, and every hit draws from it.

- **Routine, always-correct classes** fall towards the **1% floor**.
- **Risky classes keep a 5% floor:** non-benign verdicts, unsigned or invalid binaries,
  privileged accounts running unsigned code, and system binary names outside System32.
- **An entry that disagrees** has its rate rise sharply. Repeated disagreement still revokes it.
- **Evidence halves every 7 days,** so trust fades and checks rise again unless agreement
  keeps renewing it.
- **Sampling uses the OS's secure RNG,** so an attacker can't predict which events get
  re-checked.
- **Pending entries keep a fixed 25%** until you approve them.

The cost is two counters and a timestamp per entry, plus one random draw per hit. In a
replay of 8,000 events with entries auto-approved, spot-check calls fell by about 37% and
total tokens by about 18% compared with a flat 5%. `net-bandit entries` shows each entry's
current spot-check rate. Set `mode = "fixed"` in `[spotcheck]` to go back to a flat rate.

## Privilege separation: model-written code never runs as SYSTEM

net-bandit treats everything that comes back from Claude as **data**, never as instructions
for the agent itself:

| From Claude | What the agent (possibly SYSTEM) does with it |
| --- | --- |
| Verdict, confidence, reason | Schema-checked and stored. Used only to label the event and write logs. Never executed. |
| A `judge(e)` check, as text | Size- and depth-checked, then **parsed** (static AST validation), signed and stored. Never executed in the agent. |

All execution of model-written checks, **including the self-test** that runs a new check
once, happens in a separate **entry worker** process. The agent sends it the check and
the event over a pipe and reads back a verdict.

- **Sandbox.** On Windows the worker runs in an **AppContainer** with no capabilities.
  That means no network (loopback included) and read access only to the Python install
  and the net_bandit package, which are granted explicitly. If an AppContainer can't be
  created, it falls back to a **restricted, low-integrity token** with every privilege
  removed. That mode doesn't block the network, so the agent locks its data folder and API
  key file down to SYSTEM and Administrators when it runs as SYSTEM.
- **Never unsandboxed.** If neither sandbox works, cached checks are **disabled**, never run
  unsandboxed (`allow_unisolated = false`). Events are then recorded as `unknown`, Security
  event 7132 is raised, and nothing is sent to Claude, so a broken sandbox can't run up costs.
- **Job object.** The worker can't start child processes, is limited to 256 MB, and dies on
  any unhandled exception.
- **What the worker holds.** No API key, no database, no signing key, no environment
  variables except `SYSTEMROOT`.
- **Kill switch.** A check that takes longer than `timeout_ms` gets its worker killed and
  restarted. This also stops hangs inside C code, such as catastrophic regex backtracking,
  which an in-process time budget can't interrupt.

`net-bandit doctor` starts the worker and probes **from inside the sandbox** whether it can
read the signing key, database or API key file, write files, or reach the network. Every
line should read "denied".

Cost: about 0.2 ms per cache hit for the pipe round trip, against 0.03 ms in-process
(measured on Linux). A Claude call takes seconds.

**Residual risk, which is about data rather than code:** prompt injection in event text
could still sway a *verdict* (for example, toward a false negative). That's what the
spot-checks, the risk-weighted floors, and the "unknown" fallback are there to catch.

## Safety controls (and their limits)

- **AST allowlist.** Entries may only use a small subset of Python, allowlisted helpers
  and string or dict methods. No imports, while loops, try, lambdas, dunders or other
  builtins.
- **Execution budget.** An opcode and time budget, enforced by a trace hook.
- **Self-test.** A new entry must reproduce Claude's verdict on the event it came from.
- **Integrity.** Entries are HMAC-signed with a local key and checked before every run.
  An entry that was tampered with or errors is revoked.
- **Manual approval by default.** New entries start *pending*. Their verdicts are used
  but labelled `cache-pending`, and they are re-checked by the model five times as often.
- **Differential checks.** A sample of cache hits is re-judged by Claude. Repeated
  disagreement revokes the entry, and on any disagreement Claude's verdict wins.
- **Prompt injection.** Event data is wrapped and labelled as untrusted evidence.

The AST allowlist and execution budget still apply inside the worker, as defence in
depth. The OS sandbox is the real boundary. Before production, also sign entries with a
key held outside the endpoint, and require more than one independent model to agree
before an entry is approved.

## Staying out of the way of the OS and apps

The `[resources]` config section is applied at startup with native calls:

| Control | API | Effect |
| --- | --- | --- |
| Background mode | `SetPriorityClass(PROCESS_MODE_BACKGROUND_BEGIN)` | Lowers CPU, I/O and memory priority together |
| Low memory priority | `SetProcessInformation(ProcessMemoryPriority)` | Under pressure, the agent's pages are trimmed before your apps' |
| EcoQoS | `SetProcessInformation(ProcessPowerThrottling)` | On hybrid Intel CPUs, the scheduler prefers efficiency cores, which have their own L2, so the agent's work evicts less of your apps' cache |
| Affinity | `SetProcessAffinityMask` | Optionally confines the agent to specific logical CPUs |
| Job object | `SetInformationJobObject` | Hard CPU-rate cap (default 5%) and a memory ceiling (default 512 MB) |
| Working-set cap | `SetProcessWorkingSetSizeEx` | Optional hard limit on resident memory |

The agent also keeps its own footprint small:
- In-memory caches are bounded: compiled entries (LRU, 256), regexes, PID names and seen sets.
- SQLite uses a 2 MB page cache and WAL, and commits in batches rather than once per event.
- Old decision records are pruned daily.
- Entries are tiny, so a cache hit touches a few kilobytes of code and data.

Every `self_report_minutes`, it logs its own working set and CPU time. For CPU cache
effects specifically, measure last-level-cache misses of your important apps with and
without the agent running, using Intel VTune or AMD uProf. Client Windows has no way
to partition the shared L3 cache. That needs server CPUs with cache allocation
technology, which is relevant later for the appliance.

## Known POC limitations

- The native collectors are untested beyond `doctor` until you run them on your machine.
- Process snapshot polling misses short-lived processes. Use Sysmon or 4688.
- A catalog hit is reported as `catalog` without a second WinVerifyTrust call against
  that catalog.
- With Sysmon installed, set `tcp_table = false` to avoid duplicate network events.
- 4104 script blocks are free-form, so expect Claude to decline to compile most of them.

## Path to a network appliance (VM or NUC)

The engine does not depend on where events come from. To move to a network device:
add network sources (TAP or SPAN through a Zeek-style sensor, NetFlow/IPFIX, DNS and
DHCP logs, 802.1X/RADIUS), add a publisher that sends decisions and new entries over
NATS/JetStream, and share the entry store so a class learned on one host or segment
protects all of them.

---

(c) 2026 Shane D. Shook. All Rights Reserved.
