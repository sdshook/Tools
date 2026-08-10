# FORVM
**(c) 2026, Shane D. Shook, All Rights Reserved**

**FORVM** (Forensic VM) is an agentic, human-on-the-loop (HOTL) DFIR
workstation. It combines standard open-source forensic tooling (plaso,
Volatility3, The Sleuth Kit, bulk_extractor, YARA, tshark) with a
Claude-driven investigation loop that works through a case playbook,
cites every finding back to raw evidence, and never concludes anything
without the checks required to defend that conclusion. A human examiner
directs the investigation and reviews every finding; the agent's job is
to do exhaustive, well-cited legwork, not to make unsupervised calls on
a case.

Everything here is provisioned by a single build script
(`build_dfir_vm.py`) onto a clean Ubuntu 22.04/24.04 VM. The resulting
system is referred to below as **dfir.py**: the running console, agent,
and toolset the build script produces.

---

## What dfir.py does

dfir.py is the deployed system: an interactive console (`dfir_cli.py`) backed
by an agent loop (`agent.py`) that has read-only tool access to a fixed
set of forensic utilities. At a high level, a session looks like this:

1. Open (or resume) a **case**: case reference, examiner, org, case
   type, and description are captured interactively.
2. **Process evidence**: mount an image read-only from one location
   (decrypting first if it's BitLocker- or LUKS-encrypted), hash it for
   chain of custody, and build a plaso timeline written to a SEPARATE
   output location, never back to the evidence mount or source, and
   never to the VM's own disk. Repeatable per evidence item, so a case
   with a workstation image *and* a USB image processes both, and every
   later citation is attributed to the specific source it came from.
3. **Run the case's playbook**: a fixed set of investigative questions
   (see *Skills Catalog* below) that the agent works through one at a
   time, querying plaso/Volatility/tshark/bulk_extractor/YARA as needed,
   citing every claim to a specific tool result, and refusing to
   conclude a negative finding until every required check has actually
   been run.
4. **Ask anything else**: free-form questions outside the fixed
   playbook route through the same tool-calling, citation, and logging
   discipline.
5. **Verify, expand, or challenge findings**: independently re-run a
   question and get flagged if the result disagrees with (or drifts in
   confidence from) the prior run. Nothing is ever silently overwritten;
   every prior version is retained.
6. **Draft a report**: a deterministic (no-LLM) assembly of everything
   recorded in the case, clearly marked as an unreviewed draft.

Every tool call, every agent decision, and every word exchanged with the
examiner is logged to the case directory in three separate,
hash-chained files (see *Logging & Chain of Custody* below). dfir.py is
built around the assumption that findings may need to be defended later,
not just produced quickly.

---

## Project structure

```
/opt/dfir-agent/                  (created by build_dfir_vm.py - metadata only)
├── evidence/                     read-only evidence mount point (chmod 555);
│                                  legacy/manual mount location. /process
│                                  writes to your chosen external storage root instead
├── cases/
│   └── <case_id>/
│       ├── case_meta.json        case reference, examiner, type,
│       │                          evidence_mount_root, output_storage_root, dates
│       ├── keywords.txt          search terms for /kw_search (one per line, # comments)
│       ├── evidence_index/
│       │   └── manifest.json     one entry per processed evidence source, pointing at
│       │                          wherever that source's mount + .plaso file actually live
│       ├── findings/
│       │   └── findings.json     current + historical findings per question
│       ├── report/
│       │   └── report_draft_*.md deterministic draft reports
│       └── logs/
│           ├── tool_calls.jsonl          every tool invocation
│           ├── processing_actions.jsonl  agent decisions/state transitions
│           └── user_prompts.jsonl        examiner <-> agent dialogue ONLY
├── tools/
│   ├── plaso_tool.py             log2timeline/psort wrapper, multi-source aware
│   ├── volatility_tool.py        volatility3 plugin wrapper (JSON output)
│   ├── bulk_extractor_tool.py
│   ├── pcap_tool.py              tshark wrapper
│   ├── yara_tool.py              on-disk YARA scanning (distinct from
│   │                              volatility's in-memory yarascan)
│   ├── evidence_tool.py          mount/decrypt/hash: deterministic,
│   │                              never exposed to the LLM
│   ├── keyword_search_tool.py    grep-based search, PST/OST/EDB extraction,
│   │                              export + hashing: also never exposed to the LLM
│   ├── mobile_backup_tool.py     Android/iOS backup extraction (ALEAPP/iLEAPP,
│   │                              android-backup-extractor): also never exposed to the LLM
│   ├── case_logger.py            hash-chained three-log-stream writer
│   └── audit_log.py
├── playbooks/                    the skills catalog, see below
│   ├── bad_leaver.yaml
│   ├── malware_process_ioc.yaml
│   └── host_compromise.yaml
├── agent.py                      the tool-calling loop, caching, validation
├── dfir_cli.py                  the interactive console
└── .env                          CLAUDE_API_KEY (chmod 600, root-only)
```

Evidence is mounted read-only from one location, and all processing
output (plaso timelines and anything else generated during `/process`)
is written to a completely SEPARATE location, chosen independently.
Nothing is ever written back to the evidence mount or the evidence
source itself:

```
<evidence_mount_root>/<case_id>/<source_id>/
└── mnt/                          read-only mount tree (EWF/BitLocker/LUKS as applicable)

<output_storage_root>/<case_id>/<source_id>/
└── <source_id>.plaso             plaso timeline for this evidence source
```

`dfir_cli.py` prompts for both locations separately (at case creation, and
again per source during `/process`, defaulting to the case-level
choice) and refuses a path that overlaps the other, so the mount tree
and the output tree can never collide.

A desktop launcher ("DFIR Agent Console") is installed to the
applications menu and, if run via `sudo`, to the invoking user's Desktop.

---

## Requirements

- **OS:** Ubuntu 22.04 or 24.04, run as root (or via `sudo`).
- **Claude API key:** passed via `--claude-api-key`, the `CLAUDE_API_KEY`
  environment variable, or an interactive hidden prompt if neither is
  given.
- **Network access** for `apt` and `pip` package installation during
  build.
- **Disk space:** evidence storage is deliberately *not* tied to the
  VM's own disk. At case creation (and again, overridable, at each
  `/process` run) you're prompted for two separate locations: an
  **evidence mount location** (read-only; where evidence images are
  mounted from) and an **output storage location** (where plaso
  timelines and other processing output are written). The two are
  never allowed to overlap, and nothing is ever written back to the
  evidence mount or source. `dfir_cli.py` also checks whether either path
  resolves onto the VM's own filesystem and warns (without blocking) if
  so, since the expectation is that neither evidence nor its outputs
  live on the VM itself. Only case metadata, logs, and findings (all
  small) are stored under `/opt/dfir-agent`.

### Installed via `apt`
`build-essential`, `git`, `curl`, `wget`, `python3`/`pip`/`venv`/`dev`,
`libewf-dev`/`ewf-tools` (E01 support), `afflib-tools` (AFF support),
`sleuthkit` (TSK), `testdisk` (photorec), `yara`, `tshark`, `tcpdump`,
`cryptsetup` (LUKS), `ntfs-3g`, `pst-utils` (readpst, for PST/OST mail
containers, falls back to a source-build note if unavailable),
`libesedb-utils` (esedbexport, for EDB/Exchange ESE databases, same
fallback behavior), `python3-tk`/`default-jre` (ALEAPP/
android-backup-extractor dependencies), `docker.io`/`docker-compose-v2`
(optional, for Timesketch), `jq`, `bulk-extractor` (falls back to a
source-build note if unavailable in a given release's repos), and
`libbde-utils` (BitLocker support, same fallback behavior).

### Installed via `pip` (into a dedicated venv at `/opt/dfir-agent/venv`)
`plaso`, `volatility3`, `anthropic`, `pyyaml`, `pandas`,
`timesketch-import-client`, `python-dotenv`.

### Installed via git clone (mobile forensic tooling)
ALEAPP and iLEAPP (the [LEAPP family](https://leapps.org/), open source
and actively maintained) are cloned into `tools/vendor/` and their own
`requirements.txt` installed into the venv. android-backup-extractor is
cloned and built via its gradle wrapper for extracting adb backup (.ab)
files. Each step is wrapped so a failure doesn't abort the whole
install; mobile evidence support just won't be available until resolved
manually. Skip this step entirely with `--skip-mobile-tools` if it
isn't needed.

### Not included
Timesketch itself (docker-compose stack) and Zeek are deliberately left
out: tshark/tcpdump plus bulk_extractor cover pcap analysis without the
extra log-format reconciliation Zeek would require.

---

## Running dfir.py

```bash
sudo python3 build_dfir_vm.py --claude-api-key sk-ant-...
# or, to keep the key out of shell history:
sudo CLAUDE_API_KEY=sk-ant-... python3 build_dfir_vm.py

source /opt/dfir-agent/venv/bin/activate
python3 /opt/dfir-agent/dfir_cli.py
```

---

## CLI / help menu reference

Typing `/help` (or `/?`) inside the console prints this list at any time:

| Command | Description |
|---|---|
| `/help`, `/?` | Show the command list. |
| `/case` | Create a new case and switch the running session to it; no restart needed. |
| `/process` | Process one evidence item - prompts for Evidence Type (mobile/cloud/PC/Storage) and branches accordingly: PC/Storage mounts a disk image (decrypting if needed) and builds a plaso timeline; mobile extracts an Android adb backup or runs ALEAPP/iLEAPP against the extraction; cloud unpacks an export archive (e.g. Google Takeout) if zipped. Run once per evidence item; each gets its own labeled `source_id`. Read location and output location are always chosen separately and can never overlap; neither is ever the VM's own disk. Entirely deterministic: never routes through the LLM, and credentials are never written to any log. |
| `/kw_search` | Search every processed evidence source against the terms in `keywords.txt` (creates a template on first run if missing), including extracting PST/OST/EDB/mbox mail containers first (mbox covers Google Takeout/Vault Gmail exports) so their contents are searchable too. Works uniformly across all Evidence Types - PC/Storage mounts, mobile extractions, and cloud exports. Every responsive file is copied to an export destination you choose, classified into `docs`/`pics`/`vids`/`emails` by extension, hashed (SHA-256), and recorded in both an export manifest and the case's audit log. Entirely deterministic: never routes through the LLM. |
| `/playbook` | List every question in the current case's playbook. |
| `/findings` | Show all findings recorded so far for this case. |
| `/run <id>` | Run (or re-run fresh) a specific playbook question. |
| `/verify <id>` | Independently re-run a question. Flags a `*** VERIFICATION DISAGREEMENT ***` if the verdict changed, or a confidence-drift notice if the verdict held but confidence moved; both versions are always preserved, never silently overwritten. |
| `/expand <id>` | Re-run a question with the agent instructed to look beyond the playbook's listed checks. |
| `/why-not <id>` | Show the recorded finding for a question without making any new tool or API call (read-only, zero cost). |
| `/report` | Assemble a draft Markdown report from `findings.json`. Deterministic (no LLM summarization), and headed with an explicit "unreviewed draft" notice. |
| `/exit`, `/quit` | Close the session. |
| *(anything else)* | Sent to the agent as a free-form question: identical tool access, citation requirements, and logging as a playbook question, just not tied to a fixed question ID. |

Any input starting with `/` that isn't one of the above is rejected with
a pointer back to `/help`, rather than being silently forwarded to the
model as a question.

---

## Evidence types

`/process` prompts for an **Evidence Type** per source, which determines
how it's processed:

- **PC / Storage** - a disk image (workstation, external drive, USB).
  Mounted (EWF if `.E01`/`.Ex01`), decrypted if BitLocker or LUKS, and
  built into a plaso timeline. This is the original flow, unchanged.
- **mobile** - prompts for platform (Android or iOS):
  - Android: an adb backup (`.ab`) is unpacked via
    android-backup-extractor first; an already-extracted directory or a
    `.tar`/`.zip`/`.gz` extraction goes straight to ALEAPP.
  - iOS: run against an already-decrypted iTunes/Finder backup directory
    or a filesystem extraction. **This does not decrypt an encrypted
    backup itself** - iLEAPP has no built-in handling for Apple's backup
    encryption, so provide a decrypted directory or an unencrypted
    extraction.
  - No plaso timeline is produced for mobile sources; the raw extracted
    data is what `/kw_search` later searches, and the ALEAPP/iLEAPP HTML/
    TSV report is kept alongside it for reference.
- **cloud** - a cloud export such as Google Takeout. A `.zip` is
  extracted automatically; anything else is used as-is. No plaso
  timeline or mobile-tool report is produced; the source is registered
  directly for `/kw_search`, which already handles mbox mail (Takeout's
  Gmail format) and plain JSON/HTML content within it.

Every evidence type shares the same read/output location separation and
same-filesystem safety check described above, and every source -
regardless of type - is searchable by `/kw_search` uniformly, since that
command works off each source's `final_mount` path rather than assuming
a disk-image layout.

---

## Keyword search

`/kw_search` reads search terms from `keywords.txt` in the case
directory (one term or regex per line; lines starting with `#` are
ignored). If the file doesn't exist, `/kw_search` creates a template
and stops so you can fill it in before the first real run.

It searches every evidence source registered for the case via `grep`
across the mounted content, including anything extracted from PST/OST
mail containers (`readpst`), EDB/Exchange databases (`esedbexport`), or
mbox files (Python's stdlib `mailbox` module) found within the mount
tree. mbox covers Google Takeout and most Google Vault Gmail exports
(Vault can also export to PST, already covered by the PST/OST path);
each message is split out individually before searching, so a match
inside a multi-gigabyte mbox exports just that message, not the whole
container. EDB extraction yields raw ESE table data for search
purposes, not fully reconstructed message threads; treat EDB hits as
leads pointing at raw records rather than polished emails. True
Exchange mailbox reconstruction from EDB typically needs specialized
tooling beyond what's open-source here.

Every responsive file is copied to an export destination you choose
(prompted the same way as the evidence/output locations, and checked
against the VM's own filesystem the same way) and classified by
extension into one of four subfolders:

```
<export_destination>/<case_id>/exports/
├── docs/
├── pics/
├── vids/
├── emails/
└── export_manifest.jsonl
```

Each exported file is renamed with a short SHA-256 prefix to avoid
collisions between same-named files from different sources, without
losing the original filename. Every export is recorded twice: once in
`export_manifest.jsonl` (original path, source, matched keyword,
exported filename, SHA-256) and once as a `file_exported` entry in the
case's hash-chained `processing_actions.jsonl`, so the export record
carries the same chain-of-custody guarantees as everything else in the
case.

---

## Skills catalog (playbooks)

Playbooks are YAML files under `playbooks/`; each is a case type
("skill") the agent knows how to investigate. A playbook is a list of
questions, each mapping to the specific tool checks required to answer
it, plus two optional validation flags:

- `negative_requires_all_checks: true`, meaning every listed check must
  be run via a tool call before the agent may conclude the question is
  `not_supported`.
- `positive_requires_corroboration: true`, meaning a `supported` finding
  needs evidence from at least two independent tool sources, or an
  explicit `corroboration_note` justifying why a single source (e.g. an
  exact hash match) is sufficient on its own.

### `bad_leaver` (insider-threat / departing-employee investigations)
| Question | Checks |
|---|---|
| Exfil to personal cloud storage | plaso (browser history, prefetch sync clients), tshark (upload volume), volatility (sync process running); negative requires all, positive requires corroboration |
| Mass download spike before resignation | plaso (MFT/USN baseline comparison, RecentDocs/ShellBags) |
| USB exfiltration | plaso (USB registry history, file copy events) |
| Mail forwarding rules / mass export | external audit log (O365/Workspace, not covered by plaso/TSK) |
| Anti-forensic activity near departure | plaso (USN deletion events), bulk_extractor (unallocated space), volatility (crash dumps / wiper processes) |
| Malicious process in memory | volatility (malfind/pslist/netscan/cmdline); positive requires corroboration |

### `malware_process_ioc` (malware identification & IOC extraction)
| Question | Checks |
|---|---|
| Malicious/anomalous processes | volatility (pstree anomalies, psscan hidden processes, malfind, ldrmodules), YARA; negative requires all, positive requires corroboration |
| Persistence mechanisms | plaso (run keys, scheduled tasks), volatility (services) |
| Network IOCs (C2, beaconing) | tshark (beaconing pattern, suspicious DNS), volatility (netscan); positive requires corroboration |
| File-based IOCs | volatility (dumped/hashed files), bulk_extractor (carved PE strings), plaso (execution timeline) |
| IOC compilation | synthesis step: every exported IOC must trace back to a `finding_id` from an earlier question, never invented fresh |

### `host_compromise` (host-level intrusion analysis)
| Question | Checks |
|---|---|
| Initial access vector | plaso (exploit artifacts, RDP/SMB logons), volatility (process creation near intrusion window); negative requires all, positive requires corroboration |
| Privilege escalation | plaso (UAC bypass/token manipulation), volatility (privilege tokens); positive requires corroboration |
| Lateral movement | plaso (RDP/PsExec/WMI logons), tshark (SMB/RDP/WinRM to other hosts) |
| Persistence | plaso (run keys/services/scheduled tasks), volatility (services) |
| Data staging/exfil | plaso (archive creation), bulk_extractor (unallocated space), tshark (upload volume) |
| Anti-forensic activity | plaso (event log clearing, timestomping via MFT SI/FN mismatch) |

Adding a fourth playbook is just dropping a new `<name>.yaml` file
following this same schema into `playbooks/`. `dfir_cli.py` discovers
playbooks dynamically at case-creation time, no code changes required.

---

## Validation architecture

dfir.py treats "the agent said so" as insufficient on its own. Every
finding is subject to:

- **Citation discipline**: every claim must be backed by a specific
  tool-returned `result_ref`, traceable through `tool_calls.jsonl`.
- **Plaso-first, minimum three queries**: for any plaso-required check,
  the agent must try at least three differently-scoped queries before
  concluding plaso lacks the answer; a single narrow empty result is
  never sufficient grounds to move on.
- **Native extraction fallback**: if plaso and the other bound tools
  genuinely can't answer a check, the agent proposes an exact tool and
  command (`suggest_native_extraction`) for the human examiner to run,
  rather than fabricating a result.
- **Negative-finding guard** (false negatives): `not_supported` can't
  be concluded on a question requiring it until every listed check has
  actually been invoked.
- **Corroboration guard** (false positives): `supported` findings on
  flagged questions need two independent tool sources or an explicit
  justification for relying on one.
- **Verification diffing** (reproducibility): `/verify` compares an
  independent re-run against the prior finding and flags both outright
  disagreement and same-verdict confidence drift. The code only ever
  *detects and surfaces* a discrepancy; it never auto-resolves one. The
  human examiner decides what it means, and both versions stay on
  record under `history` in `findings.json`.
- **Multi-source attribution**: when a case has more than one processed
  evidence item, every plaso event is tagged with
  `_evidence_source_id`, and the agent is required to name which source
  a citation came from.

---

## Logging & chain of custody

Every case directory carries three **separate** log streams, each
hash-chained (every entry stores the SHA-256 of the previous entry, so
tampering or reordering is detectable):

- `tool_calls.jsonl`: every tool invocation, with arguments and a
  pointer to the result.
- `processing_actions.jsonl`: agent-level decisions and state
  transitions (checks completed, findings accepted or rejected,
  verification outcomes, evidence processing steps).
- `user_prompts.jsonl`: only the examiner <-> agent dialogue, kept
  deliberately separate from the two logs above.

Evidence handling is designed around the same principle: images are
SHA-256 hashed before mounting, mounted strictly read-only, and
decryption credentials are used once in-process and never written to
any log, file, or return value that could end up logged.

---

## Design principle: HOTL, not autonomous

dfir.py's agent is built to do exhaustive, well-cited legwork and
surface it for review, not to conclude a case on its own. Mounting,
decryption, and timeline construction (`/process`) are deterministic
infrastructure operations that never touch the LLM. Report drafts
(`/report`) are assembled without any LLM summarization step, so
nothing in a report can be an unsourced claim. And wherever two results
disagree, whether on a re-verify or a confidence shift, the system's
job stops at detecting and logging the discrepancy; resolving it is
always left to the human examiner.
