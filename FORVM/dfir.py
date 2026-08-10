#!/usr/bin/env python3
"""
build_dfir_vm.py
(c) 2026, Shane D. Shook, All Rights Reserved

Provisions a base Ubuntu VM into an agentic DFIR workstation:
  - Installs plaso, volatility3, sleuthkit (TSK), bulk_extractor
  - Creates a dedicated venv + directory layout under /opt/dfir-agent
  - Scaffolds an agent harness (tool wrappers + playbook) that calls the
    Claude API for HOTL-reviewed timeline/memory/pcap analysis
  - Stores the Claude API key in a root-only env file, never in plaintext argv

Run as root (or via sudo) on a clean Ubuntu 22.04/24.04 VM:

    sudo python3 build_dfir_vm.py --claude-api-key sk-ant-... 
    # or, safer (avoids shell history / process list exposure):
    sudo CLAUDE_API_KEY=sk-ant-... python3 build_dfir_vm.py

This script only installs and wires up tooling. It does not exfiltrate,
mount, or touch any evidence itself.
"""

import argparse
import getpass
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

INSTALL_ROOT = Path("/opt/dfir-agent")
VENV_DIR = INSTALL_ROOT / "venv"
ENV_FILE = INSTALL_ROOT / ".env"


def run(cmd, **kwargs):
    print(f"\n$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def require_root():
    if os.geteuid() != 0:
        sys.exit("This script must be run as root (sudo). Aborting.")


def apt_install(packages):
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    # Preseed tshark's dumpcap prompt (allow non-root capture group) so
    # install doesn't hang waiting for interactive input.
    subprocess.run(
        ["debconf-set-selections"],
        input="wireshark-common wireshark-common/install-setuid boolean true\n",
        text=True, check=True,
    )
    run(["apt-get", "update", "-y"], env=env)
    run(["apt-get", "install", "-y"] + packages, env=env)


def install_system_deps():
    print("\n=== Installing base OS + forensic tooling packages ===")
    base_pkgs = [
        "build-essential", "git", "curl", "wget",
        "python3", "python3-pip", "python3-venv", "python3-dev",
        "libewf-dev", "ewf-tools",           # E01 image support
        "afflib-tools",                       # AFF image support
        "sleuthkit",                          # TSK (fls, icat, mmls, etc.)
        "testdisk",                           # photorec, useful alongside bulk_extractor
        "yara",
        "tshark", "tcpdump",                  # pcap analysis (no Zeek dependency)
        "cryptsetup",                          # LUKS volume decryption
        "ntfs-3g",                             # mounting decrypted NTFS volumes read-only
        "docker.io", "docker-compose-v2",     # for Timesketch stack
        "jq",
    ]
    apt_install(base_pkgs)

    # libbde-utils (bdemount, for BitLocker) is not in every Ubuntu release's
    # default repos - try it, fall back to a note rather than failing the
    # whole install.
    print("\n=== Installing BitLocker (libbde) support ===")
    try:
        apt_install(["libbde-utils"])
    except subprocess.CalledProcessError:
        print(textwrap.dedent("""
            WARNING: libbde-utils (bdemount) not available via apt on this
            release. BitLocker-encrypted evidence will need it built from
            source before /process can decrypt BitLocker volumes:
              git clone https://github.com/libyal/libbde.git
              cd libbde && ./synclibs.sh && ./autogen.sh && ./configure && make && make install
        """))

    # bulk_extractor: try apt first, fall back to source build notes
    print("\n=== Installing bulk_extractor ===")
    try:
        apt_install(["bulk-extractor"])
    except subprocess.CalledProcessError:
        print(textwrap.dedent("""
            WARNING: bulk-extractor not available via apt on this release.
            Build from source after this script finishes:
              git clone --recursive https://github.com/simsong/bulk_extractor.git
              cd bulk_extractor && ./bootstrap.sh && ./configure && make && make install
        """))


def create_dirs():
    print("\n=== Creating directory layout under /opt/dfir-agent ===")
    dirs = [
        INSTALL_ROOT,
        INSTALL_ROOT / "evidence",       # read-only mounts go here
        INSTALL_ROOT / "cases",          # per-case working dirs (plaso storage, vol output)
        INSTALL_ROOT / "tools",          # agent tool wrapper modules
        INSTALL_ROOT / "playbooks",      # question -> artifact/tool checklists
        INSTALL_ROOT / "logs",           # audit log of every tool call the agent makes
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    # evidence dir should never be writable by the agent process
    os.chmod(INSTALL_ROOT / "evidence", 0o555)


def create_venv_and_python_deps():
    print("\n=== Creating Python venv and installing analysis + agent deps ===")
    if not VENV_DIR.exists():
        run(["python3", "-m", "venv", str(VENV_DIR)])
    pip = str(VENV_DIR / "bin" / "pip")
    run([pip, "install", "--upgrade", "pip"])
    run([pip, "install",
         "plaso",            # log2timeline/psort
         "volatility3",
         "anthropic",        # Claude API SDK
         "pyyaml",
         "pandas",
         "timesketch-import-client",
         "python-dotenv",
         ])


def write_env_file(api_key: str):
    print(f"\n=== Writing Claude API key to {ENV_FILE} (root-only, chmod 600) ===")
    ENV_FILE.write_text(f"CLAUDE_API_KEY={api_key}\n")
    os.chmod(ENV_FILE, 0o600)


def write_playbooks():
    playbooks_dir = INSTALL_ROOT / "playbooks"
    print(f"\n=== Writing playbook library to {playbooks_dir} ===")

    (playbooks_dir / "bad_leaver.yaml").write_text(textwrap.dedent("""\
        # Bad-leaver / insider-threat playbook
        # Each question maps to required tools/artifacts. The agent must run
        # ALL listed checks before marking a question "not_supported" -
        # this is what makes negative findings defensible.
        case_type: bad_leaver
        questions:
          - id: exfil_personal_cloud
            question: "Did the user exfiltrate data to personal cloud storage before departure?"
            checks:
              - tool: plaso
                target: browser_history_cloud_domains
              - tool: plaso
                target: prefetch_sync_client_execution
              - tool: tshark
                target: upload_volume_to_cloud_ip_ranges
              - tool: volatility
                target: cloud_sync_process_running
            negative_requires_all_checks: true
            positive_requires_corroboration: true

          - id: mass_download_before_resignation
            question: "Was there a spike in file access/download volume in the N days before resignation?"
            checks:
              - tool: plaso
                target: mft_usn_file_access_baseline_comparison
              - tool: plaso
                target: recentdocs_shellbags

          - id: usb_exfil
            question: "Was removable media used to copy data off the host?"
            checks:
              - tool: plaso
                target: usb_device_registry_history
              - tool: plaso
                target: file_copy_events_to_removable_volume

          - id: email_exfil
            question: "Were mail forwarding rules or mass mailbox exports created?"
            checks:
              - tool: external_log
                target: o365_workspace_audit_log
                note: "Not covered by plaso/TSK - requires audit log export ingested separately."

          - id: anti_forensic_activity
            question: "Is there evidence of log/file deletion or anti-forensic tooling near departure?"
            checks:
              - tool: plaso
                target: usn_journal_deletion_events
              - tool: bulk_extractor
                target: carved_artifacts_in_unallocated_space
              - tool: volatility
                target: crashdump_or_terminated_wiper_process

          - id: malicious_process_memory
            question: "Any malicious/anomalous processes or injected code in memory at capture time?"
            checks:
              - tool: volatility
                target: malfind_pslist_netscan_cmdline
            positive_requires_corroboration: true
        """))

    (playbooks_dir / "malware_process_ioc.yaml").write_text(textwrap.dedent("""\
        # Malware process identification + IOC extraction playbook
        case_type: malware_process_ioc
        questions:
          - id: malicious_process_identification
            question: "Are there anomalous or malicious processes running in memory?"
            checks:
              - tool: volatility
                target: pslist_pstree_parent_child_anomalies
              - tool: volatility
                target: psscan_unlinked_hidden_processes
              - tool: volatility
                target: malfind_injected_code
              - tool: volatility
                target: ldrmodules_hidden_dlls
              - tool: yara
                target: yarascan_known_signatures
            negative_requires_all_checks: true
            positive_requires_corroboration: true

          - id: persistence_mechanisms
            question: "What persistence mechanisms are present (services, run keys, scheduled tasks)?"
            checks:
              - tool: plaso
                target: registry_run_keys_services
              - tool: plaso
                target: scheduled_task_creation_events
              - tool: volatility
                target: svcscan_service_list

          - id: network_iocs
            question: "What network indicators (C2 IPs/domains, beaconing) are associated with the activity?"
            checks:
              - tool: tshark
                target: periodic_beaconing_pattern
              - tool: tshark
                target: dns_queries_to_suspicious_domains
              - tool: volatility
                target: netscan_connections
            positive_requires_corroboration: true

          - id: file_iocs
            question: "What file-based IOCs (hashes, dropped files, paths) can be extracted?"
            checks:
              - tool: volatility
                target: dumpfiles_procdump_for_hashing
              - tool: bulk_extractor
                target: embedded_pe_strings_urls
              - tool: plaso
                target: file_creation_execution_timeline

          - id: ioc_compilation
            question: "Compiled IOC set (hashes, IPs, domains, mutexes, registry keys, filenames) for sharing."
            checks:
              - tool: synthesis
                target: aggregate_prior_findings
                note: "Not a raw evidence check - summarizes cited IOCs from the questions above. Every IOC in the export must trace back to a finding_id from an earlier check."
        """))

    (playbooks_dir / "host_compromise.yaml").write_text(textwrap.dedent("""\
        # Host compromise analysis playbook
        case_type: host_compromise
        questions:
          - id: initial_access_vector
            question: "How did the attacker gain initial access to this host?"
            checks:
              - tool: plaso
                target: browser_email_attachment_exploit_artifacts
              - tool: plaso
                target: rdp_smb_remote_logon_events
              - tool: volatility
                target: process_creation_near_intrusion_window
            negative_requires_all_checks: true
            positive_requires_corroboration: true

          - id: privilege_escalation
            question: "Was privilege escalation attempted or achieved?"
            checks:
              - tool: plaso
                target: uac_bypass_token_manipulation_artifacts
              - tool: volatility
                target: privilege_token_analysis
            positive_requires_corroboration: true

          - id: lateral_movement
            question: "Is there evidence of lateral movement to or from this host?"
            checks:
              - tool: plaso
                target: rdp_psexec_wmi_logon_events
              - tool: tshark
                target: smb_rdp_winrm_traffic_to_other_hosts

          - id: persistence
            question: "What persistence was established on this host?"
            checks:
              - tool: plaso
                target: registry_run_keys_services_scheduled_tasks
              - tool: volatility
                target: svcscan_service_list

          - id: data_staging_exfil
            question: "Was data staged or exfiltrated from this host?"
            checks:
              - tool: plaso
                target: archive_creation_events
              - tool: bulk_extractor
                target: carved_artifacts_in_unallocated_space
              - tool: tshark
                target: upload_volume_to_external_destinations

          - id: anti_forensic_activity
            question: "Evidence of log clearing, timestomping, or other anti-forensic activity?"
            checks:
              - tool: plaso
                target: event_log_clear_events
              - tool: plaso
                target: timestomping_mft_si_fn_mismatch
        """))


def write_evidence_tool():
    tools_dir = INSTALL_ROOT / "tools"
    print(f"\n=== Writing evidence mount/decrypt module to {tools_dir}/evidence_tool.py ===")
    (tools_dir / "evidence_tool.py").write_text(textwrap.dedent('''\
        """Evidence mounting and decryption - deterministic infrastructure,
        deliberately NOT exposed to the LLM agent as a tool. Mounting and
        decrypting evidence is not a reasoning task, and the model should
        never see or handle a decryption credential. cli.py's /process
        command calls these functions directly; the agent only ever sees
        the resulting read-only mount path and plaso storage file.

        Credentials are passed as function arguments and used immediately -
        never written to disk or returned in any value that could end up
        logged. Callers (cli.py) must never pass a password/passphrase to
        logger.log_action or logger.log_tool_call.
        """
        import hashlib
        import subprocess
        from pathlib import Path


        def compute_sha256(path: str, chunk_size: int = 1024 * 1024) -> str:
            """Hash the evidence image before touching it - the first entry
            in the chain of custody for this processing session."""
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    h.update(chunk)
            return h.hexdigest()


        def mount_ewf(image_path: str, mount_dir: str) -> str:
            """Mount an E01/Ex01 image read-only via ewfmount (FUSE)."""
            Path(mount_dir).mkdir(parents=True, exist_ok=True)
            subprocess.run(["ewfmount", image_path, mount_dir], check=True)
            return mount_dir


        def mount_bitlocker(source_path: str, mount_dir: str, credential: str,
                             credential_type: str = "password") -> str:
            """Mount a BitLocker volume read-only via bdemount. credential_type
            is 'password' or 'recovery_key'. The credential is passed via
            stdin to bdemount, never as a plaintext argv entry, so it never
            appears in `ps` output or shell history."""
            Path(mount_dir).mkdir(parents=True, exist_ok=True)
            flag = "-r" if credential_type == "recovery_key" else "-p"
            subprocess.run(
                ["bdemount", flag, credential, "-X", "allow_other", source_path, mount_dir],
                check=True, capture_output=True,
            )
            return mount_dir


        def mount_luks(device_path: str, mapper_name: str, passphrase: str) -> str:
            """Open a LUKS volume read-only via cryptsetup. Passphrase is
            piped via stdin (input=), never passed as an argv value."""
            subprocess.run(
                ["cryptsetup", "luksOpen", "--readonly", device_path, mapper_name],
                input=passphrase, text=True, check=True, capture_output=True,
            )
            return f"/dev/mapper/{mapper_name}"


        def mount_ntfs(device_or_file_path: str, mount_dir: str) -> str:
            Path(mount_dir).mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["mount", "-o", "ro", "-t", "ntfs-3g", device_or_file_path, mount_dir],
                check=True,
            )
            return mount_dir


        def mount_generic(device_path: str, mount_dir: str) -> str:
            Path(mount_dir).mkdir(parents=True, exist_ok=True)
            subprocess.run(["mount", "-o", "ro", device_path, mount_dir], check=True)
            return mount_dir


        def unmount(mount_dir: str) -> None:
            """Best-effort unmount - tries fusermount (for ewfmount/bdemount
            FUSE mounts) then falls back to umount."""
            result = subprocess.run(["fusermount", "-u", mount_dir], capture_output=True)
            if result.returncode != 0:
                subprocess.run(["umount", mount_dir], check=False, capture_output=True)
        '''))


def write_tool_stubs():
    tools_dir = INSTALL_ROOT / "tools"
    print(f"\n=== Writing agent tool wrapper stubs to {tools_dir} ===")

    (tools_dir / "__init__.py").write_text("")

    (tools_dir / "plaso_tool.py").write_text(textwrap.dedent('''\
        """Wraps log2timeline/psort. All output is cited by plaso source+offset.

        Multi-source cases: each evidence item gets its OWN storage file
        (evidence_index/<source_id>.plaso) rather than sharing one - this
        sidesteps any ambiguity about plaso's own append/merge semantics
        for an existing storage file, and gives clean 1:1 provenance
        between a storage file and a physical evidence item for free.
        query_case_timeline() is the primary entry point: it queries every
        source registered in the case manifest and tags each event with
        which evidence item it came from.
        """
        import json
        import subprocess
        from pathlib import Path

        def run_log2timeline(image_path: str, storage_file: str) -> str:
            cmd = ["log2timeline.py", storage_file, image_path]
            subprocess.run(cmd, check=True)
            return storage_file

        def query_timeline(storage_file: str, output_format: str = "json_line",
                            date_filter: str | None = None) -> str:
            cmd = ["psort.py", "-o", output_format, storage_file]
            if date_filter:
                cmd += ["--slice", date_filter]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.stdout

        def parse_json_lines(raw_output: str) -> list[dict]:
            events = []
            for line in raw_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return events

        def load_manifest(case_dir: str) -> dict:
            manifest_path = Path(case_dir) / "evidence_index" / "manifest.json"
            if not manifest_path.exists():
                return {"sources": []}
            return json.loads(manifest_path.read_text())

        def query_case_timeline(case_dir: str, date_filter: str | None = None) -> list[dict]:
            """Query across ALL evidence sources processed for this case.
            This is the entry point the agent should always use - it never
            needs to know individual storage file paths. Every returned
            event carries _evidence_source_id and _evidence_source_label
            so the agent (and the human reviewer) can attribute a finding
            to the specific evidence item it came from."""
            manifest = load_manifest(case_dir)
            tagged_events = []
            for src in manifest.get("sources", []):
                storage_file = src.get("plaso_storage_file")
                if not storage_file or not Path(storage_file).exists():
                    continue
                raw = query_timeline(storage_file, date_filter=date_filter)
                for event in parse_json_lines(raw):
                    event["_evidence_source_id"] = src.get("source_id")
                    event["_evidence_source_label"] = src.get("label")
                    tagged_events.append(event)
            return tagged_events
        '''))

    (tools_dir / "volatility_tool.py").write_text(textwrap.dedent('''\
        """Wraps volatility3 plugins with JSON output for clean agent citations."""
        import json
        import subprocess

        def run_plugin(memory_image: str, plugin: str, extra_args: list[str] | None = None) -> list[dict]:
            cmd = ["vol", "-f", memory_image, "-r", "json", plugin]
            if extra_args:
                cmd += extra_args
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return json.loads(result.stdout)

        def get_process_tree(memory_image: str) -> list[dict]:
            return run_plugin(memory_image, "windows.pstree")

        def get_network_connections(memory_image: str) -> list[dict]:
            return run_plugin(memory_image, "windows.netscan")

        def get_malfind_hits(memory_image: str) -> list[dict]:
            return run_plugin(memory_image, "windows.malfind")

        def get_cmdline_history(memory_image: str) -> list[dict]:
            return run_plugin(memory_image, "windows.cmdline")
        '''))

    (tools_dir / "bulk_extractor_tool.py").write_text(textwrap.dedent('''\
        """Wraps bulk_extractor. Treat hits as leads to correlate, not standalone findings."""
        import subprocess
        from pathlib import Path

        def run_bulk_extractor(image_path: str, output_dir: str) -> str:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            cmd = ["bulk_extractor", "-o", output_dir, image_path]
            subprocess.run(cmd, check=True)
            return output_dir
        '''))

    (tools_dir / "pcap_tool.py").write_text(textwrap.dedent('''\
        """Wraps tshark for pcap analysis. JSON output keeps citations to
        specific frame numbers, same pattern as the plaso/volatility wrappers."""
        import json
        import subprocess

        def read_packets(pcap_path: str, display_filter: str | None = None,
                          fields: list[str] | None = None) -> list[dict]:
            """Generic tshark JSON extraction, optionally filtered.
            e.g. display_filter="ip.dst==203.0.113.0/24 && tcp.len>0" for
            checking upload volume to a known cloud/exfil destination range."""
            cmd = ["tshark", "-r", pcap_path, "-T", "json"]
            if display_filter:
                cmd += ["-Y", display_filter]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return json.loads(result.stdout) if result.stdout.strip() else []

        def conversation_summary(pcap_path: str) -> str:
            """Endpoint/conversation stats - good first pass before targeted filters."""
            cmd = ["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"]
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return result.stdout

        def extract_http_requests(pcap_path: str) -> list[dict]:
            return read_packets(pcap_path, display_filter="http.request")

        def bytes_to_destination(pcap_path: str, dst_filter: str) -> list[dict]:
            """dst_filter e.g. 'ip.addr==203.0.113.5' - use for confirming
            upload volume to a specific suspected exfil destination."""
            return read_packets(pcap_path, display_filter=f"{dst_filter} && tcp.len>0")
        '''))

    (tools_dir / "yara_tool.py").write_text(textwrap.dedent('''\
        """Standalone YARA scanning against extracted files/disk paths - distinct
        from volatility's windows.yarascan, which scans live memory regions
        (call that via volatility_tool.run_plugin(..., "windows.yarascan",
        ["--yara-file", rule_path]) for memory-resident IOC matches)."""
        import subprocess
        from pathlib import Path

        def scan_path(rule_path: str, target_path: str, recursive: bool = True) -> str:
            cmd = ["yara"]
            if recursive:
                cmd.append("-r")
            cmd += [rule_path, target_path]
            # yara exits non-zero on rule compile errors, not on "no matches" -
            # matches (or their absence) are read from stdout, not returncode.
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.stdout
        '''))

    (tools_dir / "audit_log.py").write_text(textwrap.dedent('''\
        """Every agent tool call and finding gets appended here for chain of custody."""
        import json
        import time
        from pathlib import Path

        LOG_PATH = Path("/opt/dfir-agent/logs/agent_audit.jsonl")

        def record(event_type: str, detail: dict) -> None:
            entry = {"ts": time.time(), "type": event_type, "detail": detail}
            with LOG_PATH.open("a") as f:
                f.write(json.dumps(entry) + "\\n")
        '''))


def write_case_logger():
    tools_dir = INSTALL_ROOT / "tools"
    print(f"\n=== Writing case-scoped logging module to {tools_dir}/case_logger.py ===")
    (tools_dir / "case_logger.py").write_text(textwrap.dedent('''\
        """Case-scoped logging: three SEPARATE logs per case.

          tool_calls.jsonl          - every tool invocation the agent makes
                                       (plaso, volatility, tshark,
                                       bulk_extractor, yara) with args and a
                                       pointer to raw output.
          processing_actions.jsonl  - agent-level decisions/state transitions
                                       (playbook loaded, question started,
                                       check completed, finding recorded).
          user_prompts.jsonl        - ONLY the human<->agent conversation:
                                       what the examiner typed and what the
                                       agent replied. Kept separate so the
                                       interactive dialogue record never
                                       gets interleaved with raw tool
                                       telemetry or internal agent actions.

        Each log is hash-chained (every entry stores the sha256 of the
        previous entry) so tampering or reordering after the fact is
        detectable - the same principle as a evidence chain of custody log.
        """
        import hashlib
        import json
        import time
        from pathlib import Path


        class CaseLog:
            def __init__(self, path: Path):
                self.path = path
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if not self.path.exists():
                    self.path.touch()

            def _last_hash(self) -> str:
                if self.path.stat().st_size == 0:
                    return "0" * 64
                with self.path.open("rb") as f:
                    last_line = f.readlines()[-1]
                return json.loads(last_line)["entry_hash"]

            def append(self, entry_type: str, detail: dict) -> dict:
                record = {
                    "ts": time.time(),
                    "type": entry_type,
                    "detail": detail,
                    "prev_hash": self._last_hash(),
                }
                record["entry_hash"] = hashlib.sha256(
                    json.dumps(record, sort_keys=True).encode()
                ).hexdigest()
                with self.path.open("a") as f:
                    f.write(json.dumps(record) + "\\n")
                return record


        class CaseLogger:
            """Bundles the three per-case logs behind one interface."""

            def __init__(self, case_dir: Path):
                self.case_dir = case_dir
                logs_dir = case_dir / "logs"
                self.tool_calls = CaseLog(logs_dir / "tool_calls.jsonl")
                self.processing_actions = CaseLog(logs_dir / "processing_actions.jsonl")
                self.user_prompts = CaseLog(logs_dir / "user_prompts.jsonl")

            def log_tool_call(self, tool: str, function: str, args: dict, result_ref: str):
                return self.tool_calls.append("tool_call", {
                    "tool": tool, "function": function, "args": args,
                    "result_ref": result_ref,
                })

            def log_action(self, action: str, detail: dict | None = None):
                return self.processing_actions.append("action", {"action": action, **(detail or {})})

            def log_user_prompt(self, role: str, text: str):
                return self.user_prompts.append("message", {"role": role, "text": text})
        '''))


def write_cli():
    print(f"\n=== Writing interactive prompt interface to {INSTALL_ROOT}/cli.py ===")
    (INSTALL_ROOT / "cli.py").write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        """
        Interactive DFIR agent console (HOTL prompt interface).

        Launch from the desktop shortcut, or directly:
            /opt/dfir-agent/venv/bin/python /opt/dfir-agent/cli.py

        Starting a new case interactively prompts for case reference details
        and creates /opt/dfir-agent/cases/<case_id>/ with:
            logs/tool_calls.jsonl          - every tool invocation
            logs/processing_actions.jsonl  - agent decisions/state transitions
            logs/user_prompts.jsonl        - the human<->agent conversation
                                              ONLY - kept separate from the
                                              two logs above.
        """
        import getpass
        import json
        import os
        import sys
        from datetime import datetime, timezone
        from pathlib import Path

        import yaml
        from dotenv import load_dotenv

        sys.path.insert(0, "/opt/dfir-agent")
        from tools.case_logger import CaseLogger
        from tools import evidence_tool, plaso_tool
        import agent

        INSTALL_ROOT = Path("/opt/dfir-agent")
        CASES_DIR = INSTALL_ROOT / "cases"
        PLAYBOOKS_DIR = INSTALL_ROOT / "playbooks"
        ACTIVE_CASE_POINTER = INSTALL_ROOT / ".active_case"

        load_dotenv(INSTALL_ROOT / ".env")


        def list_playbooks() -> list[str]:
            return sorted(p.stem for p in PLAYBOOKS_DIR.glob("*.yaml"))


        def list_existing_cases() -> list[str]:
            if not CASES_DIR.exists():
                return []
            return sorted(p.name for p in CASES_DIR.iterdir() if p.is_dir())


        def is_same_filesystem_as_vm_root(path: Path) -> bool:
            """Best-effort check that a chosen storage path isn't secretly
            on the VM's own disk (e.g. a directory under /opt or /home that
            resolves to the root filesystem rather than a mounted external
            or network volume)."""
            try:
                return os.stat(path).st_dev == os.stat("/").st_dev
            except OSError:
                return False


        def prompt_evidence_storage_root(default: str = "") -> str:
            while True:
                storage_root = input(
                    "Evidence storage root - external/NAS/network path where "
                    "mounted evidence and plaso timelines will be written "
                    f"(never the VM's own disk){f\' [{default}]\' if default else \'\'}: "
                ).strip() or default
                if not storage_root:
                    print("Required - evidence artifacts are never written under /opt/dfir-agent.")
                    continue
                path = Path(storage_root)
                path.mkdir(parents=True, exist_ok=True)
                if is_same_filesystem_as_vm_root(path):
                    confirm = input(
                        f"WARNING: {storage_root!r} appears to be on the same filesystem "
                        f"as the VM itself, not a separate/external volume. Use it anyway? [y/N]: "
                    ).strip().lower()
                    if confirm != "y":
                        continue
                return storage_root


        def prompt_new_case() -> Path:
            print("\\n=== New Case Intake ===")
            case_ref = input("Case reference number: ").strip()
            examiner = input("Examiner name: ").strip()
            org = input("Requesting org / client (optional): ").strip()
            playbooks = list_playbooks()
            print(f"Available case types: {', '.join(playbooks)}")
            case_type = input("Case type: ").strip()
            while case_type not in playbooks:
                case_type = input(f"Not found. Choose one of {playbooks}: ").strip()
            description = input("Brief case description: ").strip()
            evidence_note = input("Evidence source(s) (paths - will be mounted read-only): ").strip()
            evidence_storage_root = prompt_evidence_storage_root()

            case_id = case_ref.replace(" ", "_") or datetime.now(timezone.utc).strftime("case_%Y%m%dT%H%M%SZ")
            case_dir = CASES_DIR / case_id
            if case_dir.exists():
                sys.exit(f"Case directory {case_dir} already exists. Use resume instead.")
            case_dir.mkdir(parents=True)
            (case_dir / "findings").mkdir()
            (case_dir / "evidence_index").mkdir()

            meta = {
                "case_id": case_id,
                "case_ref": case_ref,
                "examiner": examiner,
                "org": org,
                "case_type": case_type,
                "description": description,
                "evidence_note": evidence_note,
                "evidence_storage_root": evidence_storage_root,
                "opened_at": datetime.now(timezone.utc).isoformat(),
            }
            (case_dir / "case_meta.json").write_text(json.dumps(meta, indent=2))

            logger = CaseLogger(case_dir)
            logger.log_action("case_opened", meta)

            ACTIVE_CASE_POINTER.write_text(case_id)
            print(f"\\nCase '{case_id}' created at {case_dir}")
            return case_dir


        def resume_case() -> Path:
            cases = list_existing_cases()
            if not cases:
                print("No existing cases found.")
                return prompt_new_case()
            print("\\n=== Existing Cases ===")
            for i, c in enumerate(cases, 1):
                print(f"  {i}. {c}")
            choice = input("Select case number (or Enter to create new): ").strip()
            if not choice:
                return prompt_new_case()
            case_dir = CASES_DIR / cases[int(choice) - 1]
            ACTIVE_CASE_POINTER.write_text(case_dir.name)
            return case_dir


        def select_case() -> Path:
            print("DFIR Agent - Interactive Console")
            choice = input("(N)ew case or (R)esume existing? [N/r]: ").strip().lower()
            if choice == "r":
                return resume_case()
            return prompt_new_case()


        HELP_TEXT = """Commands:
          /help                Show this list.
          /case                Create a new case and switch to it (this
                                session stays open, just points at the
                                new case afterward).
          /process             Mount evidence (decrypting first if needed)
                                and build a plaso timeline for it. Run once
                                per evidence item - each gets its own
                                labeled source_id and storage file, and
                                results are combined with attribution when
                                the agent queries. Mounts and timelines are
                                written to the external storage root you
                                choose (prompted at case creation, and
                                overridable per source) - never to the VM's
                                own disk. Never routes through the LLM, and
                                credentials are never logged.
          /playbook            List questions in this case's playbook.
          /findings            Show all findings recorded so far.
          /run <id>            Run a playbook question (or re-run it fresh).
          /verify <id>         Independently re-run a question; flags any
                                disagreement or confidence drift vs the
                                prior finding (both versions kept).
          /expand <id>         Re-run a question, instructed to look beyond
                                the playbook's listed checks.
          /why-not <id>        Show the recorded finding for a question
                                without making any new tool/API calls.
          /report              Assemble a draft report from findings.json.
                                Deterministic, no LLM summarization - marked
                                unreviewed until an examiner signs off.
          /exit, /quit         Close the session.

          Anything else (not starting with /) is sent to the agent as a
          free-form question - same tool access, citation requirements,
          and logging as playbook questions, just not tied to a playbook
          check id."""


        def handle_process_evidence(case_dir: Path, meta: dict, logger):
            """Mount evidence read-only, decrypt if needed, and build a
            plaso timeline. Entirely deterministic - the LLM is never
            invoked here, and no credential is ever written to a log.

            Multi-source: each call processes ONE evidence item into its
            own storage file (evidence_index/<source_id>.plaso) and its
            own namespaced mount path, then APPENDS an entry to
            manifest.json['sources'] rather than overwriting it. Run
            /process again for each additional evidence item in the case.
            The agent queries across all of them at once and every event
            comes back tagged with which source it came from."""
            print("\\n=== Evidence Processing ===")

            manifest_path = case_dir / "evidence_index" / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"sources": []}
            existing_ids = {s["source_id"] for s in manifest["sources"]}
            if manifest["sources"]:
                print(f"{len(manifest[\'sources\'])} evidence source(s) already processed for "
                      f"this case: {[s[\'source_id\'] for s in manifest[\'sources\']]}")

            default_path = meta.get("evidence_note", "") if not manifest["sources"] else ""
            image_path = input(f"Evidence image path [{default_path}]: ").strip() or default_path
            if not image_path or not Path(image_path).exists():
                print(f"Path not found: {image_path!r}. Aborting.")
                return

            default_id = f"source_{len(manifest[\'sources\']) + 1:02d}"
            source_id = input(f"Label for this evidence source (e.g. \'workstation_C\', "
                              f"\'usb_drive_1\') [{default_id}]: ").strip() or default_id
            if source_id in existing_ids:
                print(f"Source id \'{source_id}\' already used in this case. Aborting - "
                      f"re-run /process with a distinct label.")
                return

            storage_root = prompt_evidence_storage_root(default=meta.get("evidence_storage_root", ""))
            source_root = Path(storage_root) / case_dir.name / source_id

            logger.log_action("evidence_processing_started",
                               {"source_id": source_id, "image_path": image_path,
                                "storage_root": storage_root})

            print("Computing SHA-256 of the evidence image for chain of custody "
                  "(may take a while for large images)...")
            digest = evidence_tool.compute_sha256(image_path)
            logger.log_action("evidence_hash_computed",
                               {"source_id": source_id, "image_path": image_path, "sha256": digest})
            print(f"SHA-256: {digest}")

            mount_root = source_root / "mnt"
            mount_root.mkdir(parents=True, exist_ok=True)
            working_path = image_path

            if Path(image_path).suffix.lower() in (".e01", ".ex01"):
                ewf_mount = mount_root / "ewf"
                print("Mounting EWF (E01) image read-only...")
                try:
                    evidence_tool.mount_ewf(image_path, str(ewf_mount))
                    logger.log_action("evidence_mounted",
                                       {"source_id": source_id, "type": "ewf", "mount_point": str(ewf_mount)})
                    candidates = list(ewf_mount.glob("ewf1"))
                    working_path = str(candidates[0]) if candidates else str(ewf_mount)
                except Exception as exc:
                    logger.log_action("evidence_mount_failed",
                                       {"source_id": source_id, "type": "ewf", "error": str(exc)})
                    print(f"EWF mount failed: {exc}")
                    return

            enc = input("Is this volume encrypted? (none/bitlocker/luks) [none]: ").strip().lower() or "none"
            final_path = working_path

            if enc == "bitlocker":
                cred_type = input("Credential type - (p)assword or (r)ecovery key? [p]: ").strip().lower()
                cred_type = "recovery_key" if cred_type == "r" else "password"
                credential = getpass.getpass("BitLocker credential (input hidden, never logged): ")
                bde_mount = mount_root / "bde"
                print("Mounting BitLocker volume (credential used once, never stored)...")
                try:
                    evidence_tool.mount_bitlocker(working_path, str(bde_mount), credential, cred_type)
                except Exception as exc:
                    logger.log_action("evidence_decrypt_failed",
                                       {"source_id": source_id, "type": "bitlocker", "error": str(exc)})
                    print(f"BitLocker mount failed: {exc}")
                    return
                logger.log_action("evidence_decrypted",
                                   {"source_id": source_id, "type": "bitlocker", "credential_provided": True})
                final_mount = mount_root / "final"
                bde1 = bde_mount / "bde1"
                evidence_tool.mount_ntfs(str(bde1), str(final_mount))
                logger.log_action("evidence_mounted",
                                   {"source_id": source_id, "type": "ntfs_decrypted", "mount_point": str(final_mount)})
                final_path = str(final_mount)
            elif enc == "luks":
                passphrase = getpass.getpass("LUKS passphrase (input hidden, never logged): ")
                mapper_name = f"dfir_{case_dir.name}_{source_id}"
                print("Opening LUKS volume read-only (credential used once, never stored)...")
                try:
                    mapped = evidence_tool.mount_luks(working_path, mapper_name, passphrase)
                except Exception as exc:
                    logger.log_action("evidence_decrypt_failed",
                                       {"source_id": source_id, "type": "luks", "error": str(exc)})
                    print(f"LUKS open failed: {exc}")
                    return
                logger.log_action("evidence_decrypted",
                                   {"source_id": source_id, "type": "luks", "credential_provided": True})
                final_mount = mount_root / "final"
                evidence_tool.mount_generic(mapped, str(final_mount))
                logger.log_action("evidence_mounted",
                                   {"source_id": source_id, "type": "luks_decrypted", "mount_point": str(final_mount)})
                final_path = str(final_mount)
            elif enc != "none":
                print(f"Unsupported encryption type '{enc}' - mount/decrypt it manually, "
                      f"then re-run /process pointing at the decrypted path.")
                return

            storage_file = source_root / f"{source_id}.plaso"
            print(f"Running log2timeline against {final_path} -> {storage_file} "
                  f"(this can take a long time on large evidence)...")
            logger.log_action("plaso_processing_started", {"source_id": source_id, "source_path": final_path})
            try:
                plaso_tool.run_log2timeline(final_path, str(storage_file))
            except Exception as exc:
                logger.log_action("plaso_processing_failed", {"source_id": source_id, "error": str(exc)})
                print(f"log2timeline failed: {exc}")
                return
            logger.log_action("plaso_processing_completed",
                               {"source_id": source_id, "storage_file": str(storage_file)})

            manifest["sources"].append({
                "source_id": source_id, "label": source_id, "image_path": image_path,
                "sha256": digest, "encryption": enc, "final_mount": final_path,
                "storage_root": storage_root,
                "plaso_storage_file": str(storage_file),
                "processed_at": datetime.now(timezone.utc).isoformat(),
            })
            manifest_path.write_text(json.dumps(manifest, indent=2))
            logger.log_action("evidence_source_registered",
                               {"source_id": source_id, "total_sources": len(manifest["sources"])})
            print(f"\\nProcessing complete. Source \'{source_id}\' registered "
                  f"({len(manifest[\'sources\'])} total for this case).")
            print(f"Evidence mount and timeline written to: {source_root}")
            print("(Only case metadata, logs, and findings live under /opt/dfir-agent - "
                  "evidence itself stays at the storage root you chose.)")
            print("The agent's plaso_query_timeline tool automatically queries "
                  "all registered sources and tags results by source_id - "
                  "run /process again for any additional evidence items.")


        def generate_report(case_dir: Path, meta: dict, playbook: dict, logger) -> Path:
            """Deterministic assembly from findings.json - no LLM call, so
            nothing in the report can be an unsourced claim. Always a DRAFT;
            never auto-marked reviewed or final."""
            findings_path = case_dir / "findings" / "findings.json"
            findings = json.loads(findings_path.read_text()) if findings_path.exists() else {}
            manifest_path = case_dir / "evidence_index" / "manifest.json"
            manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"sources": []}

            lines = [
                f"# DFIR Case Report (DRAFT) - {meta[\'case_id\']}",
                "",
                "**AI-assisted draft. Not reviewed or approved. Do not distribute "
                "until an examiner signs off.**",
                "",
                f"- Case reference: {meta.get(\'case_ref\')}",
                f"- Case type: {meta.get(\'case_type\')}",
                f"- Examiner: {meta.get(\'examiner\')}",
                f"- Organization: {meta.get(\'org\')}",
                f"- Opened: {meta.get(\'opened_at\')}",
                f"- Description: {meta.get(\'description\')}",
                "",
                "## Evidence Sources",
            ]
            if not manifest["sources"]:
                lines.append("_No evidence has been processed via /process yet._")
            else:
                for src in manifest["sources"]:
                    lines.append(f"- **{src[\'source_id\']}** - `{src[\'image_path\']}` "
                                 f"(SHA-256: `{src[\'sha256\']}`, encryption: {src.get(\'encryption\', \'none\')}, "
                                 f"processed: {src.get(\'processed_at\')})")
            lines.append("")
            lines.append("## Findings")
            for q in playbook["questions"]:
                qid = q["id"]
                f = findings.get(qid)
                lines.append(f"### {q[\'question\']}")
                lines.append(f"*(Question ID: {qid})*")
                lines.append("")
                if not f:
                    lines.append("_Not yet investigated._")
                    lines.append("")
                    continue
                lines.append(f"- **Finding:** {f.get(\'finding\')}")
                lines.append(f"- **Confidence:** {f.get(\'confidence\')}")
                lines.append(f"- **Summary:** {f.get(\'summary\')}")
                if f.get("corroboration_note"):
                    lines.append(f"- **Corroboration note:** {f[\'corroboration_note\']}")
                verification = f.get("verification")
                if verification:
                    if verification.get("disagreement"):
                        status = "DISAGREEMENT ON RE-VERIFY - human review required"
                    elif verification.get("confidence_drift"):
                        status = "confidence drift on re-verify"
                    else:
                        status = "confirmed on re-verify"
                    lines.append(f"- **Verification status:** {status} "
                                 f"(prior: {verification.get(\'prior_finding\')}/{verification.get(\'prior_confidence\')} "
                                 f"-> new: {verification.get(\'new_finding\')}/{verification.get(\'new_confidence\')})")
                evidence = f.get("evidence", [])
                if evidence:
                    lines.append("- **Evidence:**")
                    for e in evidence:
                        src_note = f", source: {e[\'source_id\']}" if e.get("source_id") else ""
                        lines.append(f"  - [{e.get(\'tool\')}] {e.get(\'detail\')} (ref: {e.get(\'result_ref\')}{src_note})")
                suggestions = f.get("native_extraction_suggestions", [])
                if suggestions:
                    lines.append("- **Native extraction suggested (human follow-up):**")
                    for s in suggestions:
                        lines.append(f"  - {s.get(\'artifact\')} via {s.get(\'tool\')}: `{s.get(\'command\')}`")
                if f.get("history"):
                    lines.append(f"- _{len(f[\'history\'])} prior version(s) on record - see findings.json._")
                lines.append("")

            report_dir = case_dir / "report"
            report_dir.mkdir(exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            report_path = report_dir / f"report_draft_{ts}.md"
            report_path.write_text("\\n".join(lines))
            logger.log_action("report_draft_generated", {"path": str(report_path)})
            return report_path


        def repl(case_dir: Path):
            logger = CaseLogger(case_dir)
            meta = json.loads((case_dir / "case_meta.json").read_text())
            playbook = yaml.safe_load((PLAYBOOKS_DIR / f"{meta[\'case_type\']}.yaml").read_text())
            logger.log_action("playbook_loaded", {
                "case_type": meta["case_type"], "n_questions": len(playbook["questions"]),
            })

            print(f"\\nCase: {meta[\'case_id\']}  |  Type: {meta[\'case_type\']}  |  Examiner: {meta[\'examiner\']}")
            print("Type /help for commands, or ask a free-form question.\\n")

            while True:
                try:
                    user_input = input(f"dfir[{meta[\'case_id\']}]> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\\nExiting.")
                    return None
                if not user_input:
                    continue

                logger.log_user_prompt("examiner", user_input)

                if user_input in ("/exit", "/quit"):
                    logger.log_action("session_closed", {})
                    print("Session closed. Logs written to", case_dir / "logs")
                    return None

                if user_input == "/case":
                    logger.log_action("case_switch_requested", {})
                    new_dir = prompt_new_case()
                    print(f"Switched to case '{new_dir.name}'.")
                    return new_dir

                if user_input == "/process":
                    handle_process_evidence(case_dir, meta, logger)
                    continue

                if user_input == "/report":
                    report_path = generate_report(case_dir, meta, playbook, logger)
                    print(f"Draft report written to: {report_path}")
                    print("This is a DRAFT prepared by the console - review and approve before distribution.")
                    continue

                if user_input in ("/help", "/?"):
                    print(HELP_TEXT)
                    continue

                if user_input == "/playbook":
                    for q in playbook["questions"]:
                        print(f"  [{q[\'id\']}] {q[\'question\']}")
                    continue

                if user_input == "/findings":
                    findings_file = case_dir / "findings" / "findings.json"
                    print(findings_file.read_text() if findings_file.exists()
                          else "No findings recorded yet.")
                    continue

                def find_question(qid):
                    return next((q for q in playbook["questions"] if q["id"] == qid), None)

                if user_input.startswith("/verify "):
                    qid = user_input.split(" ", 1)[1].strip()
                    q = find_question(qid)
                    if not q:
                        print(f"Unknown question id: {qid}")
                        continue
                    finding = agent.run_question(case_dir, q, logger, mode="verify")
                    logger.log_user_prompt("agent", json.dumps(finding))
                    if not finding:
                        print("No finding produced (max turns exceeded).")
                    else:
                        verification = finding.get("verification")
                        if verification and verification.get("disagreement"):
                            print(f"\\n*** VERIFICATION DISAGREEMENT: \'{qid}\' ***")
                            print(f"  Prior run: {verification[\'prior_finding\']} "
                                  f"(confidence: {verification[\'prior_confidence\']})")
                            print(f"  This run:  {verification[\'new_finding\']} "
                                  f"(confidence: {verification[\'new_confidence\']})")
                            print("  Flagged for human review - both versions preserved "
                                  "in findings.json under \'history\'.\\n")
                        elif verification and verification.get("confidence_drift"):
                            print(f"\\n--- CONFIDENCE DRIFT: \'{qid}\' --- "
                                  f"(verdict unchanged: {verification[\'new_finding\']})")
                            print(f"  Prior confidence: {verification[\'prior_confidence\']}")
                            print(f"  This run:         {verification[\'new_confidence\']}")
                            print("  Same verdict but confidence shifted - flagged for "
                                  "human review, both versions preserved under \'history\'.\\n")
                        elif verification:
                            print(f"Verification confirmed prior finding: {verification[\'new_finding\']} "
                                  f"(confidence: {verification[\'new_confidence\']})\\n")
                        print(json.dumps(finding, indent=2))
                    continue

                if user_input.startswith("/expand "):
                    qid = user_input.split(" ", 1)[1].strip()
                    q = find_question(qid)
                    if not q:
                        print(f"Unknown question id: {qid}")
                        continue
                    finding = agent.run_question(case_dir, q, logger, mode="expand")
                    logger.log_user_prompt("agent", json.dumps(finding))
                    print(json.dumps(finding, indent=2) if finding else "No finding produced (max turns exceeded).")
                    continue

                if user_input.startswith("/why-not "):
                    qid = user_input.split(" ", 1)[1].strip()
                    existing = agent.load_finding(case_dir, qid)
                    if not existing:
                        print(f"No finding recorded yet for '{qid}'. Run it first (e.g. /verify {qid}).")
                    else:
                        logger.log_user_prompt("agent", json.dumps(existing))
                        print(json.dumps(existing, indent=2))
                    continue

                if user_input.startswith("/run "):
                    qid = user_input.split(" ", 1)[1].strip()
                    q = find_question(qid)
                    if not q:
                        print(f"Unknown question id: {qid}")
                        continue
                    finding = agent.run_question(case_dir, q, logger, mode="run")
                    logger.log_user_prompt("agent", json.dumps(finding))
                    print(json.dumps(finding, indent=2) if finding else "No finding produced (max turns exceeded).")
                    continue

                if user_input.startswith("/"):
                    print(f"Unknown command: {user_input!r}. Type /help for a list of commands.")
                    continue

                # Free-form question - same tool binding and citation discipline,
                # no required-checks enforcement.
                finding = agent.run_freeform(case_dir, user_input, logger)
                response_text = json.dumps(finding, indent=2) if finding else "No answer produced (max turns exceeded)."
                logger.log_user_prompt("agent", response_text)
                print(response_text)


        def main():
            case_dir = None
            if ACTIVE_CASE_POINTER.exists():
                prior = ACTIVE_CASE_POINTER.read_text().strip()
                prior_dir = CASES_DIR / prior
                if prior_dir.exists():
                    resume = input(f"Resume active case \'{prior}\'? [Y/n]: ").strip().lower()
                    if resume != "n":
                        case_dir = prior_dir
            if case_dir is None:
                case_dir = select_case()

            # repl() returns the next case_dir to run (set by /case), or
            # None to end the session - loop here rather than recursing so
            # switching cases doesn't grow the call stack.
            while case_dir is not None:
                case_dir = repl(case_dir)


        if __name__ == "__main__":
            main()
        '''))
    os.chmod(INSTALL_ROOT / "cli.py", 0o755)


def write_desktop_launcher():
    print("\n=== Creating desktop launcher ===")
    launcher_content = textwrap.dedent(f"""\
        [Desktop Entry]
        Type=Application
        Name=DFIR Agent Console
        Comment=Interactive HOTL DFIR agent - case intake, tool calls, findings
        Exec=x-terminal-emulator -T "DFIR Agent Console" -e {VENV_DIR}/bin/python {INSTALL_ROOT}/cli.py
        Icon=utilities-terminal
        Terminal=false
        Categories=System;Security;
        """)
    apps_path = Path("/usr/share/applications/dfir-agent.desktop")
    apps_path.write_text(launcher_content)
    os.chmod(apps_path, 0o755)

    # Also drop a copy on the invoking (sudo) user's Desktop, if one exists.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            desktop_dir = Path(pw.pw_dir) / "Desktop"
            if desktop_dir.exists():
                user_launcher = desktop_dir / "dfir-agent.desktop"
                user_launcher.write_text(launcher_content)
                os.chmod(user_launcher, 0o755)
                os.chown(user_launcher, pw.pw_uid, pw.pw_gid)
                print(f"Launcher also placed at {user_launcher}")
        except KeyError:
            pass


def write_agent_skeleton():
    print(f"\n=== Writing agent loop (caching + minimal per-question context) ===")
    (INSTALL_ROOT / "agent.py").write_text(textwrap.dedent('''\
        #!/usr/bin/env python3
        """
        HOTL DFIR agent loop.

        Design points for token economy:
          - System prompt + tool definitions are static per case -> marked
            with cache_control so repeated calls reuse the cached prefix
            instead of re-billing full price every turn.
          - Context is rebuilt FRESH per question from case state
            (findings.json), not accumulated as one ever-growing
            conversation. Raw tool output is never carried forward past
            the question that produced it - only the compact finding +
            citation survives into later context.
          - Retrieval is narrow: each tool call targets the specific
            artifact/time window the playbook check calls for, not a
            dump of the whole case.
        """
        import json
        import os
        import re
        from pathlib import Path

        import anthropic
        from dotenv import load_dotenv

        from tools import plaso_tool, volatility_tool, bulk_extractor_tool, pcap_tool, yara_tool

        load_dotenv("/opt/dfir-agent/.env")
        client = anthropic.Anthropic(api_key=os.environ["CLAUDE_API_KEY"])

        # Override with a stronger model for /verify on high-stakes findings
        # if you want (e.g. claude-opus-4-8); sonnet is the sane default for
        # the bulk of playbook checks.
        MODEL = os.environ.get("CLAUDE_MODEL", "claude-sonnet-5")
        MAX_TURNS = 15

        SYSTEM_PROMPT = """You are a HOTL (human-on-the-loop) DFIR analyst assistant.

        Rules you must always follow:
        1. Every finding must cite specific tool-returned evidence (the
           result_ref hash, plus the source artifact detail - offset, PID,
           event ID, frame number, file path) that a tool call actually
           returned. Never assert a finding without a tool-call-backed
           citation. Do not use outside knowledge to fill in facts about
           this case.
        2. If the question specifies required checks, you must invoke ALL
           of them via tool calls before concluding a negative
           ("not_supported") finding. A missing check makes a negative
           finding indefensible - run it or explicitly note why it could
           not be run (e.g. artifact source unavailable).
        3. You only have READ access to evidence. Never attempt to write,
           delete, or modify anything via a tool call.
        4. Plaso is the primary evidence source for this investigation.
           For any check requiring plaso, try at least three differently
           -scoped plaso_query_timeline calls (a different date_filter, a
           wider time window, or no filter at all) before concluding
           plaso cannot answer it - a single narrow, empty-handed query
           is not sufficient grounds to move on. Only after genuinely
           exhausting reasonable plaso queries should you fall back to
           the other bound tools (volatility, tshark, bulk_extractor,
           yara) where the playbook check calls for them.
        5. If, after that, a required artifact still cannot be answered
           by plaso or any other bound tool - because plaso has no
           parser for that artifact type, the source wasn't included in
           the timeline, or the artifact needs a tool you don't have -
           call suggest_native_extraction with the exact tool and
           command a human examiner should run to fill the gap. Do not
           fabricate a result and do not silently treat "plaso returned
           nothing" as equivalent to "not_supported" - those are
           different things. Distinguish clearly in your summary between
           "checked thoroughly via the required tools, genuinely absent"
           versus "insufficient extraction coverage, human follow-up
           suggested."
        6. Before finalizing a "supported" finding, actively look for an
           innocuous or alternative explanation for the evidence (e.g. a
           cloud-sync process could be a sanctioned IT tool, not exfil;
           a flagged domain could be a false-positive YARA/DNS match) and
           state in your summary why you ruled it out. If the question
           requires corroboration, a single citation is not enough - you
           need evidence from at least two independent tool sources (or,
           for an unambiguous artifact like an exact file-hash match to a
           known-bad sample, a one-line corroboration_note explaining why
           that single source is sufficient on its own).
        7. When multiple evidence sources have been processed for this
           case, every plaso_query_timeline result is tagged with
           _evidence_source_id and _evidence_source_label showing which
           physical evidence item it came from. If more than one source
           exists, your evidence citations must name which source each
           artifact came from - do not present findings from different
           evidence items as if they were interchangeable.
        8. When you are done investigating, output your final answer as a
           single fenced JSON block with this exact shape, and nothing
           else outside the fence:
           ```json
           {"finding": "supported" | "not_supported" | "inconclusive",
            "confidence": "low" | "medium" | "high",
            "summary": "one or two sentence plain-language summary",
            "checks_run": ["tool_category", ...],
            "evidence": [{"tool": "...", "result_ref": "...", "detail": "...", "source_id": "..."}],
            "corroboration_note": "only if a supported finding rests on one source",
            "native_extraction_suggestions": [{"artifact": "...", "tool": "...", "command": "...", "rationale": "..."}]}
           ```
           source_id is the _evidence_source_id from a plaso event (or the
           relevant tool's evidence item, if applicable) - omit only when
           the case has a single evidence source. Omit corroboration_note
           and native_extraction_suggestions (or leave them empty) unless
           actually relevant.
        """

        TOOLS = [
            {
                "name": "plaso_query_timeline",
                "description": "Query the processed plaso timeline(s) for this case (psort), optionally filtered to a date/time slice. Automatically queries EVERY evidence source registered for this case and tags each returned event with which source it came from - you never need to know or supply a storage file path. Returns events with source file, parser, and offset for citation. This is the PRIMARY tool - try multiple differently-scoped queries before concluding it lacks the answer.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "date_filter": {"type": "string", "description": "Optional psort --slice filter, e.g. '2026-01-15 00:00:00'"},
                    },
                },
            },
            {
                "name": "volatility_run_plugin",
                "description": "Run a volatility3 plugin against a memory image. Returns structured JSON with PIDs/offsets for citation. Common plugins: windows.pstree, windows.psscan, windows.malfind, windows.netscan, windows.cmdline, windows.ldrmodules, windows.svcscan, windows.yarascan.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "memory_image": {"type": "string"},
                        "plugin": {"type": "string"},
                        "extra_args": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["memory_image", "plugin"],
                },
            },
            {
                "name": "bulk_extractor_scan",
                "description": "Run bulk_extractor against a disk image or file to carve unstructured artifacts (emails, URLs, PII patterns) from allocated and unallocated space. Treat hits as leads to correlate against the timeline, not standalone findings.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "image_path": {"type": "string"},
                        "output_dir": {"type": "string"},
                    },
                    "required": ["image_path", "output_dir"],
                },
            },
            {
                "name": "tshark_query",
                "description": "Query a pcap file with tshark. Use display_filter for targeted queries (e.g. upload volume to a suspected destination). Cite results by frame number.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "pcap_path": {"type": "string"},
                        "display_filter": {"type": "string"},
                    },
                    "required": ["pcap_path"],
                },
            },
            {
                "name": "yara_scan",
                "description": "Scan a file or directory path with a YARA rule file for known signatures. Distinct from volatility_run_plugin windows.yarascan, which scans live memory - use this for on-disk files.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "rule_path": {"type": "string"},
                        "target_path": {"type": "string"},
                    },
                    "required": ["rule_path", "target_path"],
                },
            },
            {
                "name": "suggest_native_extraction",
                "description": "Propose a native forensic extraction for a human examiner to run when plaso and the other bound tools cannot sufficiently answer a required check - e.g. plaso has no parser for the artifact, the source wasn't in the timeline, or the artifact needs a tool not available to you (RegRipper, MFTECmd, TSK icat/fls, exiftool, etc). Does not execute anything; only records a structured suggestion. Always give the literal command and the specific artifact it targets - never vague.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "artifact": {"type": "string", "description": "What evidence is needed, e.g. 'ShellBags for user profile X'"},
                        "tool": {"type": "string", "description": "Suggested tool, e.g. 'RegRipper', 'MFTECmd', 'The Sleuth Kit icat/fls', 'exiftool'"},
                        "command": {"type": "string", "description": "The literal command a human examiner should run"},
                        "rationale": {"type": "string", "description": "Why plaso/existing bound tools couldn't cover this"},
                    },
                    "required": ["artifact", "tool", "command", "rationale"],
                },
                "cache_control": {"type": "ephemeral"},
            },
        ]

        TOOL_NAME_TO_CATEGORY = {
            "plaso_query_timeline": "plaso",
            "volatility_run_plugin": "volatility",
            "bulk_extractor_scan": "bulk_extractor",
            "tshark_query": "tshark",
            "yara_scan": "yara",
            "suggest_native_extraction": "native_extraction_suggestion",
        }


        def dispatch_tool(name: str, tool_input: dict, case_dir: Path):
            if name == "plaso_query_timeline":
                return plaso_tool.query_case_timeline(
                    str(case_dir), date_filter=tool_input.get("date_filter"))
            if name == "volatility_run_plugin":
                return volatility_tool.run_plugin(
                    tool_input["memory_image"], tool_input["plugin"], tool_input.get("extra_args"))
            if name == "bulk_extractor_scan":
                return bulk_extractor_tool.run_bulk_extractor(
                    tool_input["image_path"], tool_input["output_dir"])
            if name == "tshark_query":
                return pcap_tool.read_packets(
                    tool_input["pcap_path"], tool_input.get("display_filter"))
            if name == "yara_scan":
                return yara_tool.scan_path(
                    tool_input["rule_path"], tool_input["target_path"])
            if name == "suggest_native_extraction":
                # No execution - just echo back the structured suggestion for logging.
                return {"status": "recorded_for_human_followup", **tool_input}
            raise ValueError(f"Unknown tool: {name}")


        def build_system_blocks():
            return [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]


        def load_findings(case_dir: Path) -> dict:
            path = case_dir / "findings" / "findings.json"
            if path.exists():
                return json.loads(path.read_text())
            return {}


        def save_finding(case_dir: Path, question_id: str, finding: dict):
            """Never silently overwrite a prior finding - the previous
            version (if any) is preserved under 'history' so re-running a
            question (via /run or /verify) never destroys the record of
            what was concluded before."""
            path = case_dir / "findings" / "findings.json"
            all_findings = load_findings(case_dir)
            prior_entry = all_findings.get(question_id)
            history = []
            if prior_entry:
                history = prior_entry.get("history", [])
                prev_current = {k: v for k, v in prior_entry.items() if k != "history"}
                history.append(prev_current)
            all_findings[question_id] = {**finding, "history": history}
            path.write_text(json.dumps(all_findings, indent=2))


        def extract_finding_json(text: str):
            match = re.search(r"```json\\s*(\\{.*?\\})\\s*```", text, re.S)
            if not match:
                match = re.search(r"(\\{.*\\})", text, re.S)
            if not match:
                return None
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                return None


        def build_question_prompt(case_dir: Path, question: dict, mode: str) -> str:
            """Minimal, question-scoped context: this question's checks plus
            ONLY the compact summaries of prior findings, never raw evidence
            from earlier questions."""
            prior = load_findings(case_dir)
            prior_summary = {
                qid: {"finding": f.get("finding"), "summary": f.get("summary")}
                for qid, f in prior.items()
            }
            checks = question.get("checks", [])
            checks_desc = "\\n".join(
                f"  - [{c['tool']}] {c['target']}" + (f" ({c['note']})" if c.get("note") else "")
                for c in checks
            )
            negative_note = (
                "\\nThis question requires ALL listed checks to be run before "
                "a negative finding is accepted.\\n"
                if question.get("negative_requires_all_checks") else ""
            )
            mode_note = {
                "verify": "\\nMODE: VERIFY - re-run the checks independently; do not assume a prior result.\\n",
                "expand": "\\nMODE: EXPAND - go beyond the listed checks; also consider adjacent artifact sources not enumerated below.\\n",
                "run": "",
            }.get(mode, "")
            return (
                f"Question ID: {question['id']}\\n"
                f"Question: {question['question']}\\n"
                f"Required checks:\\n{checks_desc}\\n"
                f"{negative_note}{mode_note}\\n"
                f"Prior findings on this case (for cross-reference only, not evidence "
                f"for THIS question unless you independently verify via a tool call):\\n"
                f"{json.dumps(prior_summary, indent=2)}"
            )


        def run_question(case_dir: Path, question: dict, logger, mode: str = "run") -> dict | None:
            checks_required = {c["tool"] for c in question.get("checks", [])}
            negative_requires_all = question.get("negative_requires_all_checks", False)
            checks_invoked = set()
            plaso_query_count = 0
            native_suggestions = []

            prior_finding = load_finding(case_dir, question["id"]) if mode == "verify" else None

            logger.log_action("question_started", {"id": question["id"], "mode": mode})

            messages = [{"role": "user", "content": build_question_prompt(case_dir, question, mode)}]

            for _ in range(MAX_TURNS):
                response = client.messages.create(
                    model=MODEL, max_tokens=2000,
                    system=build_system_blocks(), tools=TOOLS, messages=messages,
                )
                messages.append({"role": "assistant", "content": response.content})

                tool_uses = [b for b in response.content if b.type == "tool_use"]

                if not tool_uses:
                    final_text = "".join(b.text for b in response.content if b.type == "text")
                    finding = extract_finding_json(final_text)
                    if not finding:
                        messages.append({"role": "user", "content":
                            "Provide your final answer as the fenced JSON block described in the system prompt."})
                        continue

                    # Enforce plaso-first looping: don't accept a non-"supported"
                    # conclusion on a plaso-required check after only one narrow
                    # query, unless the model already proposed a native
                    # extraction to cover the gap.
                    if ("plaso" in checks_required and plaso_query_count < 3
                            and finding.get("finding") in ("not_supported", "inconclusive")
                            and not native_suggestions):
                        logger.log_action("plaso_coverage_insufficient_retry_requested",
                                           {"id": question["id"], "plaso_query_count": plaso_query_count})
                        messages.append({"role": "user", "content":
                            f"You've only queried plaso {plaso_query_count} time(s) for this question. "
                            f"A minimum of 3 differently-scoped plaso_query_timeline calls is required "
                            f"before concluding, or call suggest_native_extraction if plaso genuinely "
                            f"cannot cover this artifact."})
                        continue

                    if (finding.get("finding") == "not_supported" and negative_requires_all
                            and not checks_required.issubset(checks_invoked)):
                        missing = sorted(checks_required - checks_invoked)
                        logger.log_action("negative_finding_rejected_incomplete_checks",
                                           {"id": question["id"], "missing": missing})
                        messages.append({"role": "user", "content":
                            f"You have not yet run: {missing}. Run all required checks "
                            f"before concluding not_supported."})
                        continue

                    # False-positive guard: a "supported" finding on a
                    # corroboration-required question needs evidence from
                    # >=2 independent tool sources, or an explicit
                    # corroboration_note justifying a single source.
                    if (finding.get("finding") == "supported"
                            and question.get("positive_requires_corroboration")):
                        evidence = finding.get("evidence", [])
                        distinct_sources = {e.get("tool") for e in evidence if e.get("tool")}
                        has_justification = bool(finding.get("corroboration_note", "").strip())
                        if len(distinct_sources) < 2 and not has_justification:
                            logger.log_action("positive_finding_rejected_insufficient_corroboration",
                                               {"id": question["id"], "distinct_sources": sorted(distinct_sources)})
                            messages.append({"role": "user", "content":
                                f"This question requires corroboration from at least 2 "
                                f"independent tool sources before accepting a supported "
                                f"finding. Current evidence sources: {sorted(distinct_sources) or 'none'}. "
                                f"Either gather corroborating evidence from a different tool, "
                                f"or, if this single source is genuinely unambiguous (e.g. an "
                                f"exact hash match), include a corroboration_note explaining why."})
                            continue

                    if native_suggestions:
                        finding.setdefault("native_extraction_suggestions", [])
                        existing_cmds = {s.get("command") for s in finding["native_extraction_suggestions"]}
                        for s in native_suggestions:
                            if s.get("command") not in existing_cmds:
                                finding["native_extraction_suggestions"].append(s)

                    # Reproducibility check: an independent /verify run that
                    # disagrees with the prior finding - on the verdict OR
                    # just on confidence - is a real validation signal, not
                    # noise. This is HOTL: the code's only job is to DETECT
                    # and SURFACE the discrepancy, never to auto-resolve it
                    # (e.g. don't pick the higher-confidence one, don't
                    # average confidences, don't discard either version).
                    # The human examiner decides what it means; both
                    # versions stay in findings.json under 'history'.
                    if mode == "verify" and prior_finding:
                        prior_verdict = prior_finding.get("finding")
                        new_verdict = finding.get("finding")
                        prior_conf = prior_finding.get("confidence")
                        new_conf = finding.get("confidence")
                        disagreement = prior_verdict != new_verdict
                        confidence_drift = (not disagreement) and (prior_conf != new_conf)
                        finding["verification"] = {
                            "prior_finding": prior_verdict,
                            "prior_confidence": prior_conf,
                            "new_finding": new_verdict,
                            "new_confidence": new_conf,
                            "disagreement": disagreement,
                            "confidence_drift": confidence_drift,
                        }
                        if disagreement:
                            action = "verification_disagreement"
                        elif confidence_drift:
                            action = "verification_confidence_drift"
                        else:
                            action = "verification_confirmed"
                        logger.log_action(action, {
                            "id": question["id"], "prior_finding": prior_verdict, "new_finding": new_verdict,
                            "prior_confidence": prior_conf, "new_confidence": new_conf,
                        })

                    save_finding(case_dir, question["id"], finding)
                    logger.log_action("question_completed",
                                       {"id": question["id"], "finding": finding.get("finding"),
                                        "native_extraction_suggestions": len(native_suggestions)})
                    return finding

                tool_results = []
                for tu in tool_uses:
                    category = TOOL_NAME_TO_CATEGORY.get(tu.name, tu.name)
                    try:
                        result = dispatch_tool(tu.name, tu.input, case_dir)
                        record = logger.log_tool_call(category, tu.name, tu.input, "success")
                        checks_invoked.add(category)
                        if tu.name == "plaso_query_timeline":
                            plaso_query_count += 1
                        if tu.name == "suggest_native_extraction":
                            native_suggestions.append({**tu.input, "result_ref": record["entry_hash"][:16]})
                        payload = {"result_ref": record["entry_hash"][:16], "data": result}
                        content = json.dumps(payload, default=str)[:8000]
                        tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": content})
                    except Exception as exc:
                        logger.log_tool_call(category, tu.name, tu.input, f"error: {exc}")
                        tool_results.append({"type": "tool_result", "tool_use_id": tu.id,
                                              "content": f"ERROR calling {tu.name}: {exc}", "is_error": True})
                messages.append({"role": "user", "content": tool_results})

            logger.log_action("question_max_turns_exceeded",
                               {"id": question["id"], "native_extraction_suggestions": len(native_suggestions)})
            return None


        def run_freeform(case_dir: Path, prompt_text: str, logger) -> dict | None:
            """Ad hoc question outside the playbook - same tool binding and
            citation discipline, no required-checks enforcement."""
            fake_question = {"id": "freeform", "question": prompt_text, "checks": []}
            logger.log_action("freeform_started", {"prompt": prompt_text})
            return run_question(case_dir, fake_question, logger, mode="run")


        def load_finding(case_dir: Path, question_id: str) -> dict | None:
            return load_findings(case_dir).get(question_id)
        '''))
    os.chmod(INSTALL_ROOT / "agent.py", 0o755)


def write_readme():
    (INSTALL_ROOT / "README.md").write_text(textwrap.dedent(f"""\
        # DFIR Agent VM

        ## Layout
        - `evidence/`  - mount evidence images here READ-ONLY (chmod 555). Never write here.
        - `cases/`     - per-case plaso storage, volatility output, findings, and case logs.
        - `tools/`     - agent tool wrappers (plaso, volatility3, bulk_extractor, tshark, yara)
                         plus `case_logger.py`.
        - playbooks/ - YAML checklists mapping questions to required checks
    (bad_leaver, malware_process_ioc, host_compromise - add more as .yaml
    files following the same schema: id/question/checks/[negative_requires_all_checks])
        - `logs/`      - global install/system log (not case-specific).
        - `agent.py`   - agent-loop skeleton; wire up your tool-calling logic here.
        - `cli.py`     - interactive prompt interface / desktop console. Starting a
                         new case interactively prompts for case reference details
                         and creates the case directory automatically.
        - `.env`       - CLAUDE_API_KEY (chmod 600, root-only).

        ## Case directory layout (created per case by cli.py)
            cases/<case_id>/
              case_meta.json              - case reference, examiner, type, dates
              logs/
                tool_calls.jsonl          - every tool invocation (hash-chained)
                processing_actions.jsonl  - agent decisions/state transitions
                user_prompts.jsonl        - ONLY the examiner<->agent dialogue,
                                             kept separate from the two logs above
              findings/findings.json
              evidence_index/

        ## Desktop console
        A launcher ("DFIR Agent Console") is installed to the applications menu
        (and to the invoking user's Desktop, if present). It opens a terminal
        running `cli.py`, which will:
          1. Offer to resume the active case or start a new one.
          2. On new case, interactively prompt for case reference number,
             examiner, org, case type (from the playbook library), description,
             and evidence source paths.
          3. Drop into a REPL (`/playbook`, `/findings`, `/verify <id>`,
             `/expand <id>`, `/why-not <id>`, free-form questions) with every
             turn logged to the appropriate case log stream.

        You can also launch it directly without the desktop shortcut:
            /opt/dfir-agent/venv/bin/python /opt/dfir-agent/cli.py

        ## Mounting evidence read-only (example, E01 image)
            ewfmount -X allow_other image.E01 /opt/dfir-agent/evidence/mnt_ewf
            mount -o ro,loop /opt/dfir-agent/evidence/mnt_ewf/ewf1 \\
                  /opt/dfir-agent/evidence/case001

        ## Next steps
        1. Stand up Timesketch (docker) if you want a review UI on top of plaso:
           https://timesketch.org/guides/install/docker/
        2. Flesh out `agent.py` with your tool-calling loop against the
           Anthropic Messages API, binding each playbook check to a function
           in `tools/`.
        3. Test against a known-answer sample image before trusting output
           on a real case.
        """))


def main():
    parser = argparse.ArgumentParser(description="Build an agentic DFIR VM.")
    parser.add_argument(
        "--claude-api-key",
        help="Claude API key. If omitted, reads CLAUDE_API_KEY env var, "
             "then falls back to an interactive hidden prompt.",
    )
    parser.add_argument(
        "--skip-system-deps",
        action="store_true",
        help="Skip apt package installation (useful for re-runs).",
    )
    args = parser.parse_args()

    require_root()

    api_key = args.claude_api_key or os.environ.get("CLAUDE_API_KEY")
    if not api_key:
        api_key = getpass.getpass("Claude API key (input hidden): ").strip()
    if not api_key:
        sys.exit("No Claude API key provided. Aborting.")

    if not args.skip_system_deps:
        install_system_deps()
    create_dirs()
    create_venv_and_python_deps()
    write_env_file(api_key)
    write_playbooks()
    write_tool_stubs()
    write_evidence_tool()
    write_case_logger()
    write_agent_skeleton()
    write_cli()
    write_desktop_launcher()
    write_readme()

    print(textwrap.dedent(f"""

        ================================================================
        Done. DFIR agent scaffold installed at {INSTALL_ROOT}

        Activate the venv:
            source {VENV_DIR}/bin/activate

        Read {INSTALL_ROOT}/README.md for evidence-mounting and next steps.
        The agent loop in agent.py is a SKELETON - wire up the tool-calling
        logic before running it against real case evidence.
        ================================================================
    """))


if __name__ == "__main__":
    main()
