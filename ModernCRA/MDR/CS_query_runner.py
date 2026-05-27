#!/usr/bin/env python3
"""
CS_query_runner.py
Cyber Risk Assessment — CrowdStrike Falcon Automated Collection Script
Shane D. Shook, PhD (c) 2026  |  Automated by script

Collects three categories of data from CrowdStrike Falcon via the OAuth2 REST API:

  1. NGSIEM / Event Search CQL queries  (LVL1–LVL5 threat-hunting queries)
       Uses the async job pattern:
         POST  /loggingapi/combined/queries/v1         → start job  → job_id
         GET   /loggingapi/combined/queries-results/v1 → poll status
         GET   /loggingapi/combined/queries-results/v1 → paginate events
  2. Host / device inventory  → HostInventory.csv
       GET /devices/queries/devices-scroll/v1          → stream of AIDs
       POST /devices/entities/devices/v2               → batch detail lookup
  3. Management / audit activity log  → MgmtActivity.csv
       GET /loggingapi/combined/events/v1  (UserActivityAuditEvent +
           AuthActivityAuditEvent stream events via /sensors/entities/datafeed/v2)
       NOTE: Falcon management audit events are surfaced through the Event Streams
       API (Firehose / streaming endpoint).  If your tenant uses the standard
       AuditEvents endpoint instead, set --audit-source=api (see CLI flags).
  4. Application / software inventory  → app-inventory.csv
       GET /discover/queries/applications/v1           → app IDs
       GET /discover/entities/applications/v2          → batch detail lookup

Writes every result to an individual CSV file in the output directory and
produces a signed chain-of-custody manifest (JSON + SHA-256).

API SCOPES REQUIRED (create a dedicated API client with these read permissions):
  Hosts                        : Read
  Event Streams                : Read        (for MgmtActivity streaming)
  NGSIEM / LogScale            : Read + Write (Write needed to submit search jobs)
  Falcon Discover (Assets)     : Read        (for app-inventory)
  Audit Events (if available)  : Read

AUTHENTICATION:
  OAuth2 client-credentials flow.  POST /oauth2/token with client_id +
  client_secret → Bearer token (30-minute TTL).  The script auto-refreshes.

BASE URLS (choose the correct one for your cloud region):
  US-1  : https://api.crowdstrike.com        (default)
  US-2  : https://api.us-2.crowdstrike.com
  EU-1  : https://api.eu-1.crowdstrike.com
  GOV-1 : https://api.laggar.gcw.crowdstrike.com

Usage:
    python CS_query_runner.py \
        --client-id    YOUR_CLIENT_ID \
        --client-secret YOUR_CLIENT_SECRET \
        [--base-url    https://api.crowdstrike.com] \
        [--days        90] \
        [--output      ./cs_assessment_output] \
        [--from-date   2026-02-25T00:00:00Z] \
        [--to-date     2026-05-25T23:59:59Z]

Requirements:
    pip install requests
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cs_runner")

# ── Constants ─────────────────────────────────────────────────────────────────
POLL_INTERVAL    = 5       # seconds between job-status polls
POLL_TIMEOUT     = 600     # seconds before giving up on a single NGSIEM job
PAGE_LIMIT       = 1000    # events per NGSIEM results page (max 1000)
HOST_BATCH       = 100     # AIDs per PostDeviceDetailsV2 call (max 100)
APP_BATCH        = 100     # app IDs per batch detail call
TOKEN_REFRESH    = 1700    # re-authenticate after ~28 min (token TTL is 30 min)
COC_FILENAME     = "chain_of_custody.json"
NGSIEM_REPO      = "search-all"   # CQL repository; also: "investigate_view"

# ── CQL Query catalogue ───────────────────────────────────────────────────────
# Each entry:  (output_csv, risk_level, description, cql_string | None)
#
# CQL is the CrowdStrike Query Language used in Falcon NGSIEM / Event Search.
# Field mapping from SentinelOne equivalents:
#   S1 event.type / filter          → #event_simpleName in CQL
#   src.process.name                → ContextBaseFileName / FileName / ImageFileName
#   src.process.cmdline             → CommandLine
#   src.process.user                → UserName  (or UserSid)
#   src.process.image.path          → ImageFileName  (full path)
#   tgt.process.name                → TargetFileName / TargetImageFileName
#   tgt.process.cmdline             → TargetCommandLine (where available)
#   endpoint.name                   → ComputerName
#   event.time / timestamp          → ContextTimeStamp_decimal (epoch ms)
#   dst.ip.address                  → RemoteAddressIP4
#   dst.port.number                 → RemotePort_decimal
#   src.ip.address                  → LocalAddressIP4
#   event.network.direction         → ConnectionDirection (1=outbound, 0=inbound)
#   event.dns.request               → DomainName
#   registry.keyPath                → RegObjectName
#   tgt.file.path                   → TargetFileName (file events)
#   driver.loadVerdict              → (no direct equivalent; use DriverLoadStatus_decimal)
#
# CQL uses the | pipe syntax.  table([...]) selects output columns.
# groupBy([...], function=([count()])) is the aggregation equivalent.
# Regex matching: /pattern/i  (case-insensitive flag i)
# String in list: in(field, values=["a","b"])
# Note: "time" range is injected by the runner as start=/end= on job submission.

QUERIES = [

    # ── LVL1  Cloud Storage ───────────────────────────────────────────────────
    (
        "CloudUsers.csv", "LVL1",
        "Cloud storage sync client outbound connections by user",
        r"""#event_simpleName=NetworkConnectIP4
| ImageFileName=/dropbox|boxsync|boxdrive|googledrive|backupandsync|icloud|pcloud|megasync|tresorit|egnyte|syncapp/i
| ConnectionDirection=1
| NOT ImageFileName=/microsoft|windows/i
| groupBy([ImageFileName, UserName], function=([count()]))
| rename(field=ImageFileName, as=ProcessName)""",
    ),
    (
        "CloudSync.csv", "LVL1",
        "Command-line cloud upload activity referencing cloud service URLs",
        r"""#event_simpleName=ProcessRollup2
| CommandLine=/box\.com|dropbox\.com|drive\.google\.com|mega\.nz|wetransfer\.com|pcloud\.com|egnyte\.com|mediafire\.com|gofile\.io|transfer\.sh|pastebin\.com|rclone|curl\s+-[TFd]|-Method\s+P(UT|OST)|Invoke-WebRequest|aws\s+s3|gsutil|azcopy/i
| NOT ImageFileName=/chrome|msedge|firefox/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),

    # ── LVL1  AI Users ────────────────────────────────────────────────────────
    (
        "AIUsers.csv", "LVL1",
        "AI tool desktop application launches by user",
        r"""#event_simpleName=ProcessRollup2
| FileName=/claude|perplexity|notion|cursor|ollama|lmstudio|gpt4all|koboldcpp|llama|whisper|krisp|otter|fathom|fireflies|elevenlabs|runway|grammarly|jasper|codeium|tabnine|windsurf|gemini|chatgpt|copilot|zed/i
| NOT FileName=/update|setup|install|uninstall|helper|native.host|crash|proxy|autostarter/i
| groupBy([FileName, UserName], function=([count()]))
| rename(field="count()", as=launches)
| sort([FileName, -launches])""",
    ),
    (
        "AIWebUse.csv", "LVL1",
        "AI service browser access by DNS resolution",
        r"""#event_simpleName=DnsRequest
| DomainName=/claude|anthropic|openai|chatgpt|perplexity|gemini|copilot\.microsoft|grok\.x|mistral|huggingface|character\.ai|poe\.com|pi\.ai|together\.ai|replicate\.com|jasper\.ai|copy\.ai|writesonic\.com|grammarly\.com|notion\.so|cursor\.sh/i
| NOT ContextBaseFileName=/MsMpEng|CSFalconService|svchost/i
| groupBy([DomainName], function=([count(distinct=UserName), count()]))
| rename(field="count(distinct=UserName)", as=unique_users)
| rename(field="count()", as=total_lookups)
| sort([-unique_users])""",
    ),

    # ── LVL1  USB ─────────────────────────────────────────────────────────────
    (
        "USBConnected.csv", "LVL1",
        "USB storage device connection events (registry + removable media)",
        r"""#event_simpleName=RemovableMediaVolumeMount
| table([ComputerName, ContextTimeStamp_decimal, DeviceVendorId, DeviceProductId, DeviceSerialNumber, VolumeName, DriveLetter, UserName])""",
    ),
    (
        "USBUse.csv", "LVL1",
        "Process activity referencing removable drive letters",
        r"""#event_simpleName=ProcessRollup2
| CommandLine=/[D-Zd-z]:\\\\/
| NOT CommandLine=/HostGUID|HKLM:|HTTP/i
| NOT FileName=/edge|chrome/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),

    # ── LVL2  User Profile Propagation ───────────────────────────────────────
    (
        "UPPCount.csv", "LVL2",
        "User login count across multiple endpoints (profile propagation indicator)",
        r"""#event_simpleName=UserLogon
| groupBy([UserName, LogonType_decimal, ComputerName], function=([count()]))
| rename(field="count()", as=logon_count)
| groupBy([UserName, LogonType_decimal], function=([count(distinct=ComputerName), sum(logon_count)]))
| rename(field="count(distinct=ComputerName)", as=unique_computers)
| rename(field="sum(logon_count)", as=total_logons)
| unique_computers > 1 AND unique_computers < 42
| sort([-unique_computers])""",
    ),
    (
        "UPPActivity.csv", "LVL2",
        "Detailed login activity for administratively flagged accounts",
        r"""#event_simpleName=UserLogon
| UserName=/^(administrator|admin)$/i
| table([UserName, LogonType_decimal, ComputerName, ContextTimeStamp_decimal])
| sort([UserName, ContextTimeStamp_decimal])""",
    ),

    # ── LVL2  User Services ───────────────────────────────────────────────────
    (
        "UserServices.csv", "LVL2",
        "User-space processes making outbound network connections",
        r"""#event_simpleName=NetworkConnectIP4
| ImageFileName=/\\\\Users\\\\/i
| NOT ImageFileName=/microsoft|zoom|gotomeeting|grammarly|notion|creative/i
| ConnectionDirection=1
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, LocalAddressIP4, RemoteAddressIP4, RemotePort_decimal, ConnectionDirection, UserName])""",
    ),

    # ── LVL2  Credential Theft (LSASS) ───────────────────────────────────────
    (
        "CredentialTheft.csv", "LVL2",
        "Suspicious handle opens against lsass.exe (credential theft indicator)",
        r"""#event_simpleName=ProcessRollup2
| TargetProcessId_decimal=*
| NOT FileName=/MsMpEng|CSFalconService|tphkload|MBAMService|AdobeARM|Taskmgr|msiexec|MRT/i
| join(query={#event_simpleName=OpenProcessHandle GrantedAccess_decimal>0 TargetImageFileName=/lsass/i}, field=[TargetProcessId_decimal], key=[ContextProcessId_decimal], include=[TargetImageFileName, GrantedAccess_decimal])
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, UserName, TargetImageFileName, GrantedAccess_decimal, CommandLine])""",
    ),

    # ── LVL2  WMI Lateral Movement ───────────────────────────────────────────
    (
        "WMILateral.csv", "LVL2",
        "WMI-spawned process creation (lateral movement indicator)",
        r"""#event_simpleName=ProcessRollup2
| ParentBaseFileName=/WmiPrvSE/i
| NOT FileName=/WmiPrvSE|WerFault/i
| table([ComputerName, ContextTimeStamp_decimal, ParentBaseFileName, FileName, CommandLine, UserName])""",
    ),

    # ── LVL2  Local Privilege Escalation ──────────────────────────────────────
    (
        "LPE.csv", "LVL2",
        "Non-system user spawning administrative shell processes",
        r"""#event_simpleName=ProcessRollup2
| NOT UserName=/SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM|UMFD/i
| FileName=/^(cmd|powershell|net|net1|whoami|runas)\.exe$/i
| NOT CommandLine=/Sentinel|CSFalcon/i
| groupBy([ComputerName, UserName, FileName, CommandLine], function=([count()]))
| rename(field="count()", as=event_count)
| sort([ComputerName, -event_count])""",
    ),

    # ── LVL2  Privilege Hygiene ───────────────────────────────────────────────
    (
        "PrivilegeRisks.csv", "LVL2",
        "Privilege escalation hygiene — low-integrity processes producing elevated children",
        r"""#event_simpleName=ProcessRollup2
| IntegrityLevel_decimal in [4, 8]
| TargetProcessIntegrityLevel_decimal in [12, 16]
| NOT UserSid=/S-1-5-18|S-1-5-19|S-1-5-20/
| groupBy([ComputerName, UserName, UserSid, FileName, ImageFileName, CommandLine, TargetFileName, TargetCommandLine], function=([count()]))
| rename(field="count()", as=event_count)
| sort([-event_count])""",
    ),

    # ── LVL3  Network Tunnels ─────────────────────────────────────────────────
    (
        "NetworkTunnels.csv", "LVL3",
        "Tunnel tool network connections (ngrok, cloudflared, frpc, tor, etc.)",
        r"""#event_simpleName=NetworkConnectIP4
| ImageFileName=/ngrok|cloudflared|frpc|ligolo|chisel|bore|rathole|tunnelto|tor/i
| NOT ImageFileName=/monitor|doctor|repository|protector|collector|editor|windowsapps|store|laborator|microsoft|torun|driverstore/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, LocalAddressIP4, RemoteAddressIP4, RemotePort_decimal, ConnectionDirection, UserName])""",
    ),

    # ── LVL3  DNS / DGA Beaconing ────────────────────────────────────────────
    (
        "DGABeacons.csv", "LVL3",
        "High-frequency NXDOMAIN DNS requests (DGA / beaconing pattern, >100 hits)",
        r"""#event_simpleName=DnsRequest
| RequestType_decimal=0
| NOT DomainName=/rocketcyber|digicert|grammarly|opendns|typekit|in-addr\.arpa|microsoft|wpad|_ldap|office|amazon|google|yahoo|azure|verizon|kaseya|adobe|example|dynatrace|webex|cdn|arpa|windowsupdate|doubleclick|sentinelone|zoom|pki|msft|metrix|trafficmanager|kerberos|tcp\.|duckduckgo|southwest|ipv4|ipv6|autodiscover|actionablemessage|claude|scorecard|verisign/i
| groupBy([ComputerName, ContextBaseFileName, UserName, DomainName], function=([count()]))
| rename(field="count()", as=nxdomain_count)
| nxdomain_count > 100
| sort([-nxdomain_count])""",
    ),
    (
        "BadTLDs.csv", "LVL3",
        "DNS queries to high-risk country-code and generic TLDs",
        r"""#event_simpleName=DnsRequest
| DomainName=/\.(ru|cn|onion|tk|xyz|top|icu)$/i
| NOT ContextBaseFileName=/MsMpEng|CSFalconService/i
| NOT DomainName=/rubicon|digicert/i
| table([ComputerName, ContextBaseFileName, DomainName, UserName, ContextTimeStamp_decimal])""",
    ),

    # ── LVL3  Backdoors ───────────────────────────────────────────────────────
    (
        "BackdoorsIn.csv", "LVL3",
        "Inbound connections on non-standard ports",
        r"""#event_simpleName=NetworkConnectIP4
| ConnectionDirection=0
| NOT RemoteAddressIP4=127.0.0.1
| NOT LocalPort_decimal in [135, 139, 0, 7680]
| LocalPort_decimal < 10000
| table([ComputerName, FileName, ImageFileName, LocalAddressIP4, LocalPort_decimal, RemoteAddressIP4, RemotePort_decimal, ConnectionDirection, UserName, ContextTimeStamp_decimal])""",
    ),
    (
        "BackdoorsOut.csv", "LVL3",
        "Outbound connections on non-standard ports and protocols",
        r"""#event_simpleName=NetworkConnectIP4
| ConnectionDirection=1
| NOT RemoteAddressIP4=/^(127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|10\.|169\.254\.)/
| NOT RemotePort_decimal in [53, 80, 8080, 8081, 443, 3268, 3478, 5228, 7680, 19305, 52311]
| NOT FileName=/CSFalconService|MsMpEng|svchost|OUTLOOK|ms-teams/i
| NOT CommandLine=/update|mojo|office|rocket/i
| table([ComputerName, ContextTimeStamp_decimal, LocalAddressIP4, LocalPort_decimal, RemoteAddressIP4, RemotePort_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),

    # ── LVL3  Beacons ─────────────────────────────────────────────────────────
    (
        "Beacons.csv", "LVL3",
        "High-frequency outbound IP connections (>500 per process/destination pair)",
        r"""#event_simpleName=NetworkConnectIP4
| ConnectionDirection=1
| NOT FileName=/MsMpEng|CSFalconService|MpsMonitor|spoolsv|MsSense|Spotify|MicrosoftEdge|opera|firefox|chrome|adobe/i
| NOT CommandLine=/office|onedrive|zoom|program files|programdata|kaseya|instal|upgr|update|claude/i
| NOT RemoteAddressIP4=/^(127\.|192\.168\.|172\.)/
| groupBy([ComputerName, FileName, RemoteAddressIP4], function=([count()]))
| rename(field="count()", as=connection_count)
| connection_count > 500
| sort([-connection_count])""",
    ),

    # ── LVL4  RMM Checks ─────────────────────────────────────────────────────
    (
        "RmmUse.csv", "LVL4",
        "RMM tool process creation events",
        r"""#event_simpleName=ProcessRollup2
| ImageFileName=/mstsc|teamviewer|gotomeeting|g2m|anydesk|screenconnect|connectwise|logmein|splashtop|bomgar|beyondtrust|ninjarmm|atera|pulseway|remoting_host|vnc|zohoassist|supremo|datto|dameware|dwrcs|dwrcc/i
| NOT ImageFileName=/driverstore/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, UserName])""",
    ),
    (
        "RMMComms.csv", "LVL4",
        "RMM tool active network connections",
        r"""#event_simpleName=NetworkConnectIP4
| ImageFileName=/mstsc|tsclient|teamviewer|anydesk|screenconnect|connectwise|logmein|splashtop|bomgar|beyondtrust|ninjarmm|realvnc|tightvnc|ultravnc|winvnc|datto|zoho|supremo|rescue|gotoassist|gotomypc|goto|citrix|isl|remotepc|getscreen|fixme|mikogo|basup|rustdesk|lmi_rescue|landesk|dameware|dwrcs/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, LocalAddressIP4, RemoteAddressIP4, RemotePort_decimal, ConnectionDirection, UserName])""",
    ),

    # ── LVL4  LOLBin Abuse ───────────────────────────────────────────────────
    (
        "LolBinUse.csv", "LVL4",
        "Living-off-the-land binary execution (LOLBAS)",
        r"""#event_simpleName=ProcessRollup2
| FileName=/certutil|bitsadmin|mshta|sfc|hh\.exe|wscript|cscript|regsvr32|rundll32|msiexec|wmic|installutil|regasm|regsvcs|cmstp|msbuild|dnscmd|odbcconf|pcalua|pwsh|powershell|desktopimgdownldr|esentutl|extrac32|findstr|makecab|mavinject|msdeploy|msdt|presentationhost|replace|rpcping|shdocvw|wab|xwizard/i
| NOT CommandLine=/Embedding|CbsPersist|Kaseya|REPAIRFROMAPP|PfSvWsSwap/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),
    (
        "LolBinMasq.csv", "LVL4",
        "Potential LOLBin masquerade — known system binaries in non-standard paths",
        r"""#event_simpleName=ProcessRollup2
| FileName=/^(svhost|svchost|rundll|rundll32|service|cmd)\.exe$/i
| NOT ImageFileName=/system32|syswow64|winsxs/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),

    # ── LVL4  Base64 Activity ─────────────────────────────────────────────────
    (
        "Base64Activities.csv", "LVL4",
        "Encoded command execution (base64 padding == in command line)",
        r"""#event_simpleName=ProcessRollup2
| CommandLine=/==/
| NOT FileName=/edge|chrome/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, CommandLine, UserName])""",
    ),

    # ── LVL4  Scheduled Tasks ─────────────────────────────────────────────────
    (
        "SchTasks.csv", "LVL4",
        "Scheduled task registration from user or temp paths",
        r"""#event_simpleName=ScheduledTaskRegistered
| TaskExecCommand=/\\Users\\|\\Temp\\/i
| NOT ContextBaseFileName=/svchost|taskeng/i
| NOT TaskName=/OneDrive|Lvf/i
| NOT ImageFileName=/zoom|piriform|office|edge/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, ImageFileName, TaskName, TaskExecCommand, UserName])""",
    ),

    # ── LVL4  Process Injection ───────────────────────────────────────────────
    (
        "ProcessInjections.csv", "LVL4",
        "Remote thread creation events (process injection indicator)",
        r"""#event_simpleName=CreateRemoteThreadV2
| NOT SourceImageFileName=TargetImageFileName
| NOT SourceImageFileName=/werfault|werfaultsecure|mbam|msmpeng|csfalconservice|csrss|wininit|services/i
| NOT TargetImageFileName=/spoolsv/i
| table([ComputerName, ContextTimeStamp_decimal, SourceFileName, SourceImageFileName, TargetFileName, TargetImageFileName, UserName, SourceCommandLine])""",
    ),

    # ── LVL4  Office App Shells ───────────────────────────────────────────────
    (
        "ShellsSpawn.csv", "LVL4",
        "Office applications spawning shells or LOLBins",
        r"""#event_simpleName=ProcessRollup2
| ParentBaseFileName=/winword|excel|powerpnt|outlook|onenote|msaccess|mspub/i
| FileName=/cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|ftp|curl|nslookup|wmic|msbuild|installutil|regasm|schtasks|at\.exe|sc\.exe|msiexec|reg\.exe|regedit|net\.exe|net1|nltest|whoami|systeminfo|ipconfig|tasklist|taskkill|vssadmin|wbadmin|bcdedit|esentutl|extrac32|findstr|hh\.exe|makecab|msdt|pcalua|presentationhost|xwizard|forfiles|mmc\.exe|ping|arp\.exe|netstat|icacls|takeown|attrib|cipher|dnscmd|rpcping/i
| NOT FileName=/acrobat|cabinet/i
| NOT CommandLine=/Office|OfficeC2R|Teams/i
| table([ComputerName, ContextTimeStamp_decimal, UserName, ParentBaseFileName, FileName, CommandLine, ParentCommandLine])""",
    ),

    # ── LVL4  User Executable Drops ──────────────────────────────────────────
    (
        "UserExecs.csv", "LVL4",
        "Executable files created in writable user locations",
        r"""#event_simpleName=PeFileWritten
| TargetFileName=/\\Temp\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\Downloads\\|\\Public\\/i
| NOT TargetFileName=/Program Files|chrom|ProgramData/i
| NOT ContextBaseFileName=/MsMpEng|CSFalconService|msiexec|WindowsInstaller/i
| NOT ContextBaseFileName=/setup|updat|inst|vc_redist|HP|icarus|package|MSI|runtime|claude|creative|driver|zoom/i
| table([ComputerName, ContextTimeStamp_decimal, UserName, ContextBaseFileName, TargetFileName])""",
    ),

    # ── LVL4  New Services ────────────────────────────────────────────────────
    (
        "NewServices.csv", "LVL4",
        "Suspicious new Windows service installations",
        r"""#event_simpleName=ServiceInstalled
| NOT ImageFileName=/msiexec|TrustedInstaller|AgentMon|lenovo/i
| table([ComputerName, ContextTimeStamp_decimal, ServiceDisplayName, ServiceImagePath, UserName])""",
    ),

    # ── LVL4  Suspicious Driver Loads ────────────────────────────────────────
    (
        "Rootkits.csv", "LVL4",
        "Suspicious or non-benign driver load events",
        r"""#event_simpleName=DriverLoad
| NOT DriverLoadStatus_decimal=0
| NOT ContextBaseFileName=/ntoskrnl/i
| table([ComputerName, ContextTimeStamp_decimal, ContextBaseFileName, ImageFileName, SHA256HashData, DriverLoadStatus_decimal])""",
    ),

    # ── LVL4  Suspicious Scripts ──────────────────────────────────────────────
    (
        "SuspScripts.csv", "LVL4",
        "Script execution with download or reflective-load indicators",
        r"""#event_simpleName=CommandHistory
| CommandLine=/IEX|Invoke-Expression|Net\.WebClient|DownloadString|DownloadFile|WebRequest|bitsadmin|Start-BitsTransfer|Reflection\.Assembly|FromBase64String/i
| table([ComputerName, ContextTimeStamp_decimal, FileName, CommandLine, UserName])""",
    ),

    # ── LVL5  OS Builds ───────────────────────────────────────────────────────
    (
        "OSBuilds.csv", "LVL5",
        "Endpoint OS name and build revision inventory (from NGSIEM telemetry)",
        r"""#event_simpleName=OsVersionInfo
| groupBy([ComputerName, OSVersionString, MajorVersion_decimal, MinorVersion_decimal, BuildNumber_decimal], function=([count()]))
| table([ComputerName, OSVersionString, MajorVersion_decimal, MinorVersion_decimal, BuildNumber_decimal])""",
    ),

    # ── LVL5  Endpoint Activity Health ───────────────────────────────────────
    (
        "Endpoints.csv", "LVL5",
        "Daily event counts per endpoint by type (health comparison baseline)",
        r"""#event_simpleName in [ProcessRollup2, NetworkConnectIP4, UserLogon]
| bucket(span=1d)
| groupBy([_bucket, ComputerName, #event_simpleName], function=([count()]))
| rename(field="_bucket", as=day)
| rename(field="#event_simpleName", as=event_type)
| rename(field="count()", as=event_count)
| sort([day, ComputerName, event_type])""",
    ),

    # ── Manual / Entra ID exports ─────────────────────────────────────────────
    # These have no CrowdStrike API equivalent and must be sourced externally.
    ("EntraUsers.csv",  "LVL2", "Entra ID user accounts (Entra portal export — manual)", None),
    ("EntraGroups.csv", "LVL2", "Entra ID group memberships (Entra portal export — manual)", None),
    ("EntraRoles.csv",  "LVL2", "Entra ID privileged role assignments (Entra portal export — manual)", None),
]


# ── OAuth2 / REST client ──────────────────────────────────────────────────────

class CSClient:
    """
    Thin CrowdStrike Falcon REST client with automatic OAuth2 token refresh.
    Does NOT use FalconPy — pure requests to keep the single-file dependency
    footprint identical to the SentinelOne runner.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base          = base_url.rstrip("/")
        self.client_id     = client_id
        self.client_secret = client_secret
        self.session       = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self._token_time   = 0.0
        self._refresh_token()

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _refresh_token(self) -> None:
        r = self.session.post(
            f"{self.base}/oauth2/token",
            data={
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "grant_type":    "client_credentials",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        token = r.json()["access_token"]
        self.session.headers["Authorization"] = f"Bearer {token}"
        self._token_time = time.monotonic()
        log.debug("OAuth2 token refreshed")

    def _ensure_token(self) -> None:
        if time.monotonic() - self._token_time > TOKEN_REFRESH:
            self._refresh_token()

    def get(self, path: str, **kwargs) -> requests.Response:
        self._ensure_token()
        r = self.session.get(f"{self.base}{path}", **kwargs)
        r.raise_for_status()
        return r

    def post(self, path: str, **kwargs) -> requests.Response:
        self._ensure_token()
        r = self.session.post(f"{self.base}{path}", **kwargs)
        r.raise_for_status()
        return r

    # ── NGSIEM async search ───────────────────────────────────────────────────

    def ngsiem_start(
        self,
        query: str,
        start_ms: int,
        end_ms: int,
        repository: str = NGSIEM_REPO,
    ) -> str:
        """Submit an async CQL search; return the job ID."""
        body = {
            "queryString": query,
            "isLive":      False,
            "start":       start_ms,
            "end":         end_ms,
        }
        r = self.post(
            f"/loggingapi/combined/queries/v1",
            params={"repository": repository},
            json=body,
        )
        data = r.json()
        # Response: {"id": "job-id-string", ...}
        job_id = data.get("id") or data.get("job_id")
        if not job_id:
            raise RuntimeError(f"NGSIEM start_search returned no job ID: {data}")
        return job_id

    def ngsiem_status(
        self,
        job_id: str,
        repository: str = NGSIEM_REPO,
    ) -> dict:
        """Poll job status; returns the status object."""
        r = self.get(
            "/loggingapi/combined/queries-results/v1",
            params={"id": job_id, "repository": repository},
        )
        return r.json()

    def ngsiem_results(
        self,
        job_id: str,
        repository: str = NGSIEM_REPO,
        offset: int = 0,
        limit: int = PAGE_LIMIT,
    ) -> dict:
        """Fetch one page of results for a completed job."""
        r = self.get(
            "/loggingapi/combined/queries-results/v1",
            params={
                "id":         job_id,
                "repository": repository,
                "offset":     offset,
                "limit":      limit,
            },
        )
        return r.json()

    # ── Host inventory (two-step: IDs → details) ──────────────────────────────

    def scroll_device_ids(self, filter_fql: str = "") -> list[str]:
        """
        Scroll all device IDs using the continuous pagination endpoint
        GET /devices/queries/devices-scroll/v1 (no record cap).
        Returns a flat list of all AIDs.
        """
        aids: list[str] = []
        offset = ""
        while True:
            params: dict = {"limit": 5000}
            if filter_fql:
                params["filter"] = filter_fql
            if offset:
                params["offset"] = offset
            r = self.get("/devices/queries/devices-scroll/v1", params=params)
            body = r.json()
            batch = body.get("resources", [])
            aids.extend(batch)
            meta   = body.get("meta", {})
            offset = meta.get("pagination", {}).get("offset", "")
            total  = meta.get("pagination", {}).get("total", len(aids))
            log.info("    scrolled %d / %d device IDs …", len(aids), total)
            if not batch or len(aids) >= total:
                break
        return aids

    def get_device_details(self, aids: list[str]) -> list[dict]:
        """
        Batch-fetch device details via POST /devices/entities/devices/v2.
        CrowdStrike returns full host records including: hostname, os_version,
        agent_version, last_seen, external_ip, mac_address, site_name,
        groups, platform_name, status, device_policies, and more.
        """
        results: list[dict] = []
        for i in range(0, len(aids), HOST_BATCH):
            chunk = aids[i : i + HOST_BATCH]
            r = self.post(
                "/devices/entities/devices/v2",
                json={"ids": chunk},
            )
            body = r.json()
            results.extend(body.get("resources", []))
            log.info("    fetched details for %d / %d hosts …", len(results), len(aids))
        return results

    # ── Application / software inventory ─────────────────────────────────────

    def scroll_app_ids(self) -> list[str]:
        """
        Page through all application IDs via
        GET /discover/queries/applications/v1.
        Requires Falcon Discover (Assets:read) scope.
        """
        app_ids: list[str] = []
        offset = 0
        while True:
            r = self.get(
                "/discover/queries/applications/v1",
                params={"limit": 1000, "offset": offset},
            )
            body  = r.json()
            batch = body.get("resources", [])
            app_ids.extend(batch)
            total = body.get("meta", {}).get("pagination", {}).get("total", len(app_ids))
            log.info("    scrolled %d / %d application IDs …", len(app_ids), total)
            if not batch or len(app_ids) >= total:
                break
            offset += len(batch)
        return app_ids

    def get_app_details(self, app_ids: list[str]) -> list[dict]:
        """
        Batch-fetch application details via
        GET /discover/entities/applications/v2?ids=...
        Fields include: name, version, vendor, install_date, host.hostname,
        host.agent_version, host.platform_name, is_normalized_vendor, and more.
        """
        results: list[dict] = []
        for i in range(0, len(app_ids), APP_BATCH):
            chunk = app_ids[i : i + APP_BATCH]
            r = self.get(
                "/discover/entities/applications/v2",
                params=[("ids", aid) for aid in chunk],
            )
            body = r.json()
            batch = body.get("resources", [])
            # Flatten the nested 'host' sub-object
            for app in batch:
                host = app.pop("host", None) or {}
                for k, v in host.items():
                    app[f"host_{k}"] = v
            results.extend(batch)
            log.info(
                "    fetched details for %d / %d apps …", len(results), len(app_ids)
            )
        return results

    # ── Management audit log via Audit Events API ─────────────────────────────

    def fetch_audit_events(self, from_date: str, to_date: str) -> list[dict]:
        """
        Pull management-plane audit events from the Audit Events endpoint:
        GET /audit/v1/events  (offset-paginated, up to 500 per call)

        Fields returned include: timestamp, audit_type, action, comment,
        user_name, user_uuid, cid, metadata (nested dict).

        NOTE: The /audit/v1/events endpoint requires the 'Audit Events: Read'
        API scope. If your API client was created before this scope existed,
        regenerate it and add the scope. If the endpoint returns 403, fall
        back to the NGSIEM approach commented below.
        """
        events: list[dict] = []
        offset = 0
        limit  = 500
        params_base = {
            "filter": (
                f"timestamp:>='{from_date}'"
                f"+timestamp:<='{to_date}'"
            ),
            "sort":   "timestamp|asc",
            "limit":  limit,
        }
        while True:
            params = dict(params_base)
            params["offset"] = offset
            r = self.get("/audit/v1/events", params=params)
            body  = r.json()
            batch = body.get("resources", [])
            # Flatten nested 'metadata' dict
            for record in batch:
                meta = record.pop("metadata", None) or {}
                for k, v in meta.items():
                    record[f"meta_{k}"] = v
            events.extend(batch)
            total = body.get("meta", {}).get("pagination", {}).get("total", len(events))
            log.info("    fetched %d / %d audit events …", len(events), total)
            if not batch or len(events) >= total:
                break
            offset += len(batch)
        return events


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def iso_to_epoch_ms(iso: str) -> int:
    """Convert ISO-8601 UTC string to Unix epoch milliseconds."""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def wait_for_ngsiem_job(
    client: CSClient,
    job_id: str,
    repository: str = NGSIEM_REPO,
) -> tuple[bool, int]:
    """
    Poll until the NGSIEM job is done.
    Returns (success, total_event_count).
    Status field is 'DONE', 'RUNNING', 'FAILED', or 'CANCELED'.
    """
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        status = client.ngsiem_status(job_id, repository)
        state = (
            status.get("status")
            or status.get("job_status")
            or "UNKNOWN"
        )
        total = status.get("totalCount") or status.get("total_count") or 0
        log.info("    status: %-10s  events so far: %s", state, total)
        if state in ("DONE", "COMPLETE", "SUCCEEDED"):
            return True, int(total)
        if state in ("FAILED", "CANCELED", "ERROR"):
            log.error("    job ended with state: %s", state)
            return False, 0
        time.sleep(POLL_INTERVAL)
    log.error("    timed out waiting for NGSIEM job %s", job_id)
    return False, 0


def fetch_all_ngsiem_events(
    client: CSClient,
    job_id: str,
    total: int,
    repository: str = NGSIEM_REPO,
) -> list[dict]:
    """Paginate through all events for a completed NGSIEM job."""
    events: list[dict] = []
    offset = 0
    while True:
        page  = client.ngsiem_results(job_id, repository, offset, PAGE_LIMIT)
        batch = page.get("events") or page.get("resources") or []
        events.extend(batch)
        log.info("    paginating: %d / %d events …", len(events), total or "?")
        if not batch or (total and len(events) >= total):
            break
        offset += len(batch)
    return events


def records_to_csv(records: list[dict], path: Path) -> int:
    """Write a list of flat dicts to CSV; returns row count."""
    if not records:
        path.write_text("", encoding="utf-8")
        return 0
    all_keys: list[str] = []
    seen: set[str] = set()
    for rec in records:
        for k in rec.keys():
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    return len(records)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_coc_entry(
    csv_name: str,
    level: str,
    description: str,
    query_type: str,
    from_date: str | None = None,
    to_date: str | None = None,
) -> dict:
    return {
        "file":         csv_name,
        "level":        level,
        "description":  description,
        "query_type":   query_type,
        "from_date":    from_date,
        "to_date":      to_date,
        "status":       None,
        "row_count":    None,
        "sha256":       None,
        "collected_at": None,
        "note":         None,
    }


def finalise_entry(entry: dict, path: Path, row_count: int) -> None:
    entry["status"]       = "success"
    entry["row_count"]    = row_count
    entry["sha256"]       = sha256_file(path)
    entry["collected_at"] = iso_now()


# ── Management API collectors ─────────────────────────────────────────────────

def collect_host_inventory(
    client: CSClient,
    output_dir: Path,
    coc_entries: list[dict],
) -> None:
    """Pull all device records and write HostInventory.csv."""
    csv_name = "HostInventory.csv"
    out_path = output_dir / csv_name
    entry    = make_coc_entry(
        csv_name, "LVL5",
        "Full endpoint inventory — hostname, OS, agent version, external IP, "
        "encryption status, policies (POST /devices/entities/devices/v2 via scroll)",
        "management_api",
    )
    log.info("[LVL5] %s  (management API — device inventory)", csv_name)
    try:
        aids      = client.scroll_device_ids()
        devices   = client.get_device_details(aids) if aids else []
        row_count = records_to_csv(devices, out_path)
        finalise_entry(entry, out_path, row_count)
        log.info("    wrote %d rows → %s  [sha256: %s…]",
                 row_count, out_path.name, entry["sha256"][:16])
    except requests.HTTPError as exc:
        entry["status"] = "http_error"
        entry["note"]   = str(exc)
        log.error("    HTTP error: %s", exc)
    except Exception as exc:
        entry["status"] = "error"
        entry["note"]   = str(exc)
        log.error("    Unexpected error: %s", exc)
    coc_entries.append(entry)


def collect_app_inventory(
    client: CSClient,
    output_dir: Path,
    coc_entries: list[dict],
) -> None:
    """Pull all Falcon Discover application records and write app-inventory.csv."""
    csv_name = "app-inventory.csv"
    out_path = output_dir / csv_name
    entry    = make_coc_entry(
        csv_name, "LVL5",
        "Full software / application inventory via Falcon Discover "
        "(GET /discover/queries/applications/v1 + /entities/applications/v2)",
        "management_api",
    )
    log.info("[LVL5] %s  (management API — Falcon Discover app inventory)", csv_name)
    try:
        app_ids   = client.scroll_app_ids()
        apps      = client.get_app_details(app_ids) if app_ids else []
        row_count = records_to_csv(apps, out_path)
        finalise_entry(entry, out_path, row_count)
        log.info("    wrote %d rows → %s  [sha256: %s…]",
                 row_count, out_path.name, entry["sha256"][:16])
    except requests.HTTPError as exc:
        entry["status"] = "http_error"
        entry["note"]   = str(exc)
        log.error("    HTTP error: %s  (check Falcon Discover / Assets:read scope)", exc)
    except Exception as exc:
        entry["status"] = "error"
        entry["note"]   = str(exc)
        log.error("    Unexpected error: %s", exc)
    coc_entries.append(entry)


def collect_mgmt_activity(
    client: CSClient,
    output_dir: Path,
    coc_entries: list[dict],
    from_date: str,
    to_date: str,
) -> None:
    """
    Pull management audit events for the assessment window and write MgmtActivity.csv.
    Uses GET /audit/v1/events (requires 'Audit Events: Read' scope).
    """
    csv_name = "MgmtActivity.csv"
    out_path = output_dir / csv_name
    entry    = make_coc_entry(
        csv_name, "LVL2",
        "Management console audit log — admin logins, policy changes, agent actions, "
        "role assignments, API key events (GET /audit/v1/events)",
        "management_api",
        from_date,
        to_date,
    )
    log.info("[LVL2] %s  (management API — audit events)", csv_name)
    try:
        events    = client.fetch_audit_events(from_date, to_date)
        row_count = records_to_csv(events, out_path)
        finalise_entry(entry, out_path, row_count)
        log.info("    wrote %d rows → %s  [sha256: %s…]",
                 row_count, out_path.name, entry["sha256"][:16])
    except requests.HTTPError as exc:
        entry["status"] = "http_error"
        entry["note"]   = (
            f"{exc}  — verify the API client has 'Audit Events: Read' scope. "
            "If not available on your plan, this file must be exported manually "
            "from the Falcon console Activity > Audit Log page."
        )
        log.error("    HTTP error: %s", exc)
    except Exception as exc:
        entry["status"] = "error"
        entry["note"]   = str(exc)
        log.error("    Unexpected error: %s", exc)
    coc_entries.append(entry)


# ── Main runner ───────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> None:
    # Resolve date range
    if args.from_date and args.to_date:
        from_date = args.from_date
        to_date   = args.to_date
    else:
        now       = datetime.now(timezone.utc)
        to_date   = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        from_date = (now - timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    from_ms = iso_to_epoch_ms(from_date)
    to_ms   = iso_to_epoch_ms(to_date)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    client = CSClient(args.base_url, args.client_id, args.client_secret)

    run_start = iso_now()
    run_host  = platform.node()
    run_user  = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    coc_entries: list[dict] = []

    script_path = Path(__file__).resolve()
    script_hash = sha256_file(script_path) if script_path.exists() else "unavailable"

    log.info("=" * 70)
    log.info("CS Cyber Risk Assessment Collection Script")
    log.info("  Range  : %s → %s", from_date, to_date)
    log.info("  Console: %s", args.base_url)
    log.info("  Output : %s", output_dir.resolve())
    log.info("  Script : %s  [sha256: %s]", script_path.name, script_hash[:16] + "…")
    log.info("=" * 70)

    # ── Phase 1: Management API — host inventory ──────────────────────────────
    log.info("")
    log.info("── Phase 1: Host inventory (management API) ──────────────────────")
    collect_host_inventory(client, output_dir, coc_entries)

    # ── Phase 2: Management API — application inventory ──────────────────────
    log.info("")
    log.info("── Phase 2: Application inventory (Falcon Discover API) ──────────")
    collect_app_inventory(client, output_dir, coc_entries)

    # ── Phase 3: Management API — audit activity log ──────────────────────────
    log.info("")
    log.info("── Phase 3: Management audit log (audit events API) ──────────────")
    collect_mgmt_activity(client, output_dir, coc_entries, from_date, to_date)

    # ── Phase 4: NGSIEM CQL queries ───────────────────────────────────────────
    dv_count = sum(1 for _, _, _, q in QUERIES if q is not None)
    log.info("")
    log.info("── Phase 4: NGSIEM CQL queries (%d total) ─────────────────────────",
             dv_count)

    for csv_name, level, description, query in QUERIES:
        out_path = output_dir / csv_name
        entry    = make_coc_entry(
            csv_name, level, description,
            "ngsiem_api" if query else "manual_export",
            from_date if query else None,
            to_date   if query else None,
        )

        if query is None:
            if out_path.exists():
                entry["sha256"]       = sha256_file(out_path)
                entry["status"]       = "manually_provided"
                entry["collected_at"] = iso_now()
                with out_path.open(encoding="utf-8", errors="replace") as f:
                    entry["row_count"] = max(0, sum(1 for _ in f) - 1)
                log.info("[%s] %s — manual export found, hashed (%d rows)",
                         level, csv_name, entry["row_count"])
            else:
                entry["status"] = "pending_manual_export"
                entry["note"]   = ("Export manually from Microsoft Entra portal "
                                   "and place in the output directory before analysis.")
                log.warning("[%s] %s — NOT FOUND (manual export required)",
                            level, csv_name)
            coc_entries.append(entry)
            continue

        # ── Run NGSIEM CQL job ─────────────────────────────────────────────────
        log.info("[%s] %s", level, csv_name)
        try:
            job_id = client.ngsiem_start(query, from_ms, to_ms)
            log.info("    jobId: %s", job_id)
            entry["job_id"] = job_id

            ok, total = wait_for_ngsiem_job(client, job_id)
            if not ok:
                entry["status"] = "query_failed"
                entry["note"]   = "NGSIEM job ended in a non-DONE state; no results collected."
                coc_entries.append(entry)
                continue

            events    = fetch_all_ngsiem_events(client, job_id, total)
            row_count = records_to_csv(events, out_path)
            finalise_entry(entry, out_path, row_count)
            log.info("    wrote %d rows → %s  [sha256: %s…]",
                     row_count, out_path.name, entry["sha256"][:16])

        except requests.HTTPError as exc:
            entry["status"] = "http_error"
            entry["note"]   = str(exc)
            log.error("    HTTP error: %s", exc)
        except Exception as exc:
            entry["status"] = "error"
            entry["note"]   = str(exc)
            log.error("    Unexpected error: %s", exc)

        coc_entries.append(entry)

    # ── Write chain-of-custody manifest ──────────────────────────────────────
    coc_path = output_dir / COC_FILENAME
    manifest = {
        "title":       "Chain of Custody — CrowdStrike Falcon Cyber Risk Assessment",
        "description": (
            "This manifest records every file produced or expected by the "
            "CS_query_runner.py script, including SHA-256 hashes for integrity "
            "verification, query provenance, collection timestamps, and row counts. "
            "It should accompany the CSV files when submitted for analysis."
        ),
        "collection_metadata": {
            "script":           script_path.name,
            "script_sha256":    script_hash,
            "operator_host":    run_host,
            "operator_user":    run_user,
            "run_started_utc":  run_start,
            "run_finished_utc": iso_now(),
            "query_from_date":  from_date,
            "query_to_date":    to_date,
            "cs_base_url":      args.base_url,
            "ngsiem_repository": NGSIEM_REPO,
            "python_version":   sys.version,
            "platform":         platform.platform(),
        },
        "files": coc_entries,
    }

    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    manifest_hash = sha256_file(coc_path)
    manifest["manifest_sha256"] = manifest_hash
    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    log.info("=" * 70)
    log.info("Chain of custody written → %s", coc_path)
    log.info("Manifest SHA-256: %s", manifest_hash)

    api_mgmt_ok = sum(1 for e in coc_entries if e["status"] == "success"
                      and e.get("query_type") == "management_api")
    ngsiem_ok   = sum(1 for e in coc_entries if e["status"] == "success"
                      and e.get("query_type") == "ngsiem_api")
    manual_ok   = sum(1 for e in coc_entries if e["status"] == "manually_provided")
    pending     = sum(1 for e in coc_entries if e["status"] == "pending_manual_export")
    failed      = sum(1 for e in coc_entries if e["status"] not in
                      ("success", "manually_provided", "pending_manual_export"))
    total_rows  = sum(e["row_count"] or 0 for e in coc_entries)

    log.info("")
    log.info("  Management API OK   : %d  (HostInventory, app-inventory, MgmtActivity)", api_mgmt_ok)
    log.info("  NGSIEM queries OK   : %d", ngsiem_ok)
    log.info("  Manual exports found: %d", manual_ok)
    log.info("  Manual exports MISSING: %d  (Entra ID — add before analysis)", pending)
    log.info("  Errors              : %d", failed)
    log.info("  Total data rows     : %d", total_rows)
    log.info("=" * 70)

    if pending:
        log.warning("Files requiring manual export:")
        for e in coc_entries:
            if e["status"] == "pending_manual_export":
                log.warning("  %-35s  [%s] %s", e["file"], e["level"], e["description"])


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon bulk query runner with chain-of-custody manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API scopes required on the OAuth2 client:
  Hosts                  : Read   (device inventory)
  NGSIEM / LogScale      : Read + Write  (CQL queries)
  Falcon Discover        : Read   (application inventory)
  Audit Events           : Read   (management activity log)

Base URL by cloud region:
  US-1  https://api.crowdstrike.com          (default)
  US-2  https://api.us-2.crowdstrike.com
  EU-1  https://api.eu-1.crowdstrike.com
  GOV-1 https://api.laggar.gcw.crowdstrike.com

Examples:
  # Last 90 days, US-1 cloud
  python CS_query_runner.py --client-id ID --client-secret SECRET

  # Specific date window
  python CS_query_runner.py --client-id ID --client-secret SECRET \\
      --from-date 2026-02-25T00:00:00Z --to-date 2026-05-25T23:59:59Z

  # EU-1 cloud, custom output directory
  python CS_query_runner.py --client-id ID --client-secret SECRET \\
      --base-url https://api.eu-1.crowdstrike.com \\
      --output ./acme_assessment_may2026
""",
    )
    parser.add_argument("--client-id",     dest="client_id",     required=True,
                        help="CrowdStrike OAuth2 client ID")
    parser.add_argument("--client-secret", dest="client_secret", required=True,
                        help="CrowdStrike OAuth2 client secret")
    parser.add_argument("--base-url",      dest="base_url",
                        default="https://api.crowdstrike.com",
                        help="Falcon API base URL (default: https://api.crowdstrike.com)")
    parser.add_argument("--days",          type=int, default=90,
                        help="Look-back window in days if --from-date/--to-date omitted (default: 90)")
    parser.add_argument("--from-date",     dest="from_date",     default=None,
                        help="Query start ISO-8601 UTC (e.g. 2026-02-25T00:00:00Z)")
    parser.add_argument("--to-date",       dest="to_date",       default=None,
                        help="Query end   ISO-8601 UTC (e.g. 2026-05-25T23:59:59Z)")
    parser.add_argument("--output",        default="./cs_assessment_output",
                        help="Output directory for CSV files and CoC manifest")

    args = parser.parse_args()

    if bool(args.from_date) ^ bool(args.to_date):
        parser.error("--from-date and --to-date must both be provided together.")

    run(args)


if __name__ == "__main__":
    main()
