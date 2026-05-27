#!/usr/bin/env python3
"""
s1_query_runner.py
Cyber Risk Assessment — SentinelOne Automated Collection Script
Shane D. Shook, PhD (c) 2026  |  Automated by script

Collects three categories of data from SentinelOne via the v2.1 Management API:

  1. Deep Visibility power queries  (LVL1–LVL5 threat-hunting queries)
  2. Host / agent inventory         → HostInventory.csv
  3. Application inventory          → app-inventory.csv
  4. Management activity log        → MgmtActivity.csv

Writes every result to an individual CSV file in an output directory and
produces a signed chain-of-custody manifest (JSON + SHA-256).

Usage:
    python s1_query_runner.py \
        --url  https://YOUR-TENANT.sentinelone.net \
        --token YOUR_API_TOKEN \
        [--days 90] \
        [--output ./assessment_output] \
        [--from-date 2026-02-25T00:00:00Z] \
        [--to-date   2026-05-25T23:59:59Z]

    If --from-date / --to-date are omitted the script defaults to the
    last --days days (default 90) ending at the moment of execution.
    The --days / date-range window is applied to Deep Visibility queries
    and the management activity log.  The host and application inventories
    always reflect current console state (point-in-time snapshot).

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
log = logging.getLogger("s1_runner")

# ── Constants ─────────────────────────────────────────────────────────────────
POLL_INTERVAL   = 5      # seconds between status polls
POLL_TIMEOUT    = 600    # seconds before giving up on a single query
PAGE_LIMIT      = 1000   # S1 maximum events per page
COC_FILENAME    = "chain_of_custody.json"

# ── Query catalogue ───────────────────────────────────────────────────────────
# Each entry:  (output_csv, risk_level, description, query_string)
# Queries that cannot be run via Deep Visibility API (console exports /
# inventory pulls) are flagged with query_string = None and noted in the CoC.

QUERIES = [

    # ── LVL1  Cloud Storage ───────────────────────────────────────────────────
    (
        "CloudUsers.csv", "LVL1",
        "Cloud storage sync client outbound connections by user",
        """filter event.type = "IP Connect"
| filter src.process.image.path contains:anycase ("Dropbox", "BoxSync", "BoxDrive", "GoogleDrive", "BackupAndSync", "iCloud", "pCloud", "MegaSync", "Tresorit", "Egnyte", "SyncApp")
    OR src.process.name contains:anycase ("dropbox", "boxsync", "googledrivefs", "googledrivesync", "megasync", "pcloud", "tresorit")
| filter event.network.direction = "OUTGOING"
| filter NOT (src.process.image.path contains:anycase ("Microsoft", "Windows"))
| group lookups = count() by src.process.name, src.process.user
|| sort -unique_users""",
    ),
    (
        "CloudSync.csv", "LVL1",
        "Command-line cloud upload activity (process cmdline references)",
        """filter event.type in ("Process Creation", "Process Modification")
| filter src.process.cmdline contains:anycase ("box.com", "dropbox.com", "drive.google.com", "mega.nz", "wetransfer.com", "pcloud.com", "egnyte.com", "mediafire.com", "gofile.io", "transfer.sh", "pastebin.com", "rclone", "curl -T", "curl -F", "curl -d", "-Method PUT", "-Method POST", "Invoke-WebRequest", "aws s3", "gsutil", "azcopy")
| filter NOT (src.process.name contains:anycase ("chrome", "msedge", "firefox"))
| columns endpoint.name, event.time, src.process.name, src.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL1  AI Users ────────────────────────────────────────────────────────
    (
        "AIUsers.csv", "LVL1",
        "AI tool desktop application usage by user (process launches)",
        """filter event.type = "Process Creation"
| filter tgt.process.name contains:anycase ("claude", "perplexity", "notion", "cursor", "ollama", "lmstudio", "gpt4all", "koboldcpp", "llama", "whisper", "krisp", "otter", "fathom", "fireflies", "elevenlabs", "runway", "grammarly", "jasper", "codeium", "tabnine", "windsurf", "gemini", "chatgpt", "copilot", "zed")
| filter NOT (tgt.process.name contains:anycase ("update", "updater", "setup", "install", "uninstall", "helper", "native-host", "crash", "proxy", "autostarter"))
| group launches = count() by tgt.process.name, src.process.user
| sort tgt.process.name, -launches""",
    ),
    (
        "AIWebUse.csv", "LVL1",
        "AI service browser access by DNS resolution",
        """filter event.type = "DNS Resolved"
| filter event.dns.request contains:anycase ("claude", "anthropic", "openai", "chatgpt", "perplexity", "gemini", "copilot.microsoft", "grok.x", "mistral", "huggingface", "character.ai", "poe.com", "pi.ai", "together.ai", "replicate.com", "jasper.ai", "copy.ai", "writesonic.com", "grammarly.com", "notion.so", "cursor.sh")
| filter NOT (src.process.name contains:anycase ("MsMpEng", "SentinelAgent", "svchost"))
| group lookups = count() by event.dns.request, src.process.user
| group unique_users = count() by event.dns.request
| sort -unique_users""",
    ),

    # ── LVL1  USB ─────────────────────────────────────────────────────────────
    (
        "USBConnected.csv", "LVL1",
        "USB storage device registry connection events",
        """filter event.type in ("Registry Key Create")
| filter registry.keyPath contains "USBSTOR"
| filter registry.keyPath contains "Disk"
| columns endpoint.name, event.time, registry.value, registry.keyPath
| sort endpoint.name, event.time""",
    ),
    (
        "USBUse.csv", "LVL1",
        "Process activity referencing non-standard (removable) drive letters",
        r"""filter event.type in ("Process Creation", "Process Modification")
| filter src.process.cmdline contains "D:\\"
    OR src.process.cmdline contains "E:\\"
    OR src.process.cmdline contains "F:\\"
    OR src.process.cmdline contains "G:\\"
    OR src.process.cmdline contains "H:\\"
    OR src.process.cmdline contains "I:\\"
    OR src.process.cmdline contains "J:\\"
    OR src.process.cmdline contains "K:\\"
    OR src.process.cmdline contains "L:\\"
    OR src.process.cmdline contains "M:\\"
    OR src.process.cmdline contains "N:\\"
    OR src.process.cmdline contains "O:\\"
    OR src.process.cmdline contains "Q:\\"
    OR src.process.cmdline contains "R:\\"
    OR src.process.cmdline contains "S:\\"
    OR src.process.cmdline contains "T:\\"
    OR src.process.cmdline contains "U:\\"
    OR src.process.cmdline contains "V:\\"
    OR src.process.cmdline contains "W:\\"
    OR src.process.cmdline contains "X:\\"
    OR src.process.cmdline contains "Y:\\"
    OR src.process.cmdline contains "Z:\\"
| filter NOT (src.process.cmdline contains "HostGUID"
    OR src.process.cmdline contains "HKLM:"
    OR src.process.cmdline contains "HTTP")
| filter NOT (src.process.name contains "edge" OR src.process.name contains "chrome")
| columns endpoint.name, event.time, src.process.name, osSrc.process.cmdline, src.process.cmdline
| sort endpoint.name, event.time""",
    ),

    # ── LVL2  User Profile Propagation ───────────────────────────────────────
    (
        "UPPCount.csv", "LVL2",
        "User profile propagation summary — logins across multiple endpoints",
        """filter event.type = "Login"
| group total_logons = count() by event.login.userName, event.login.type, endpoint.name
| group unique_computers = count(), total_logons = sum(total_logons) by event.login.userName, event.login.type
| filter unique_computers > 1 AND unique_computers < 42
| sort -unique_computers""",
    ),
    (
        "UPPActivity.csv", "LVL2",
        "Detailed login activity for administratively flagged accounts",
        """filter event.type = "Login"
| filter event.login.userName in ("administrator", "admin", "Administrator", "Admin")
| columns event.login.userName, event.login.type, endpoint.name, timestamp
| sort event.login.userName, timestamp""",
    ),

    # ── LVL2  User Services ───────────────────────────────────────────────────
    (
        "UserServices.csv", "LVL2",
        "User-space processes making outbound network connections",
        """filter event.type = "IP Connect"
| filter src.process.image.path contains "Users"
| filter NOT (src.process.image.path contains "Microsoft")
| filter NOT (src.process.image.path contains "Zoom")
| filter NOT (src.process.image.path contains "GoToMeeting")
| filter NOT (src.process.image.path contains "Grammarly")
| filter NOT (src.process.image.path contains "Notion")
| filter NOT (src.process.image.path contains "Creative")
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.ip.address, dst.ip.address, dst.port.number, event.network.direction, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL2  Credential Theft ────────────────────────────────────────────────
    (
        "CredentialTheft.csv", "LVL2",
        "LSASS process handle access events (credential theft indicator)",
        """filter event.type = "Open Remote Process Handle"
| filter tgt.process.name = "lsass.exe"
| filter NOT (src.process.name in ("MsMpEng.exe", "SentinelAgent.exe", "SentinelServiceHost.exe", "tphkload.exe", "MBAMService.exe", "AdobeARM.exe", "Taskmgr.exe", "msiexec.exe", "MRT.exe"))
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.process.user, tgt.process.name, tgt.process.cmdline, src.process.cmdline
| sort endpoint.name, event.time""",
    ),

    # ── LVL2  WMI Lateral Movement ───────────────────────────────────────────
    (
        "WMILateral.csv", "LVL2",
        "WMI-spawned process creation (lateral movement indicator)",
        """filter event.type = "Process Creation"
| filter src.process.name contains:anycase ("wmiprvse.exe", "WmiPrvSE.exe")
| filter NOT (tgt.process.name contains:anycase ("WmiPrvSE.exe", "WerFault.exe"))
| columns endpoint.name, event.time, src.process.name, tgt.process.name, tgt.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL2  Local Privilege Escalation ──────────────────────────────────────
    (
        "LPE.csv", "LVL2",
        "Local privilege escalation — non-system user spawning admin tools",
        """filter event.type = "Process Creation"
| filter NOT (src.process.user contains:anycase ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NETWORK", "DWM", "UMFD"))
| filter tgt.process.name contains:anycase ("cmd", "powershell", "net.exe", "net1.exe", "whoami", "runas")
| filter NOT tgt.process.cmdline contains "Sentinel"
| group count = count() by endpoint.name, src.process.user, tgt.process.name, tgt.process.cmdline
| sort endpoint.name, -count""",
    ),

    # ── LVL2  Privilege Hygiene ───────────────────────────────────────────────
    (
        "PrivilegeRisks.csv", "LVL2",
        "Privilege hygiene issues — low-integrity processes spawning high-integrity targets",
        """src.process.user = *
| filter tgt.process.userSid = *
| filter tgt.process.integrityLevel in ("HIGH", "SYSTEM")
| filter src.process.integrityLevel in ("LOW", "MEDIUM")
| filter src.process.userSid != "S-1-5-18"
| filter src.process.userSid != "S-1-5-19"
| filter src.process.userSid != "S-1-5-20"
| group
    endpointCount = estimate_distinct(endpoint.name),
    eventCount = count(),
    sourceUserCount = estimate_distinct(src.process.userSid),
    sameUserHighEvents = count(src.process.userSid = tgt.process.userSid and tgt.process.integrityLevel = "HIGH"),
    differentUserHighEvents = count(src.process.userSid != tgt.process.userSid and tgt.process.integrityLevel = "HIGH"),
    uacConsentEvents = count(tgt.process.name = "consent.exe"),
    systemBrokerEvents = count(tgt.process.userSid = "S-1-5-18" and tgt.process.integrityLevel = "SYSTEM"),
    installerEvents = count(src.process.name in ("msiexec.exe","setup.exe","install.exe","installer.exe") or tgt.process.name in ("msiexec.exe","setup.exe","install.exe","installer.exe") or src.process.name contains:anycase "setup" or tgt.process.name contains:anycase "setup" or src.process.name contains:anycase "install" or tgt.process.name contains:anycase "install"),
    adminToolEvents = count(src.process.name in ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","schtasks.exe","wmic.exe","psexec.exe","psexesvc.exe","certutil.exe","bitsadmin.exe","python.exe") or tgt.process.name in ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","schtasks.exe","wmic.exe","psexec.exe","psexesvc.exe","certutil.exe","bitsadmin.exe","python.exe")),
    accessibilityAtLogonEvents = count(src.process.name in ("sethc.exe","utilman.exe","osk.exe","magnify.exe","narrator.exe") or src.process.parent.name = "winlogon.exe"),
    printerInstallEvents = count(src.process.cmdline contains:anycase "printui.dll" or tgt.process.image.path contains:anycase "\\\\Printer Drivers\\\\" or tgt.process.name in ("KmInstall.exe","KmUninstall.exe")),
    vendorInstallEvents = count(src.process.name contains:anycase "Acrobat" or tgt.process.name contains:anycase "Acrobat" or src.process.name contains:anycase "ChromeSetup" or tgt.process.name contains:anycase "OfficeClickToRun" or src.process.name contains:anycase "CreativeCloud" or src.process.name contains:anycase "Claude Setup" or tgt.process.image.path contains:anycase "\\\\Adobe\\\\" or tgt.process.image.path contains:anycase "\\\\Microsoft Shared\\\\ClickToRun\\\\"),
    commonWindowsHighEvents = count(tgt.process.name in ("runonce.exe","Taskmgr.exe","SynTPHelper.exe"))
  by endpoint.name, src.process.parent.name, src.process.name, src.process.cmdline, src.process.user, src.process.userSid, src.process.integrityLevel, tgt.process.name, tgt.process.userSid, tgt.process.integrityLevel, tgt.process.image.path, tgt.process.image.sha256, tgt.process.cmdline
| filter sameUserHighEvents > 0 or differentUserHighEvents > 0 or adminToolEvents > 0 or accessibilityAtLogonEvents > 0 or (uacConsentEvents > 0 and printerInstallEvents = 0 and vendorInstallEvents = 0)
| sort -sameUserHighEvents, -differentUserHighEvents, -adminToolEvents, -accessibilityAtLogonEvents, -uacConsentEvents, -installerEvents, -eventCount""",
    ),

    # ── LVL3  Network Tunnels ─────────────────────────────────────────────────
    (
        "NetworkTunnels.csv", "LVL3",
        "Tunnel tool process network connections (ngrok, cloudflared, frpc, etc.)",
        """filter event.type = "IP Connect"
| filter src.process.image.path contains:anycase ("ngrok", "cloudflared", "frpc", "ligolo", "chisel", "bore", "rathole", "tunnelto", "tor")
    OR src.process.name contains:anycase ("ngrok", "cloudflared", "frpc", "ligolo", "chisel", "bore", "rathole", "tunnelto", "tor")
| filter NOT (src.process.image.path contains:anycase ("Monitor", "Doctor", "Repository", "Protector", "Suttora", "Collector", "Editor", "WindowsApps", "store", "Laborator", "Microsoft", "ToRun", "DriverStore"))
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.ip.address, dst.ip.address, dst.port.number, event.network.direction, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL3  DNS / DGA ───────────────────────────────────────────────────────
    (
        "DGABeacons.csv", "LVL3",
        "High-frequency NXDOMAIN DNS requests (DGA / beaconing pattern)",
        """filter event.type = "DNS Unresolved"
| filter NOT (event.dns.request contains:anycase ("rocketcyber.com", "digicert.com", "grammarly.io", "opendns.com", "typekit.com", "in-addr.arpa", "microsoft.com", "wpad", "_ldap", "office", "amazon", "google", "microsoft", "yahoo", "azure", "verizon", "kaseya", "7layerit", "adobe", "example", "dynatrace", "webex", ".pub.", "cdn", "arpa", "windowsupdate", "doubleclick", "sentinelone", "zoom", "pki", "msft", "metrix", "trafficmanager", "kerberos", "tcp.", "duckduckgo", "southwest", "ipv4", "ipv6", "autodiscover", "actionablemessage", "claude", "scorecard", "casalmedia", "verisign"))
| group nxdomain_count = count() by endpoint.name, src.process.name, src.process.user, event.dns.request
| filter nxdomain_count > 100
| sort -nxdomain_count""",
    ),
    (
        "BadTLDs.csv", "LVL3",
        "DNS queries to high-risk country-code and generic TLDs",
        """filter event.type in ("DNS Resolved", "DNS Unresolved")
| filter event.dns.request contains:anycase (".ru", ".cn", ".onion", ".tk", ".xyz", ".top", ".icu")
| filter NOT (src.process.name contains:anycase ("MsMpEng", "SentinelAgent"))
| filter NOT (event.dns.request contains "rubicon" OR event.dns.request contains "digicert")
| columns endpoint.name, src.process.name, event.dns.request, src.process.user, event.time
| sort endpoint.name, event.time""",
    ),

    # ── LVL3  Backdoors ───────────────────────────────────────────────────────
    (
        "BackdoorsIn.csv", "LVL3",
        "Inbound connections on non-standard ports",
        """filter event.type = "IP Connect"
| filter src.port.number < 10000
| filter event.network.direction contains "INCOMING"
| filter NOT (dst.ip.address = "127.0.0.1")
| filter NOT (src.port.number = 135 OR src.port.number = 139 OR src.port.number = 0 OR dst.port.number = 7680)
| columns endpoint.name, src.process.name, src.process.image.path, src.ip.address, src.port.number, dst.ip.address, dst.port.number, event.network.direction, src.process.user, event.time
| sort endpoint.name, event.time""",
    ),
    (
        "BackdoorsOut.csv", "LVL3",
        "Outbound connections on non-standard ports and protocols",
        """filter event.type = "IP Connect"
| filter event.network.direction = "OUTGOING"
| filter NOT (dst.ip.address contains "127.0.0.1" OR dst.ip.address contains "192.168." OR dst.ip.address contains "172." OR dst.ip.address contains "10." OR dst.ip.address contains "169.")
| filter NOT (dst.port.number in (53, 80, 8080, 8081, 443, 3268, 3478, 5228, 7680, 19305, 52311))
| filter NOT (src.process.name contains:anycase ("SentinelAgent", "MsMpEng", "AgentMon", "KaseyaEndpoint", "ntoskrnl", "OUTLOOK", "KDService", "ms-teams"))
| filter NOT (src.process.cmdline contains:anycase ("update", "mojo", "Office", "rocket"))
| columns endpoint.name, event.time, src.ip.address, src.port.number, dst.ip.address, dst.port.number, src.process.name, src.process.image.path, src.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL3  Beacons ─────────────────────────────────────────────────────────
    (
        "Beacons.csv", "LVL3",
        "High-frequency outbound IP connections (>500) by process/destination",
        """filter event.type = "IP Connect"
| filter event.network.direction = "OUTGOING"
| filter src.process.name = *
| filter NOT (src.process.name contains:anycase ("MsMpEng.exe", "SentinelAgent.exe", "proxy", "MpsMonitor", "spoolsv", "MsSense", "Rocket", "Spotify", "edge", "opera", "firefox", "chrome", "adobe"))
| filter NOT (src.process.cmdline contains:anycase ("office", "Onedrive", "Zoom", "Program Files", "ProgramData", "Kaseya", "instal", "upgr", "update", "claude"))
| filter NOT (dst.ip.address contains "127.0.0.1" OR dst.ip.address contains "192.168." OR dst.ip.address contains "172.")
| group connection_count = count() by endpoint.name, src.process.name, dst.ip.address
| filter connection_count > 500
| sort -connection_count""",
    ),

    # ── LVL4  RMM ─────────────────────────────────────────────────────────────
    (
        "RmmUse.csv", "LVL4",
        "RMM tool process creation events",
        """filter event.type = "Process Creation"
| filter tgt.process.image.path contains:anycase ("mstsc", "TeamViewer", "GoToMeeting", "g2m", "AnyDesk", "ScreenConnect", "ConnectWise", "LogMeIn", "Splashtop", "Bomgar", "BeyondTrust", "NinjaRMM", "Atera", "Pulseway", "remoting_host", "VNC", "ZohoAssist", "Supremo", "Datto", "DameWare", "DWRCS", "dwrcc")
| filter NOT (tgt.process.image.path contains "DriverStore")
| columns endpoint.name, event.time, tgt.process.name, tgt.process.image.path, src.process.user
| sort endpoint.name, event.time""",
    ),
    (
        "RMMComms.csv", "LVL4",
        "RMM tool active network connections",
        """filter event.type = "IP Connect"
| filter src.process.image.path contains:anycase ("mstsc", "TSClient", "TeamViewer", "AnyDesk", "ScreenConnect", "ConnectWise", "LogMeIn", "Splashtop", "Bomgar", "BeyondTrust", "NinjaRMM", "RealVNC", "TightVNC", "UltraVNC", "WinVNC", "Datto", "Zoho", "Supremo", "Rescue", "GoToAssist", "GoToMyPC", "GoTo", "Citrix", "ISL", "RemotePC", "Getscreen", "Fixme", "Mikogo", "BASup", "RustDesk", "LMI_Rescue", "LanDesk", "DameWare", "DWRCS", "dwrcs")
    OR src.process.name contains:anycase ("LanDesk", "BASup", "RustDesk", "LMI", "mstsc", "TSClient", "vncviewer", "winvnc", "AnyDesk", "TeamViewer", "ScreenConnect", "bomgar", "Rescue", "g2ax", "GoToMeeting", "Supremo", "ISLLight", "RemotePCService", "rfusclient", "wfica32", "DameWare", "DWRCS", "dwrcc")
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.ip.address, dst.ip.address, dst.port.number, event.network.direction, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  LOLBin ─────────────────────────────────────────────────────────
    (
        "LolBinUse.csv", "LVL4",
        "Living-off-the-land binary execution",
        """filter event.type = "Process Creation"
| filter src.process.image.path contains:anycase ("certutil", "bitsadmin", "mshta", "sfc.exe", "hh.exe", "wscript", "cscript", "regsvr32", "rundll32", "msiexec", "wmic", "installutil", "regasm", "regsvcs", "cmstp", "msbuild", "dnscmd", "odbcconf", "pcalua", "appsyncpublishingserver", "syncappvpublishingserver", "pwsh", "posh", "powershell", "desktopimgdownldr", "esentutl", "extrac32", "findstr", "makecab", "mavinject", "Microsoft.Workflow.Compiler", "msdeploy", "msdt", "msiexecntdsutil", "presentationhost", "replace", "rpcping", "runscripthelper", "shdocvw", "wab", "xwizard")
| filter NOT (src.process.cmdline contains "Embedding" OR src.process.cmdline contains "CbsPersist" OR src.process.cmdline contains "Kaseya" OR src.process.cmdline contains "REPAIRFROMAPP" OR src.process.cmdline contains "PfSvWsSwap")
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),
    (
        "LolBinMasq.csv", "LVL4",
        "Potential LOLBin masquerade — binaries in non-standard paths",
        """filter event.type = "Process Creation"
| filter src.process.image.path contains:anycase ("svhost.exe", "svchost.exe", "rundll.exe", "rundll32.exe", "\\\\service.exe", "cmd.exe")
| filter NOT (src.process.image.path contains:anycase ("System", "SysWow", "WinSxS"))
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Base64 ──────────────────────────────────────────────────────────
    (
        "Base64Activities.csv", "LVL4",
        "Encoded command execution (base64 == padding in cmdline)",
        """filter event.type in ("Process Creation", "Process Modification")
| filter src.process.cmdline contains "=="
| filter NOT (src.process.name contains "edge" OR src.process.name contains "chrome")
| columns endpoint.name, event.time, src.process.name, osSrc.process.cmdline, src.process.cmdline
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Scheduled Tasks ─────────────────────────────────────────────────
    (
        "SchTasks.csv", "LVL4",
        "Scheduled task registration from user or temp paths",
        r"""filter event.type in ("Task Register", "Task Update")
| filter src.process.cmdline contains "\\Users\\" OR src.process.cmdline contains "\\Temp\\"
| filter NOT (src.process.name in ("svchost.exe", "taskeng.exe"))
| filter NOT (src.process.name contains "OneDrive" OR src.process.cmdline contains "\\Lvf")
| filter NOT (src.process.image.path contains:anycase ("Zoom", "piriform", "Office", "Edge"))
| columns endpoint.name, event.time, src.process.name, src.process.image.path, src.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Process Injection ───────────────────────────────────────────────
    (
        "ProcessInjections.csv", "LVL4",
        "Remote thread creation events (process injection indicator)",
        """filter event.type = "Remote Thread Creation"
| filter tgt.process.name = *
| filter NOT (src.process.name = tgt.process.name)
| filter NOT (src.process.name contains:anycase ("WerFault", "WerFaultSecure", "MBAM", "MsMpEng", "SentinelAgent", "SentinelServiceHost", "csrss", "wininit", "services.exe"))
| filter NOT (tgt.process.name contains:anycase ("spoolsv"))
| columns endpoint.name, event.time, src.process.name, src.process.image.path, tgt.process.name, src.process.user, src.process.cmdline
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Office Shells ───────────────────────────────────────────────────
    (
        "ShellsSpawn.csv", "LVL4",
        "Office applications spawning shells or LOLBins",
        """filter event.type = "Process Creation"
| filter src.process.name contains:anycase ("winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub")
| filter tgt.process.name contains:anycase ("cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "ftp.exe", "curl.exe", "nslookup", "wmic", "msbuild", "installutil", "regasm", "regsvcs", "cmstp", "odbcconf", "schtasks", "at.exe", "sc.exe", "msiexec", "reg.exe", "regedit", "net.exe", "net1.exe", "nltest", "whoami", "systeminfo", "ipconfig", "tasklist", "taskkill", "vssadmin", "wbadmin", "bcdedit", "esentutl", "expand.exe", "extrac32", "findstr", "hh.exe", "makecab", "mavinject", "msdt.exe", "pcalua", "presentationhost", "xwizard", "replace.exe", "forfiles", "mmc.exe", "explorer.exe", "ping.exe", "arp.exe", "netstat", "icacls", "takeown", "attrib.exe", "cipher.exe", "sdelete", "dnscmd", "rpcping")
| filter NOT (tgt.process.name contains:anycase ("acrobat", "cabinet"))
| filter NOT (tgt.process.cmdline contains:anycase ("Office", "OfficeC2R", "Teams"))
| columns endpoint.name, event.time, src.process.user, src.process.name, tgt.process.name, tgt.process.cmdline, src.process.cmdline
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  User Executables ────────────────────────────────────────────────
    (
        "UserExecs.csv", "LVL4",
        "Executables dropped in writable user locations (Temp, AppData, Downloads)",
        r"""filter event.type = "File Creation"
| filter tgt.file.path contains "\\Temp\\"
    OR tgt.file.path contains "\\AppData\\Local\\Temp\\"
    OR tgt.file.path contains "\\AppData\\Roaming\\"
    OR tgt.file.path contains "\\Downloads\\"
    OR tgt.file.path contains "\\Public\\"
| filter src.process.name = *
| filter tgt.file.extension contains:anycase ("exe", "cmd", "ps1", "vbs", "scr", "jar")
| filter NOT (src.process.name in ("MsMpEng.exe", "SentinelAgent.exe", "msiexec.exe", "WindowsInstaller"))
| filter NOT (tgt.file.path contains "Program Files" OR tgt.file.path contains "chrom" OR tgt.file.path contains "ProgramData")
| filter NOT (src.process.name contains "setup" OR src.process.name contains "updat" OR src.process.name contains "inst" OR src.process.name contains "vc_redist" OR src.process.name contains "Set-up" OR src.process.name contains "HP" OR src.process.name contains "icarus" OR src.process.name contains "package" OR src.process.name contains "MSI" OR src.process.name contains "runtime" OR src.process.name contains "claude" OR src.process.name contains "Creative" OR src.process.name contains "driver" OR src.process.name contains "Zoom")
| columns endpoint.name, event.time, src.process.user, src.process.name, tgt.file.extension, tgt.file.path
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  New Services ────────────────────────────────────────────────────
    (
        "NewServices.csv", "LVL4",
        "Suspicious new Windows service installations via sc.exe",
        """filter event.type = "Process Creation"
| filter tgt.process.name = "sc.exe"
| filter tgt.process.cmdline contains "create" OR tgt.process.cmdline contains "config"
| filter NOT (src.process.name contains:anycase ("msiexec.exe", "TrustedInstaller.exe", "AgentMon.exe", "Lenovo"))
| columns endpoint.name, event.time, src.process.name, tgt.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Rootkits / Driver Loads ────────────────────────────────────────
    (
        "Rootkits.csv", "LVL4",
        "Non-benign driver load events (rootkit indicator)",
        """filter event.type = "Driver Load"
| filter NOT (driver.loadVerdict = "BENIGN")
| filter NOT (src.process.name contains "ntoskrnl.exe")
| columns endpoint.name, event.time, src.process.name, driver.loadVerdict
| sort endpoint.name, event.time""",
    ),

    # ── LVL4  Suspicious Scripts ──────────────────────────────────────────────
    (
        "SuspScripts.csv", "LVL4",
        "Command script events with download or execution indicators",
        """filter event.type = "Command Script"
| filter src.process.cmdline contains:anycase ("IEX", "Invoke-Expression", "Net.WebClient", "DownloadString", "DownloadFile", "WebRequest", "bitsadmin", "Start-BitsTransfer", "Reflection.Assembly", "FromBase64String")
    OR tgt.process.cmdline contains:anycase ("IEX", "Invoke-Expression", "Net.WebClient", "DownloadString", "DownloadFile", "WebRequest", "bitsadmin", "Start-BitsTransfer", "Reflection.Assembly", "FromBase64String")
| columns endpoint.name, event.time, src.process.name, src.process.cmdline, tgt.process.cmdline, src.process.user
| sort endpoint.name, event.time""",
    ),

    # ── LVL5  OS Builds ───────────────────────────────────────────────────────
    (
        "OSBuilds.csv", "LVL5",
        "Endpoint OS name and build revision inventory",
        """filter os.name = *
| group count = count() by endpoint.name, os.name, mgmt.osRevision
| sort endpoint.name""",
    ),

    # ── LVL5  Endpoint Activity Health ───────────────────────────────────────
    (
        "Endpoints.csv", "LVL5",
        "Daily event counts per endpoint (Process Creation, IP Connect, Login) for health comparison",
        """event.type in ('Process Creation', 'IP Connect', 'Login')
| group count = count() by timestamp = timebucket("1d"), endpoint.name, event.type
| sort timestamp, endpoint.name, event.type""",
    ),

    # ── LVL5  Console-only exports — now automated above ─────────────────────
    # The following files are collected automatically by Phase 1–3 above:
    #   HostInventory.csv   → Phase 1  (GET /web/api/v2.1/agents)
    #   app-inventory.csv   → Phase 2  (GET /web/api/v2.1/application-management/applications)
    #   MgmtActivity.csv    → Phase 3  (GET /web/api/v2.1/activities)
    #
    # The filtered app-inventory exports (sentinelone.csv, kaseya.csv, etc.)
    # can be derived from app-inventory.csv in post-processing.
    # They are documented here as manual exports for analysts who prefer them
    # as separate files.
    ("SentinelsGeoLocs.csv",     "LVL5", "Geolocation of console-visible IPs (manual — derive from HostInventory.csv externalIp field via IP geolocation API)", None),
    # Entra ID — exported from Microsoft Entra portal (no SentinelOne API equivalent)
    ("EntraUsers.csv",  "LVL2", "Entra ID user accounts (Entra portal export — manual)", None),
    ("EntraGroups.csv", "LVL2", "Entra ID group memberships (Entra portal export — manual)", None),
    ("EntraRoles.csv",  "LVL2", "Entra ID privileged role assignments (Entra portal export — manual)", None),
]


# ── SentinelOne API client ────────────────────────────────────────────────────

class S1Client:
    def __init__(self, base_url: str, api_token: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"ApiToken {api_token}",
            "Content-Type": "application/json",
        })

    def _url(self, path: str) -> str:
        return f"{self.base}{path}"

    def init_query(self, query: str, from_date: str, to_date: str) -> str:
        payload = {"query": query, "fromDate": from_date, "toDate": to_date}
        r = self.session.post(self._url("/web/api/v2.1/dv/init-query"), json=payload)
        r.raise_for_status()
        return r.json()["data"]["queryId"]

    def query_status(self, query_id: str) -> dict:
        r = self.session.get(
            self._url("/web/api/v2.1/dv/query-status"),
            params={"queryId": query_id},
        )
        r.raise_for_status()
        return r.json()["data"]

    def get_events_page(self, query_id: str, cursor: str | None = None) -> dict:
        params = {"queryId": query_id, "limit": PAGE_LIMIT}
        if cursor:
            params["cursor"] = cursor
        r = self.session.get(self._url("/web/api/v2.1/dv/events"), params=params)
        r.raise_for_status()
        return r.json()

    def fetch_all_events(self, query_id: str) -> list[dict]:
        events, cursor = [], None
        while True:
            page = self.get_events_page(query_id, cursor)
            batch = page.get("data", [])
            events.extend(batch)
            pagination = page.get("pagination", {})
            cursor = pagination.get("nextCursor")
            log.info("    fetched %d events so far …", len(events))
            if not cursor or not batch:
                break
        return events

    # ── Management API: agent inventory ──────────────────────────────────────

    def fetch_all_agents(self) -> list[dict]:
        """
        Paginate GET /web/api/v2.1/agents — returns full agent/host inventory.
        Key fields in each record include: computerName, id, uuid, siteName,
        groupName, osName, osRevision, agentVersion, isActive, isDecommissioned,
        networkStatus, externalIp, lastActiveDate, encryptedApplications
        (BitLocker status), machineType, modelName, and serialNumber.
        """
        agents, cursor = [], None
        while True:
            params: dict = {"limit": PAGE_LIMIT, "sortBy": "computerName", "sortOrder": "asc"}
            if cursor:
                params["cursor"] = cursor
            r = self.session.get(self._url("/web/api/v2.1/agents"), params=params)
            r.raise_for_status()
            body = r.json()
            batch = body.get("data", [])
            agents.extend(batch)
            cursor = body.get("pagination", {}).get("nextCursor")
            log.info("    fetched %d agents so far …", len(agents))
            if not cursor or not batch:
                break
        return agents

    # ── Management API: application inventory ────────────────────────────────

    def fetch_all_applications(self) -> list[dict]:
        """
        Paginate GET /web/api/v2.1/application-management/applications.
        Each record contains: name, version, publisher, installedAt, and an
        'agents' list with computerName and agentId for each endpoint where
        the app is installed.  The method flattens agent sub-records so that
        each output row represents one (application, endpoint) pair — matching
        the layout of the console app-inventory export.
        """
        rows, cursor = [], None
        while True:
            params: dict = {"limit": PAGE_LIMIT}
            if cursor:
                params["cursor"] = cursor
            r = self.session.get(
                self._url("/web/api/v2.1/application-management/applications"),
                params=params,
            )
            r.raise_for_status()
            body = r.json()
            for app in body.get("data", []):
                base = {
                    "app_name":      app.get("name"),
                    "app_version":   app.get("version"),
                    "app_publisher": app.get("publisher"),
                    "app_type":      app.get("type"),
                    "risk_level":    app.get("riskLevel"),
                    "installed_at":  app.get("installedAt"),
                }
                agent_list = app.get("agents") or []
                if agent_list:
                    for agent in agent_list:
                        row = dict(base)
                        row["endpoint_name"] = agent.get("computerName")
                        row["agent_id"]      = agent.get("id")
                        row["site_name"]     = agent.get("siteName")
                        rows.append(row)
                else:
                    # App record with no agent detail — keep it anyway
                    rows.append(base)
            cursor = body.get("pagination", {}).get("nextCursor")
            log.info("    fetched %d app-inventory rows so far …", len(rows))
            if not cursor or not body.get("data"):
                break
        return rows

    # ── Management API: activity log ─────────────────────────────────────────

    def fetch_all_activities(self, from_date: str, to_date: str) -> list[dict]:
        """
        Paginate GET /web/api/v2.1/activities scoped to the assessment window.
        Captures all management-plane events: admin logins, policy changes,
        agent installs/uninstalls, threat actions, exclusion changes, etc.
        Results are sorted oldest-first so the CSV reads chronologically.
        Key fields: createdAt, activityType, primaryDescription,
        secondaryDescription, siteName, agentId, userId, data (nested).
        """
        activities, cursor = [], None
        while True:
            params: dict = {
                "limit":          PAGE_LIMIT,
                "createdAt__gte": from_date,
                "createdAt__lte": to_date,
                "sortBy":         "createdAt",
                "sortOrder":      "asc",
            }
            if cursor:
                params["cursor"] = cursor
            r = self.session.get(self._url("/web/api/v2.1/activities"), params=params)
            r.raise_for_status()
            body = r.json()
            batch = body.get("data", [])
            # Flatten the nested 'data' dict into top-level columns prefixed "event_"
            for record in batch:
                nested = record.pop("data", None) or {}
                for k, v in nested.items():
                    record[f"event_{k}"] = v
            activities.extend(batch)
            cursor = body.get("pagination", {}).get("nextCursor")
            log.info("    fetched %d activity records so far …", len(activities))
            if not cursor or not batch:
                break
        return activities


# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_for_query(client: S1Client, query_id: str) -> bool:
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        status = client.query_status(query_id)
        state    = status.get("responseState", "UNKNOWN")
        progress = status.get("progressStatus", 0)
        log.info("    status: %-12s  progress: %s%%", state, progress)
        if state == "FINISHED":
            return True
        if state in ("FAILED", "TIMED_OUT", "CANCELED"):
            log.error("    query ended with state: %s", state)
            return False
        time.sleep(POLL_INTERVAL)
    log.error("    timed out after %ds", POLL_TIMEOUT)
    return False


def events_to_csv(events: list[dict], path: Path) -> int:
    if not events:
        path.write_text("", encoding="utf-8")
        return 0
    all_keys: list[str] = []
    seen: set[str] = set()
    for ev in events:
        for k in ev.keys():
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
    return len(events)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Management API collectors ─────────────────────────────────────────────────

def collect_host_inventory(
    client: S1Client,
    output_dir: Path,
    coc_entries: list[dict],
) -> None:
    """Pull the full agent/host inventory and write HostInventory.csv."""
    csv_name    = "HostInventory.csv"
    out_path    = output_dir / csv_name
    entry: dict = {
        "file":        csv_name,
        "level":       "LVL5",
        "description": "Full endpoint inventory including BitLocker status, agent version, "
                        "health, network connectivity (GET /web/api/v2.1/agents)",
        "query_type":  "management_api",
        "from_date":   None,   # point-in-time snapshot
        "to_date":     None,
        "status":      None,
        "row_count":   None,
        "sha256":      None,
        "collected_at": None,
        "note":        None,
    }
    log.info("[LVL5] %s  (management API — agent inventory)", csv_name)
    try:
        agents    = client.fetch_all_agents()
        # Flatten networkInterfaces list to a readable string per agent
        for agent in agents:
            ifaces = agent.get("networkInterfaces") or []
            agent["networkInterfaces"] = "; ".join(
                f"{i.get('name','?')}:{i.get('inet','?')}" for i in ifaces
            ) if ifaces else ""
        row_count = events_to_csv(agents, out_path)
        entry["status"]       = "success"
        entry["row_count"]    = row_count
        entry["sha256"]       = sha256_file(out_path)
        entry["collected_at"] = iso_now()
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
    client: S1Client,
    output_dir: Path,
    coc_entries: list[dict],
) -> None:
    """Pull the full application inventory and write app-inventory.csv."""
    csv_name    = "app-inventory.csv"
    out_path    = output_dir / csv_name
    entry: dict = {
        "file":        csv_name,
        "level":       "LVL5",
        "description": "Full application inventory across all endpoints — one row per "
                        "(app, endpoint) pair (GET /web/api/v2.1/application-management/applications)",
        "query_type":  "management_api",
        "from_date":   None,
        "to_date":     None,
        "status":      None,
        "row_count":   None,
        "sha256":      None,
        "collected_at": None,
        "note":        None,
    }
    log.info("[LVL5] %s  (management API — application inventory)", csv_name)
    try:
        apps      = client.fetch_all_applications()
        row_count = events_to_csv(apps, out_path)
        entry["status"]       = "success"
        entry["row_count"]    = row_count
        entry["sha256"]       = sha256_file(out_path)
        entry["collected_at"] = iso_now()
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


def collect_mgmt_activity(
    client: S1Client,
    output_dir: Path,
    coc_entries: list[dict],
    from_date: str,
    to_date: str,
) -> None:
    """Pull the management activity log for the assessment window and write MgmtActivity.csv."""
    csv_name    = "MgmtActivity.csv"
    out_path    = output_dir / csv_name
    entry: dict = {
        "file":        csv_name,
        "level":       "LVL2",
        "description": "Management console activity log — admin logins, policy changes, "
                        "agent installs/uninstalls, threat actions, exclusion changes "
                        "(GET /web/api/v2.1/activities)",
        "query_type":  "management_api",
        "from_date":   from_date,
        "to_date":     to_date,
        "status":      None,
        "row_count":   None,
        "sha256":      None,
        "collected_at": None,
        "note":        None,
    }
    log.info("[LVL2] %s  (management API — activity log)", csv_name)
    try:
        activities = client.fetch_all_activities(from_date, to_date)
        row_count  = events_to_csv(activities, out_path)
        entry["status"]       = "success"
        entry["row_count"]    = row_count
        entry["sha256"]       = sha256_file(out_path)
        entry["collected_at"] = iso_now()
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

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    client = S1Client(args.url, args.token)

    run_start = iso_now()
    run_host  = platform.node()
    run_user  = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"

    coc_entries: list[dict] = []

    # ── Script self-hash ──────────────────────────────────────────────────────
    script_path = Path(__file__).resolve()
    script_hash = sha256_file(script_path) if script_path.exists() else "unavailable"

    log.info("=" * 70)
    log.info("S1 Cyber Risk Assessment Collection Script")
    log.info("  Range  : %s → %s", from_date, to_date)
    log.info("  Output : %s", output_dir.resolve())
    log.info("  Script : %s  [sha256: %s]", script_path.name, script_hash[:16] + "…")
    log.info("=" * 70)

    # ── Phase 1: Management API — host inventory ──────────────────────────────
    log.info("")
    log.info("── Phase 1: Host inventory (management API) ──────────────────────")
    collect_host_inventory(client, output_dir, coc_entries)

    # ── Phase 2: Management API — application inventory ──────────────────────
    log.info("")
    log.info("── Phase 2: Application inventory (management API) ───────────────")
    collect_app_inventory(client, output_dir, coc_entries)

    # ── Phase 3: Management API — activity log ────────────────────────────────
    log.info("")
    log.info("── Phase 3: Management activity log (management API) ─────────────")
    collect_mgmt_activity(client, output_dir, coc_entries, from_date, to_date)

    # ── Phase 4: Deep Visibility power queries ────────────────────────────────
    log.info("")
    log.info("── Phase 4: Deep Visibility queries (%d total) ────────────────────",
             sum(1 for _, _, _, q in QUERIES if q is not None))

    for csv_name, level, description, query in QUERIES:
        out_path = output_dir / csv_name

        entry: dict = {
            "file":        csv_name,
            "level":       level,
            "description": description,
            "query_type":  "deep_visibility_api" if query else "manual_console_export",
            "from_date":   from_date  if query else None,
            "to_date":     to_date    if query else None,
            "status":      None,
            "row_count":   None,
            "sha256":      None,
            "collected_at": None,
            "note":        None,
        }

        if query is None:
            # Manual export — document as placeholder in CoC
            if out_path.exists():
                entry["sha256"]       = sha256_file(out_path)
                entry["status"]       = "manually_provided"
                entry["collected_at"] = iso_now()
                # Count rows
                with out_path.open(encoding="utf-8", errors="replace") as f:
                    entry["row_count"] = max(0, sum(1 for _ in f) - 1)
                log.info("[%s] %s — manual export found, hashed (%d rows)",
                         level, csv_name, entry["row_count"])
            else:
                entry["status"] = "pending_manual_export"
                entry["note"]   = ("This file must be exported manually from the "
                                   "Microsoft Entra portal and placed in the output "
                                   "directory before analysis.")
                log.warning("[%s] %s — NOT FOUND (manual export required)", level, csv_name)
            coc_entries.append(entry)
            continue

        # ── Run via Deep Visibility API ───────────────────────────────────────
        log.info("[%s] %s", level, csv_name)
        try:
            query_id = client.init_query(query, from_date, to_date)
            log.info("    queryId: %s", query_id)
            entry["query_id"] = query_id

            ok = wait_for_query(client, query_id)
            if not ok:
                entry["status"] = "query_failed"
                entry["note"]   = "Query ended in a non-FINISHED state; no results collected."
                coc_entries.append(entry)
                continue

            events    = client.fetch_all_events(query_id)
            row_count = events_to_csv(events, out_path)

            entry["status"]       = "success"
            entry["row_count"]    = row_count
            entry["sha256"]       = sha256_file(out_path)
            entry["collected_at"] = iso_now()
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
        "title":       "Chain of Custody — SentinelOne Cyber Risk Assessment",
        "description": (
            "This manifest records every file produced or expected by the "
            "s1_query_runner.py script, including SHA-256 hashes for integrity "
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
            "s1_console_url":   args.url,
            "python_version":   sys.version,
            "platform":         platform.platform(),
        },
        "files": coc_entries,
    }

    # Hash the manifest itself after writing it so the hash is stable
    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    manifest_hash = sha256_file(coc_path)
    # Embed the manifest's own hash as a self-describing footer
    manifest["manifest_sha256"] = manifest_hash
    with coc_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    log.info("=" * 70)
    log.info("Chain of custody written → %s", coc_path)
    log.info("Manifest SHA-256: %s", manifest_hash)

    # ── Summary table ─────────────────────────────────────────────────────────
    api_mgmt_ok   = sum(1 for e in coc_entries if e["status"] == "success"
                        and e.get("query_type") == "management_api")
    dv_ok         = sum(1 for e in coc_entries if e["status"] == "success"
                        and e.get("query_type") == "deep_visibility_api")
    manual_ok     = sum(1 for e in coc_entries if e["status"] == "manually_provided")
    pending       = sum(1 for e in coc_entries if e["status"] == "pending_manual_export")
    failed        = sum(1 for e in coc_entries if e["status"] not in
                        ("success", "manually_provided", "pending_manual_export"))
    total_rows    = sum(e["row_count"] or 0 for e in coc_entries)

    log.info("")
    log.info("  Management API OK   : %d  (HostInventory, app-inventory, MgmtActivity)", api_mgmt_ok)
    log.info("  DV queries OK       : %d", dv_ok)
    log.info("  Manual exports found: %d", manual_ok)
    log.info("  Manual exports MISSING: %d  (Entra ID files — add before analysis)", pending)
    log.info("  Errors              : %d", failed)
    log.info("  Total data rows     : %d", total_rows)
    log.info("=" * 70)

    if pending:
        log.warning("The following files require manual console export:")
        for e in coc_entries:
            if e["status"] == "pending_manual_export":
                log.warning("  %-35s  [%s] %s", e["file"], e["level"], e["description"])


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelOne Deep Visibility bulk query runner with chain-of-custody manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Last 90 days (default)
  python s1_query_runner.py --url https://tenant.sentinelone.net --token TOKEN

  # Specific date range
  python s1_query_runner.py --url https://tenant.sentinelone.net --token TOKEN \\
      --from-date 2026-02-25T00:00:00Z --to-date 2026-05-25T23:59:59Z

  # Custom output directory and window
  python s1_query_runner.py --url https://tenant.sentinelone.net --token TOKEN \\
      --days 30 --output ./acme_assessment_2026-05
""",
    )
    parser.add_argument("--url",       required=True, help="SentinelOne console base URL")
    parser.add_argument("--token",     required=True, help="API token (ApiToken auth)")
    parser.add_argument("--days",      type=int, default=90,
                        help="Look-back window in days if --from-date/--to-date omitted (default: 90)")
    parser.add_argument("--from-date", dest="from_date", default=None,
                        help="Query start (ISO-8601 UTC, e.g. 2026-02-25T00:00:00Z)")
    parser.add_argument("--to-date",   dest="to_date",   default=None,
                        help="Query end   (ISO-8601 UTC, e.g. 2026-05-25T23:59:59Z)")
    parser.add_argument("--output",    default="./assessment_output",
                        help="Directory to write CSV files and CoC manifest (default: ./assessment_output)")

    args = parser.parse_args()

    if bool(args.from_date) ^ bool(args.to_date):
        parser.error("--from-date and --to-date must be provided together.")

    run(args)


if __name__ == "__main__":
    main()
