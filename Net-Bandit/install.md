# Installing and running net-bandit

These steps take a clean Windows machine to net-bandit running as SYSTEM at startup.
Run every command in an **elevated PowerShell** (Run as administrator).

> net-bandit is a proof of concept. Its Windows-native parts (event log subscriptions,
> Security log output, the AppContainer sandbox) need confirming on your machine. Step 6
> (`doctor`) checks each of them.

## 1. Prerequisites

- Windows 10 or 11, 64-bit.
- **Python 3.11 or newer, 64-bit, from python.org, installed "for all users"** (into
  Program Files). Avoid the Microsoft Store Python: it's itself an app package, and
  SYSTEM and the sandbox may not be able to run it.
- Recommended: **Sysmon** (Sysinternals), for richer process and network events.
- For step 6: **PsExec** (Sysinternals), to open a shell as SYSTEM.

## 2. Install the code where only administrators can change it

SYSTEM will run this code, so ordinary users must not be able to edit it.

```powershell
Expand-Archive net-bandit.zip "C:\Program Files"
cd "C:\Program Files\net-bandit"
py -m pip install .
```

If the `net-bandit` command isn't on your PATH afterwards, use `py -m net_bandit` wherever
these steps say `net-bandit`.

## 3. Smoke test offline (no API key needed)

```powershell
cd $env:TEMP
net-bandit replay "C:\Program Files\net-bandit\samples\windows_events.jsonl" --fake-llm --passes 3
```

You should see compiled entries being created and a cache hit rate of about 85% at the end.
`--fake-llm` uses a built-in stand-in for Claude. It's for testing only and isn't a detector.

## 4. Create the configuration and API key file

```powershell
mkdir C:\ProgramData\net-bandit
copy "C:\Program Files\net-bandit\config.example.toml" C:\ProgramData\net-bandit\config.toml
Set-Content -NoNewline C:\ProgramData\net-bandit\api.key "sk-ant-..."
icacls C:\ProgramData\net-bandit\api.key /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"
notepad C:\ProgramData\net-bandit\config.toml
```

In the config, set at least:

```toml
[general]
data_dir = "C:\\ProgramData\\net-bandit"

[llm]
api_key_file = "C:\\ProgramData\\net-bandit\\api.key"
daily_token_budget = 2000000      # your daily spending cap, in tokens
```

Keep these defaults unless you have a reason to change them:

| Setting | Default | Why |
| --- | --- | --- |
| `cache.approval_mode` | `"manual"` | New compiled checks start pending until you approve them |
| `isolation.mode` | `"auto"` | Checks run in an AppContainer, falling back to a restricted token |
| `isolation.allow_unisolated` | `false` | If no sandbox works, checks are disabled rather than run as SYSTEM |
| `eventlog.target` | `"security"` | Detections go to the Windows Security log |

The API key file is readable only by SYSTEM and Administrators. When net-bandit runs as
SYSTEM it also restricts the data folder the same way.

## 5. Turn on Windows auditing

```powershell
# Lets net-bandit write to the Security log (otherwise Windows drops its events silently)
auditpol /set /subcategory:"Application Generated" /success:enable

# Process creation events (Security 4688), including command lines
auditpol /set /subcategory:"Process Creation" /success:enable
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Optional, with Sysmon:

```powershell
sysmon64 -accepteula -i            # or -i <your-config.xml>
```

If you use Sysmon, set `tcp_table = false` under `[sources]` in the config to avoid
duplicate network events.

## 6. Check everything as SYSTEM

Open a SYSTEM shell, then run `doctor` in it:

```powershell
psexec -s -i powershell
net-bandit -c C:\ProgramData\net-bandit\config.toml doctor
```

What a healthy result looks like:

- The event channels, the TCP table, the process APIs and the signature checks show `ok`.
- `SeAuditPrivilege enabled`, `'Application Generated' auditing: on`, and the Security log
  test event is written.
- **Entry worker isolation mode: `appcontainer`**, and every worker read, write and network
  probe says **denied**.
  - If the mode is `restricted`, it still works, but the worker can reach the network.
    The data folder and key file are still locked down.
  - If no mode starts, cached checks will be disabled. Send the doctor output for a fix.

## 7. Try it in the foreground (same SYSTEM shell)

```powershell
net-bandit -c C:\ProgramData\net-bandit\config.toml run --fake-llm    # dry run, no tokens used
net-bandit -c C:\ProgramData\net-bandit\config.toml run               # live, using Claude
```

Stop it with Ctrl+C.

## 8. Run it at startup

```powershell
net-bandit -c C:\ProgramData\net-bandit\config.toml install-task --hidden
schtasks /Run /TN net-bandit
```

This registers a scheduled task named `net-bandit` that starts at boot as SYSTEM.
`--hidden` uses `pythonw.exe`, so no console window appears.

## 9. Day-to-day use (elevated shell)

```powershell
$c = "C:\ProgramData\net-bandit\config.toml"
net-bandit -c $c stats                 # hit rate, tokens used, tokens avoided
net-bandit -c $c entries               # compiled checks, hits, spot-check rates
net-bandit -c $c show 3                # read a check's code
net-bandit -c $c approve 3             # approve a pending check
net-bandit -c $c revoke 3              # remove a check; its class goes back to Claude

# Recent detections in the Security log
Get-WinEvent -FilterHashtable @{LogName='Security'; ProviderName='net-bandit'} -MaxEvents 20
```

Review and approve pending checks over the first day or two. Until you approve them, Claude
re-checks them five times as often, which costs tokens. Detections are also appended to
`C:\ProgramData\net-bandit\alerts.jsonl`.

### Security log event IDs

| ID | Meaning |
| --- | --- |
| 7111 | Malicious observation |
| 7110 | Suspicious observation |
| 7102 | High-novelty observation (benign but unlike anything seen before) |
| 7122 | A compiled check failed its integrity check (possible tampering) |
| 7132 | Isolated entry worker unavailable (cached checks not running) |
| 7120 / 7121 | Check revoked / check disagreed with Claude |
| 7123 | Claude produced a check that failed validation |
| 7130 / 7131 | Daily token budget reached / Claude call failed |
| 7100 / 7101 | Agent started / new check installed |

To collect these centrally, forward Security events from provider `net-bandit` with
Windows Event Forwarding or your SIEM's Windows agent. IDs 7111, 7110, 7122 and 7132 are
the ones to alert on.

## Updating

```powershell
schtasks /End /TN net-bandit
# replace C:\Program Files\net-bandit with the new version, then:
cd "C:\Program Files\net-bandit"
py -m pip install .
schtasks /Run /TN net-bandit
```

Your configuration, compiled checks and history in `C:\ProgramData\net-bandit` are kept.

## Removing

```powershell
schtasks /End /TN net-bandit
schtasks /Delete /TN net-bandit /F
py -m pip uninstall net-bandit
Remove-Item -Recurse "C:\Program Files\net-bandit", C:\ProgramData\net-bandit
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\net-bandit" /f   # optional
```

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| No net-bandit events in the Security log | "Application Generated" auditing off, or not running as SYSTEM | Step 5; run via the scheduled task or `psexec -s` |
| `SeAuditPrivilege` not held | Running as an administrator rather than SYSTEM | Use `psexec -s`, or the scheduled task |
| Process events have no command lines | 4688 command-line logging off | Step 5 registry setting, or install Sysmon |
| Isolation mode `restricted` instead of `appcontainer` | AppContainer couldn't be created or granted access to Python | Works, but without network blocking; send the doctor output |
| Event 7132 and every decision "unknown" | No sandbox could start | Run `doctor` and send the output |
| Costs higher than expected | Many pending checks, or a very varied machine | Approve or revoke pending checks; lower `daily_token_budget` |
