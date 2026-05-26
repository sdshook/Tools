# MS Entra Identity Posture and Use Security assessment
# (c) 2026, Shane D. Shook, PhD

A single-file, read-only security assessment for Microsoft Entra ID (Azure AD)
using the Microsoft Graph API and device code authentication. No app registration
or stored secrets required.

---
# CLI Options

python entra_assessment.py                              # 30-day window, all modules
python entra_assessment.py --days 90                    # 90-day window
python entra_assessment.py --days 60 --json             # with JSON report (default filename)
python entra_assessment.py --json my_report.json        # custom JSON path
python entra_assessment.py --tenant contoso.com         # specify tenant (recommended)
python entra_assessment.py --tenant <guid>              # or use tenant GUID directly
python entra_assessment.py --skip-defender              # skip if no Defender license
python entra_assessment.py --skip-signin                # faster, less visibility
python entra_assessment.py --init                       # generate config.yaml template

# Typical Run

python entra_assessment.py --days 90 --json my_report.json 

## Quick Start

```bash
# Dependencies install automatically on first run, or manually:
pip install azure-identity requests pyyaml

# Run with 30-day analysis window
python entra_assessment.py

# 90-day window and save JSON report
python entra_assessment.py --days 90 --json report.json

# Specify output directory for the case folder
python entra_assessment.py --output-dir C:\Cases

# Skip Defender module (if tenant has no Defender licensing)
python entra_assessment.py --skip-defender

# Skip sign-in log analysis (faster run, less visibility)
python entra_assessment.py --skip-signin
```

When the tool runs, a URL and one-time code are displayed. Open
https://microsoft.com/devicelogin in any browser, enter the code,
sign in, and the assessment starts automatically.

Module 14 (Mailbox Forwarding) uses the Exchange Online PowerShell module
and requires a second device code login mid-run. This is expected behavior.
See the Exchange Online section below for prerequisites.

---

## Authentication Flow

The assessment involves two separate authentication sessions:

**Session 1 — Microsoft Graph API (automatic at startup)**
Uses the Microsoft Graph Command Line Tools app (client ID
14d82eec-204b-4c2f-b7e8-296a70dab67e) with device code flow.
This is a Microsoft-owned public client. No custom app registration,
no client secret, no credentials stored anywhere. Covers modules 1-13
and 15-16.

**Session 2 — Exchange Online PowerShell (Module 14 only)**
When module 14 runs, a second device code prompt appears for Exchange
Online. This uses the ExchangeOnlineManagement PowerShell module
(Connect-ExchangeOnline) which has its own authentication flow
independent of the Graph API. The user must authenticate again at
this point. After authentication module 14 completes and the
assessment continues automatically with module 15.

All tokens are held in memory only for the duration of each session.

---

## Account Requirements

The assessment account requires permissions across three systems:
Microsoft Entra ID (via Graph API), the Microsoft Graph Command Line
Tools app (scope consent), and Exchange Online (role group membership).
Configure all three once per tenant using setup_assessment_account.ps1
and the manual Exchange steps below.

### Entra ID Roles

Assign all three in Entra admin center -> Users -> [account] -> Assigned roles.

| Role | Modules | Why Needed |
|---|---|---|
| Global Reader | 01, 04, 13 | Policy.Read.All for CA policies, Security Defaults, PIM |
| Security Reader | 08, 11 | IdentityRiskyUser.Read.All, SecurityAlert.Read.All |
| Reports Reader | 07, 09 | AuditLog.Read.All for sign-in logs, MFA registration report |

### Microsoft Graph Command Line Tools App — Admin Consented Scopes

These four scopes require one-time admin consent by a Global Administrator
in Entra admin center -> Enterprise applications -> Microsoft Graph Command
Line Tools -> Permissions -> Grant admin consent for your org.

The setup_assessment_account.ps1 script handles this automatically.

| Scope | Modules | Why Needed |
|---|---|---|
| Policy.Read.All | 01, 04, 13 | Security Defaults, CA policies, PIM activation policies |
| RoleEligibilitySchedule.Read.Directory | 13 | PIM eligible role assignments |
| RoleAssignmentSchedule.Read.Directory | 13 | PIM active role schedules |
| RoleManagementPolicy.Read.Directory | 13 | PIM activation policy settings |

Note: Delegated scope consent is bounded by the user's Entra roles.
Consenting Policy.Read.All does not grant CA policy access to accounts
that lack Global Reader or higher.

### Graph API Scopes Requested at Authentication

The tool requests these explicit read-only scopes at sign-in. It does
not use .default, which would pick up all pre-consented scopes on the
app including any write scopes granted to other users.

```
Directory.Read.All                     User.Read.All
Group.Read.All                         Organization.Read.All
Application.Read.All                   Device.Read.All
RoleManagement.Read.Directory          PrivilegedAccess.Read.AzureAD
AuditLog.Read.All                      Reports.Read.All
Policy.Read.All                        IdentityRiskyUser.Read.All
SecurityAlert.Read.All                 UserAuthenticationMethod.Read.All
```

### Exchange Online — Module 14 Prerequisites

Module 14 uses the ExchangeOnlineManagement PowerShell module to check
mailbox forwarding and inbox rules across all mailboxes. The Graph API
delegated permission MailboxSettings.Read only reads the calling user's
own mailbox regardless of scope consent — it cannot enumerate other
users' mailboxes. Exchange Online PowerShell uses a separate RBAC
system that correctly evaluates the assessment account's Exchange role.

**Step 1 — Install the PowerShell module (one-time, on the assessment machine):**

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

**Step 2 — Create the Exchange role group (one-time per tenant, requires
Exchange Administrator or Global Administrator):**

In Exchange admin center (admin.exchange.microsoft.com):
Roles -> Admin roles -> New role group

| Setting | Value |
|---|---|
| Name | Entra Assessment - Read Only |
| Write Scope | Default |
| Roles | View-Only Recipients, View-Only Configuration, View-Only Audit Logs |
| Members | [assessment account UPN] |

Allow 15-30 minutes for Exchange role group membership to propagate
before running module 14 for the first time.

The setup_assessment_account.ps1 script does NOT reliably create this
role group due to ExchangeOnlineManagement module version inconsistencies.
Create it manually as described above.

**What View-Only Recipients provides:**
Get-EXOMailbox across all mailboxes (server-side SMTP forwarding check)
and Get-InboxRule per mailbox (forwarding, redirect, delete, and move rules).

**What View-Only Audit Logs provides:**
Search-UnifiedAuditLog for Exchange-level events not available via Graph API.

---

## What Is Assessed (16 Modules)

| Module | Key Checks |
|---|---|
| 01 Tenant | Security Defaults status, tenant configuration |
| 02 Privileged Roles | GA count, guest/SP admins, permanent vs PIM assignments |
| 03 User Hygiene | Stale accounts, guest proportion, password-never-expires |
| 04 Conditional Access | MFA coverage gaps, legacy auth blocking, report-only policies |
| 05 Apps, AI Agents & Secrets | Dangerous permissions, AI agent SPs, expired/long-lived secrets |
| 06 Device Compliance | Unmanaged/non-compliant devices, stale registrations |
| 07 Sign-in Logs | Failure rates, legacy auth, spray detection, token replay, impossible travel |
| 08 Identity Protection | Risk detections, high/medium risk users (requires Entra P2) |
| 09 MFA Registration | Adoption by account type, weak methods, FIDO2/passwordless coverage |
| 10 App Role Analysis | Dangerous permission combos, over-privileged SPs, consent audit history |
| 11 Defender Alerts | Unresolved alerts, credential TTPs, threat actor attribution |
| 12 O365 / Exchange / BEC | Mail OAuth grants, consent events, admin password resets, legacy auth |
| 13 PIM | Eligible assignments, no-expiry assignments, weak activation policies |
| 14 Mailbox Forwarding | Server-side SMTP forwarding, inbox rules (forward/delete/hide) via Exchange PS |
| 15 Behavioral Analysis | Off-hours auth, high IP diversity, SharePoint multi-location access |
| 16 DNS and User Hygiene | SPF/DKIM/DMARC per domain, inactive users, account classification |

---

## What Cannot Be Retrieved Without Additional Licensing or Permissions

| Gap | Reason | Workaround |
|---|---|---|
| Risky users rollup | Requires Entra ID P2 license | Entra portal: Protection -> Identity Protection -> Risky users |
| Defender unified alerts | Requires Defender licensing | Microsoft Defender portal: security.microsoft.com -> Alerts |
| Mailbox rules (if Exchange role not assigned) | Requires View-Only Recipients Exchange role | Create Exchange role group as described above |
| CA policies, PIM, Security Defaults | Requires Global Reader + admin-consented scopes | Run setup_assessment_account.ps1 as Global Administrator |

---

## Forensic Evidence Preservation

Every API and PowerShell response is written to disk before analysis.
Each run creates a timestamped case directory:

```
entra_assessment_YYYYMMDD_HHMMSS/
    CUSTODY.json       Chain of custody header (collector UPN, tenant, tool version, timestamps)
    MANIFEST.json      SHA-256 hash of every evidence file, updated after every call
    raw/               Raw API and PowerShell responses, one file per call
    report/            Analyst findings and final report (separate from raw evidence)
```

Raw evidence files include both Graph API responses (JSON per endpoint)
and the Exchange Online PowerShell output from module 14. All are
individually hashed. The final report is also hashed and recorded in
MANIFEST.json, making post-collection tampering detectable.

---

## Setup Script

setup_assessment_account.ps1 configures Entra ID permissions for the
assessment account. Run once with a Global Administrator account:

```powershell
powershell -ExecutionPolicy Bypass -File setup_assessment_account.ps1 -AssessmentUPN assessor@contoso.com
```

The script:
- Assigns Global Reader, Security Reader, and Reports Reader roles
- Grants admin consent for the four additional Graph scopes on the
  Microsoft Graph Command Line Tools app
- Uses raw REST device code flow (not the Microsoft.Graph PS module)
  to avoid known token re-authentication bugs in that module

The script does NOT create the Exchange Online role group due to
ExchangeOnlineManagement module version inconsistencies. Create the
Exchange role group manually as described in the Exchange Online section.

---

## Diagnostic Tool

entra_diagnostic.py tests all Graph API endpoints used by the assessment
and reports exactly what is accessible with the current account.

```bash
python entra_diagnostic.py --json diag.json
```

Run this first on a new tenant to confirm permissions are correctly
configured before running the full assessment. The output shows which
endpoints return data, which return 403, and whether the account has
the correct scopes in its token.

---

## Generating a Report

The assessment produces a JSON evidence file (via --json) containing
all findings, metrics, and chain of custody information. To generate
a formatted Word document report from this JSON output, use the
included REPORT_PROMPT.md.

**How to use the report prompt:**

1. Open any AI interface that supports file uploads (Claude, GPT-4, etc.)
2. Attach both the JSON output file and REPORT_PROMPT.md
3. The prompt instructs the AI to ask five questions before generating
   the report:
   - Industry sector of the assessed organization
   - Specific regulatory classification within that sector
   - US states where the organization has offices or is registered
   - Countries with permanent offices or registered legal entities
   - Countries with clients, investors, or counterparties whose data is processed
4. Answer each question when prompted
5. The AI generates a professionally formatted Word document including:
   - Cover page with full tenant details and chain of custody reference
   - Executive summary with colored security posture grade boxes
   - Full regulatory and industry context for the confirmed jurisdiction
   - Section I: Exigent risks requiring immediate action
   - Section II: Hygiene issues with remediation steps
   - Section III: Architectural findings
   - Section IV: Configuration and use history anomalies
   - Section V: Priority remediation matrix with regulatory references
   - Appendix: Assessment methodology and limitations

The prompt enforces: client-specific terms in italics, no truncation of
finding details, correct classification of applicable regulations vs
inapplicable ones, and current regulatory status verified via web search
before the regulatory context section is written.
