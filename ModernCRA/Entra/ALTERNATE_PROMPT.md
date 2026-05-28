# Entra ID Security Assessment Report Generation Prompt (Alternate)
# (c) 2026, Shane D. Shook, PhD

Use this prompt when attaching a JSON output file from entra_assessment.py
to generate a professionally formatted security assessment report.

---

## CORE PRINCIPLES (apply throughout — do not restate)

1. **Evidence-based** — Every statement traces to data in the JSON file
2. **No fabrication** — Do not invent findings or infer beyond the data
3. **No truncation** — Reproduce all lists, GUIDs, and identifiers in full
4. **Regulatory currency** — Verify all cited regulations are current before use
5. **Executive orientation** — Write for business leaders, not technicians

---

## INTAKE QUESTIONS

Before generating the report, collect five pieces of information. Ask each
question individually and wait for my response before proceeding to the next.

**Q1: Industry Sector**
What is the primary industry sector? (Financial Services, Healthcare,
Critical Infrastructure, Defense Industrial Base, Legal/Professional
Services, Technology/SaaS, Retail, Government, Education, Other)

**Q2: Regulatory Classification**
What is the specific regulatory classification within that sector?
(e.g., SEC-registered RIA, HIPAA covered entity, state-registered only)

**Q3: US State Presence**
In which US states does the organization have offices or registration?
Which states have significant client/employee populations?

**Q4: International Offices**
In which countries outside the US does the organization have permanent
offices or registered legal entities?

**Q5: International Data Subjects**
In which countries does the organization have clients, customers, or
counterparties whose personal data is processed?

After receiving all answers, perform the validation steps below before
generating the report.

---

## PRE-REPORT VALIDATION (required before generating)

Three areas must be validated using both the assessment evidence and
public internet searches. Present findings to the assessor for confirmation
before proceeding.

### Validation 1: Business Registration and Entity Verification

**From the evidence:**
- Extract primary domain and all verified domains from Module 01
- Identify organization name and tenant details from JSON metadata
- Note any subsidiary or affiliated entity references in app names,
  service principals, or group names

**From public searches:**
- Search SEC EDGAR for RIA registrations (Form ADV), broker-dealer
  registrations, and investment company filings
- Search state secretary of state databases for business registrations
  in states identified in Q3
- Search international company registries for entities in countries
  identified in Q4 (Companies House UK, Handelsregister DE, etc.)
- Search FINRA BrokerCheck if financial services
- Search NPI registry if healthcare

**Present to assessor:**
- Entities found in public records not mentioned by assessor
- Registration numbers and authorization details discovered
- Any discrepancies between assessor answers and public records
- Request confirmation or correction before proceeding

### Validation 2: User and Access Locations

**From the evidence:**
- Extract sign-in locations from Module 07 and Module 15 data
- Map countries where authentication activity occurred
- Identify the geographic distribution of successful sign-ins
- Note any locations flagged as anomalous by the assessment

**From public searches:**
- Verify organization's stated office locations against public records
- Cross-reference sign-in countries against stated business presence

**Present to assessor:**
- Countries with sign-in activity not identified as office locations
- Distinguish: (a) employee travel, (b) unconfirmed office locations,
  (c) potential unauthorized access requiring investigation
- Request confirmation of which locations represent legitimate presence
  vs. items requiring follow-up

**Important distinction:** Employee travel to a country does NOT create
data protection obligations in that country. Foreign privacy laws apply
only when processing personal data of residents of that country or
maintaining legal establishment there.

### Validation 3: Regulatory Applicability

**From the evidence:**
- Infer licensing tier from presence of P2-only features (risk-based CA,
  PIM, Identity Protection)
- Identify regulated data indicators (healthcare apps, financial apps,
  PII handling patterns)
- Note compliance-related app names or service principals

**From public searches:**
- Verify current enforcement status of each applicable regulation
- Check for amendments, new rules, or guidance issued since knowledge cutoff
- Confirm effective dates and threshold requirements
- Identify any newly enacted regulations in confirmed jurisdictions

**Present to assessor:**
- Confirmed applicable regulations with current status
- Any regulations where applicability is uncertain pending confirmation
- Proposed or pending rules that may apply (labeled as such)
- Request confirmation before citing any regulation as mandatory

After the assessor confirms or corrects all three validation areas,
proceed to report generation.

---

## REPORT STRUCTURE

The report contains 8 sections. Generate them in order.

---

### Section 1: Cover Page (1 page)

**Layout:**
- Organization name and logo placeholder (centered, top third)
- Report title: "Microsoft Entra ID Security Posture Assessment"
- Date of assessment
- Classification: "Company Confidential"

**Chain of Custody Box:**
| Field | Value |
|-------|-------|
| Tenant ID | From JSON |
| Primary Domain | From JSON |
| Assessment Tool | Entra ID Security Posture Assessment v2.0 |
| Tool Author | Shane Shook |
| Records Collected | From JSON metadata |
| API Calls | From JSON metadata |
| Analysis Window | From JSON metadata |
| Evidence Hash | SHA-256 from JSON |

**Controlling Entity Box:**
| Field | Value |
|-------|-------|
| Organization | From JSON + assessor confirmation |
| Regulatory Status | From Q2 answer |
| Jurisdiction | From Q3/Q4 answers |
| Associated Entities | From assessor confirmation |

---

### Section 2: Executive Summary (2-4 pages)

The executive summary is designed for business executives and board members.
It explains the organization's reliance on technology and the risks evident
in the assessment data.

**Opening Narrative (2 paragraphs):**

Paragraph 1: Introduce what was assessed and why it matters. Explain that
Microsoft Entra ID controls who can sign in, what applications and data
they can access, and what permissions are granted to users, administrators,
and third-party services. State that auditing it reveals credential misuse
and permission abuse that could threaten the organization.

Paragraph 2: Describe the assessment scope — 17-module read-only tool,
number of records, analysis window, two authentication sessions (Graph API
and Exchange Online), and confirmation that no changes were made to the
tenant.

**Security Posture Overview:**

Present three colored grade boxes side by side:

| Box | Color Logic | Content |
|-----|-------------|---------|
| EXIGENT RISK | RED if critical findings exist | Count + primary risk statement |
| HYGIENE POSTURE | YELLOW if medium findings, else GREEN | Count + characterization |
| ANOMALIES | RED/YELLOW/GREEN based on severity | Investigation status |

Color values: RED=#C00000, YELLOW=#FFC000, GREEN=#375623

**Five Questions Framework:**

Introduce with: "Separating the variety and complexity of technologies and
services, the following questions interpret your cybersecurity posture and
defensive readiness."

For each question, provide:
- The question (italicized)
- Rating (RED/YELLOW/GREEN)
- Evidence from the assessment with module citations
- Direct answer to the question
- Remediation path: existing licenses | architecture change | investment required

| # | Question |
|---|----------|
| 1 | If a password were compromised, what would be the damage of its misuse? |
| 2 | If ransomware breaks out, can we limit the spread and value of stolen data? |
| 3 | If a device is stolen, can we limit access and remotely wipe it? |
| 4 | If a vendor, partner, or application is compromised, what is exposed? |
| 5 | If someone impersonates an executive via email, what is the financial exposure? |

**Rating Criteria (incorporating device platform analysis):**

| Scenario | RED | YELLOW | GREEN |
|----------|-----|--------|-------|
| Credential | MFA <50%, no CA for privileged, GAs without phishing-resistant MFA, OR MFA methods don't match dominant platform (WHfB only but mobile-dominant) | MFA 50-90%, weak methods >50%, CA exclusions | MFA >90% strong methods matching dominant platform, CA covers privileged, legacy blocked |
| Ransomware | No device compliance CA, MDM <30%, DLP <25%, OR mobile-dominant with no MAM | Compliance <50%, DLP 25-75%, MDM 30-70% | Compliance >80%, DLP >75% covering dominant access method, MDM/MAM >70% |
| Device | MDM <30%, no CA for managed devices, unmanaged >30%, OR dominant platform unprotected (mobile-dominant with no MAM) | MDM 30-70%, partial MAM, platform mismatch | MDM/MAM >70% on dominant platform, CA blocks unmanaged, remote wipe available |
| Supply Chain | >5 apps with sensitive permissions, guests >10% unreviewed | 2-5 sensitive apps, guests 5-10%, no PIM | <2 sensitive apps documented, PIM enabled |
| BEC | External forwarding, suspicious rules, no DMARC | Internal forwarding, DMARC p=none | No forwarding, DMARC p=quarantine+ |

**Platform-specific considerations:**
- If `dominant_platform` = "mobile": MAM is required, MDM alone insufficient
- If `dominant_access_method` = "native_app": Browser-based controls inadequate
- If `unmanaged_pct` > 50%: Device compliance CA is ineffective without MAM

**Defense Posture by Technology Domain:**

The assessment now captures device platform and access method distribution
directly from sign-in logs (Module 07). Use these metrics to determine the
organization's actual technology reliance:

| Metric | JSON Key | Meaning |
|--------|----------|---------|
| Dominant Platform | `dominant_platform` | "mobile", "euc", or "mixed" |
| Mobile % | `mobile_pct` | Percentage of sign-ins from iOS/Android |
| EUC % | `euc_pct` | Percentage from Windows/MacOS/Linux |
| Dominant Access | `dominant_access_method` | "native_app", "browser", or "mixed" |
| Native App % | `native_app_pct` | Outlook, Teams, OneDrive apps |
| Browser % | `browser_pct` | Web browser access |
| Unmanaged % | `unmanaged_pct` | Sign-ins from unmanaged devices |
| Platform Distribution | `platform_distribution` | Breakdown by OS (iOS, Windows, etc.) |

**Security posture must align with actual access patterns:**

| If Dominant Platform Is | Required Controls | Gap Indicator |
|-------------------------|-------------------|---------------|
| **Mobile** (>50% iOS/Android) | MAM policies, mobile-aware CA | MDM <30% or unmanaged >50% |
| **EUC** (>50% Windows/MacOS) | Device compliance CA, endpoint protection | Compliance not required by CA |
| **Mixed** | Both mobile and desktop controls | Either gap applies |

| If Dominant Access Is | Required Controls | Gap Indicator |
|-----------------------|-------------------|---------------|
| **Native App** (>50%) | MAM app protection, Intune DLP | Browser-only DLP deployed |
| **Browser** (>50%) | CASB, browser-based DLP, session controls | No session restrictions |

**Critical finding:** If `dominant_platform` = "mobile" but MAM is absent
and `unmanaged_pct` > 50%, the security architecture does not match
actual usage. This is a HIGH severity architectural gap.

**MFA method relevance:** Windows Hello for Business (WHfB) provides
phishing-resistant MFA only on Windows devices. If `dominant_platform` =
"mobile" and WHfB is the primary MFA method, effective MFA coverage on
the dominant platform is zero. Cross-reference Module 17 MFA methods
against `dominant_platform` to identify this gap.

**Associated Entities:**

List associated companies, subsidiaries, or affiliated entities confirmed
by the assessor. Explain how data protections and protected communications
relate to those entities based on the tenant configuration.

**Regulatory Implications:**

Based on Q2 answers, state which regulations apply and summarize compliance
status. Reference the findings tables for specific gaps.

---

### Section 3: Priority Remediations Table (1-2 pages)

A single table summarizing the highest-priority actions from the assessment.

| Priority | Finding | Severity | Regulatory Impact | Remediation Path | Effort |
|----------|---------|----------|-------------------|------------------|--------|
| 1 | [Title] | CRITICAL | [Regulations] | [Action] | [Low/Med/High] |
| 2 | ... | ... | ... | ... | ... |

Include the top 10-15 items. Order by: CRITICAL first, then HIGH with
regulatory impact, then HIGH without. Each row should be actionable.

---

### Section 4: Findings by Severity (variable length)

Present findings in five tables, one per severity level. Each table uses
the same format.

**Table format:**

| # | Finding | Category | Evidence | Regulatory/Standards |
|---|---------|----------|----------|----------------------|
| 1 | [Title] | [Category from JSON] | [Bullet list of evidence items] | [Applicable citations] |

**Severity tables in order:**
1. CRITICAL (red header) — Immediate action required
2. HIGH (orange header) — Address within 30 days
3. MEDIUM (yellow header) — Address within 90 days
4. LOW (blue header) — Address as resources permit
5. INFORMATIONAL (gray header) — No action required, awareness only

**Evidence requirements:**
- All items from the JSON finding reproduced in full
- User names, emails, app names in italics
- GUIDs and identifiers not truncated

**Regulatory/Standards column:**
- Cite applicable regulations from Q2 confirmation
- Include ISO 27001:2022 control numbers where applicable
- Include NIST CSF or SP 800-53 references where applicable

---

### Section 5: Remediation Summary (2-3 pages)

This section translates findings into actionable remediation with clear
cost/effort implications.

**5.1 Capabilities Available with Current Licensing**

Based on observed P1/P2/E3/E5 features in the tenant, list security
capabilities that are licensed but not fully deployed:

| Capability | Current State | Gap | Remediation |
|------------|---------------|-----|-------------|
| MFA | 78% enrolled | 22% without | Enrollment campaign |
| Device Compliance | CA exists, not enforced | Policy disabled | Enable CA policy |
| ... | ... | ... | ... |

**5.2 Gaps Requiring Additional Licensing**

Identify security gaps that cannot be addressed with current licensing:

| Gap | Required License | Capability Enabled | Est. Cost Impact |
|-----|------------------|-------------------|------------------|
| Risk-based CA | Azure AD P2 | Sign-in risk policies | Per-user/month |
| PIM | Azure AD P2 | Just-in-time privileged access | Included with P2 |
| Advanced DLP | M365 E5 Compliance | SharePoint/Teams DLP | Per-user/month |

**5.3 Architectural Changes Required**

Identify gaps that require process or architecture changes beyond licensing:

| Gap | Current Architecture | Required Change | Implementation Effort |
|-----|---------------------|-----------------|----------------------|
| MDM enrollment | 27% enrolled | Device onboarding campaign | Medium (3-6 months) |
| Guest access review | No reviews | Implement access review process | Low (configuration) |

**5.4 Services Recommendations**

Where internal capabilities are insufficient, recommend service engagements:

- Incident response retainer for BEC investigation
- Security architecture review for Zero Trust implementation
- Managed detection and response for 24/7 monitoring

**Regulatory Alignment:**

Map each remediation to the regulatory obligations confirmed in Q2. State
which remediations are required for compliance vs. recommended best practice.

---

### Section 6: Appendix A — Regulatory and Industry Standards

List all regulations and standards applicable to the organization based on
Q2/Q3/Q4/Q5 answers. For each, provide:

| Regulation/Standard | Applicability | Key Requirements | Status |
|---------------------|---------------|------------------|--------|
| SEC Reg S-P | RIA | Safeguards Rule, privacy notices | Mandatory |
| GDPR | EU data subjects | Lawful basis, data protection | Mandatory |
| ISO 27001:2022 | Voluntary adoption | ISMS controls | Voluntary |

Include only regulations confirmed as applicable. Do not include a generic
list of all possible regulations.

---

### Section 7: Appendix B — Risk Scoring Methodology

Explain how findings are categorized by severity:

| Severity | Criteria | Response Timeline |
|----------|----------|-------------------|
| CRITICAL | Active compromise indicators, credential theft capability, data exfiltration in progress | Immediate (24-48 hours) |
| HIGH | Significant control gaps enabling compromise, regulatory violations | 30 days |
| MEDIUM | Hygiene issues increasing attack surface, best practice deviations | 90 days |
| LOW | Minor configuration issues, optimization opportunities | As resources permit |
| INFORMATIONAL | No action required, baseline documentation | None |

**Module-to-Finding Mapping:**

| Module | Data Collected | Finding Types |
|--------|----------------|---------------|
| 01 | Tenant configuration | Baseline |
| 02 | Privileged roles | Role assignment findings |
| 03 | User hygiene | Stale accounts, guests |
| 04 | Conditional Access | Policy gaps |
| 05 | Applications | OAuth, permissions |
| 06 | Devices | Compliance, MDM |
| 07 | Sign-in logs | Authentication patterns |
| 08 | Risky users | Identity Protection |
| 09 | MFA registration | Registration status |
| 10 | App roles/audit | Permission grants |
| 11 | Defender alerts | Threat detection |
| 12 | Exchange/O365 | BEC indicators |
| 13 | PIM | Privileged access |
| 14 | Mailbox forwarding | Email exfiltration |
| 15 | Behavioral analysis | Anomaly detection |
| 16 | DNS/hygiene | Email security |
| 17 | MFA reconciliation | Credential inventory |

---

### Section 8: Appendix C — References

List all references cited in the report. Generate this list dynamically
from citations used in Sections 4 and 5.

**Assessment Tool:**
- Entra ID Security Posture Assessment v2.0
- https://github.com/sdshook/Tools/tree/main/ModernCRA/Entra
- Author: Shane Shook, May 2026

**Microsoft Documentation:**
List all learn.microsoft.com URLs cited in remediation recommendations.
Do not truncate URLs.

**Regulations and Standards:**
List all regulatory documents, NIST publications, and ISO standards cited.
Include document numbers and publication dates.

---

## FORMATTING REQUIREMENTS

**Typography:**
- Font: Arial throughout
- Page size: US Letter, 1-inch margins
- Footer: Organization | Report Title | Date | Confidential | Page #
- Headings: Dark blue (#1F3864)

**Italics:**
All client-specific terms in italics: names, emails, app names, domains,
device names, role names, identifiers.

**Tables:**
- Header row with background color matching severity
- Borders: thin gray lines
- No merged cells that break readability

**Colors:**
- CRITICAL: #C00000 (red)
- HIGH: #ED7D31 (orange)
- MEDIUM: #FFC000 (yellow)
- LOW: #4472C4 (blue)
- INFO: #808080 (gray)

---

## MFA DATA INTERPRETATION

When both Module 09 and Module 17 data are present:

| Data Point | Authoritative Source |
|------------|---------------------|
| MFA registered (ground truth) | Module 17 |
| What methods are registered | Module 17 |
| isMfaCapable, defaultMfaMethod | Module 09 |
| SSPR registration/capability | Module 09 |
| Passwordless capable | Module 09 |

If Module 17 shows different counts than Module 09, use Module 17 for all
MFA coverage statements. Registry discrepancies indicate migration risk.

---

## CROSS-SECTION CONSISTENCY REQUIREMENTS

Sections 2 (Executive Summary), 4 (Findings), and 5 (Remediation) must
accurately reflect each other. The following relationships are mandatory:

**Executive Summary → Section 4:**
- Every severity count in the Executive Summary grade boxes must match
  the actual count of findings in Section 4 tables
- Every finding referenced in the Five Questions framework must appear
  in Section 4 with matching severity and evidence
- The "primary risk statement" in each grade box must correspond to
  the highest-severity finding in Section 4

**Executive Summary → Section 5:**
- Every remediation path stated in the Five Questions framework
  (existing licenses / architecture change / investment required) must
  have a corresponding entry in Section 5
- The licensing gaps mentioned in Section 5.2 must be reflected in
  Executive Summary statements about what "requires additional investment"
- The architectural gaps in Section 5.3 must match Executive Summary
  statements about "modified architecture"

**Section 4 → Section 5:**
- Every CRITICAL and HIGH finding in Section 4 must have a corresponding
  remediation action in Section 5
- The regulatory citations in Section 4 must match the regulatory
  alignment statements in Section 5.4
- No remediation in Section 5 should reference a finding not present
  in Section 4

**Section 5 → Executive Summary:**
- The Priority Remediations table (Section 3) must be a subset of
  Section 5 remediations, ordered by severity and regulatory impact
- Licensing status statements in Executive Summary must match Section 5.1
  and 5.2 determinations

---

## RECURSIVE QUALITY CONTROL (perform before delivery)

After generating the complete report, perform the following quality
control checks in sequence. If any check fails, correct the issue and
re-verify all checks from the beginning.

### Pass 1: Cross-Section Accuracy

Review the relationships defined above and verify:

☐ Executive Summary severity counts match Section 4 finding counts exactly
☐ Every finding cited in Five Questions appears in Section 4
☐ Every remediation path in Five Questions has entry in Section 5
☐ Every CRITICAL/HIGH finding in Section 4 has remediation in Section 5
☐ Priority Remediations table (Section 3) entries exist in Section 5
☐ No orphaned references (findings without remediation, remediations
  without findings, Executive Summary claims without supporting detail)

### Pass 2: Evidence Integrity

☐ All findings trace to JSON data — none invented
☐ All evidence lists complete — none truncated
☐ All GUIDs, tenant IDs, identifiers shown in full
☐ Module 17 MFA counts used when present (authoritative over Module 09)
☐ Regulatory citations verified current through public search
☐ Appendix C references match actual citations in Sections 4-5

### Pass 3: Language and Style

☐ US English spelling throughout (e.g., "organization" not "organisation",
  "analyze" not "analyse", "behavior" not "behaviour")
☐ US English grammar conventions
☐ No em-dashes (—) anywhere in the document
☐ No en-dashes (–) used as punctuation
☐ No double hyphens (--) used as separators
☐ Hyphens (-) used only within compound words (e.g., "read-only",
  "third-party", "well-known")
☐ Use commas, colons, semicolons, or parentheses for all separations
  and asides where dashes might otherwise appear
☐ Client-specific terms in italics throughout

### Pass 4: Completeness

☐ All 8 sections present in correct order
☐ Cover page contains chain of custody and controlling entity boxes
☐ Executive summary readable as standalone briefing
☐ Five Questions all answered with evidence + rating + remediation path
☐ Appendix A contains only confirmed applicable regulations
☐ Appendix B explains scoring methodology
☐ Appendix C URLs complete and not truncated
☐ Footer on every page with correct format

### Pass 5: Final Reconciliation

Re-read the Executive Summary and verify that a business executive
reading only pages 1-4 would:
- Understand the organization's reliance on technology
- Know the top risks and their severity
- Know what must be done immediately vs. over time
- Understand the regulatory implications
- Know whether remediation requires budget or just configuration

If any element is unclear or inconsistent, revise and restart from Pass 1.

---
