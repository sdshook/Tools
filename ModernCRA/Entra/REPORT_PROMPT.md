# Entra ID Security Assessment Report Generation Prompt
# (c) 2026, Shane D. Shook, PhD

Use this prompt when attaching a JSON output file from entra_assessment.py
to any AI interface that supports file uploads and document generation.

---

## PROMPT (copy everything below this line)

---

I am attaching a JSON file containing the results of a Microsoft Entra ID
security posture assessment. Please produce a professionally formatted Word
document (.docx) containing the full assessment report.

You must collect five pieces of information from me before generating
anything. Ask each question individually, one at a time, and wait for my
response before asking the next. Do not ask multiple questions in a single
message. Do not proceed to the next question until I have answered the
current one. Do not begin generating the report or any part of it until
all five answers have been received.

Do not assume any regulatory status, geographic presence, or organizational
classification from the tenant data, domain names, or organization name.
Every answer must come from me explicitly.

Begin now by asking only Question 1.

---

QUESTION 1 (ask this first, then stop and wait for my answer):

What is the primary industry sector of the assessed organization? Please
select or specify one of the following:

- Financial Services / Investment Management
- Financial Services / Banking or Credit
- Healthcare or Health IT
- Critical Infrastructure (energy, water, transportation)
- Defense Industrial Base
- Legal / Professional Services
- Technology / SaaS
- Retail / E-Commerce
- Government / Public Sector
- Education
- Other (please specify)

Wait for my answer before proceeding to Question 2.

---

QUESTION 2 (ask only after Question 1 is answered):

What is the organization's specific regulatory classification within
that sector?

Do not infer or assume regulatory status from the sector alone. Ask
this question in terms appropriate to the sector the assessor identified.

For Financial Services / Investment Management, ask:
Is the organization a Registered Investment Adviser (RIA) under the
Investment Advisers Act, an Exempt Reporting Adviser (ERA) under Section
203(l) or 203(m), a Registered Investment Company (mutual fund or ETF)
under the Investment Company Act of 1940, an unregistered private fund
with no SEC filing obligation, a state-registered adviser only, or a
registered broker-dealer under the Exchange Act?

For Financial Services / Banking or Credit, ask:
Is the organization a national bank (OCC-chartered), a state member bank
(Federal Reserve supervised), a state non-member bank (FDIC supervised),
a credit union (NCUA), or a fintech or non-bank financial company?

For Healthcare or Health IT, ask:
Is the organization a covered entity (hospital, health plan, or provider),
a business associate, or a health IT vendor with no direct PHI access?

For other sectors, ask the equivalent question about whether the
organization is directly regulated, a contractor or vendor to regulated
entities, or operating under voluntary framework adoption only.

Once you have the answer, use it to determine which regulations apply.
Only cite regulations that directly apply to the confirmed classification.
Distinguish between mandatory obligations, contractual obligations,
voluntary framework adoption, and proposed or pending rules.

Wait for my answer before proceeding to Question 3.

---

QUESTION 3 (ask only after Question 2 is answered):

In which US states does the organization maintain offices or is otherwise
registered to conduct business?

Explain to me that this determines which state-level data security
regulations and securities laws apply, and that I should list all states
where the organization has a physical presence or legal registration.

Also ask whether there are any states where a significant volume of the
organization's clients, customers, or employees reside, since two
categories of state law follow data subjects rather than the
organization's location: CCPA/CPRA applies to personal information of
California residents regardless of where the organization operates, and
all 50 states have breach notification statutes requiring notification
to affected state residents regardless of where the business is domiciled.

Wait for my answer before proceeding to Question 4.

---

QUESTION 4 (ask only after Question 3 is answered):

In which countries outside the United States does the organization have
permanent offices or registered legal entities?

Explain that a permanent office or registered entity is the primary
trigger for that country's regulatory framework applying as a mandatory
obligation, including local data protection registration, appointment of
a supervisory authority representative, and compliance with local
employment law.

Wait for my answer before proceeding to Question 5.

---

QUESTION 5 (ask only after Question 4 is answered):

In which countries does the organization have clients, customers,
investors, or counterparties whose personal data (including names,
contact information, financial data, and communications) is held or
processed by the organization?

Explain that data protection obligations in most jurisdictions attach to
the residence of the data subject, not the location of the organization,
so processing personal data of residents of a country can trigger that
country's privacy law even without a physical presence there.

Also note the following important distinction that must be applied when
writing the report: employee travel to a country does NOT create data
protection obligations in that country. An employee visiting another
country on a business trip and accessing company systems is a domestic
person temporarily abroad, not a data subject of that jurisdiction. Foreign
privacy laws should only be cited when the organization processes personal
data of residents of that country or has a legal establishment there.

After receiving the answer to Question 5, perform the research steps below
before generating any part of the report. Do not ask the analyst further
questions during this phase. Present findings from Steps A and B to the
analyst as a structured pre-report briefing and ask them to confirm,
correct, or add to the information before proceeding to report generation.

---

## PRE-REPORT RESEARCH (perform after Question 5, before generating the report)

### Step A: Regulatory Currency Check

Search for the current enforcement status of each regulation applicable
to the confirmed sector and classification before writing the regulatory
context section. Verify effective dates, threshold requirements, and any
amendments issued since your knowledge cutoff. Label proposed or pending
rules explicitly. This search should be conducted regardless of how
recently the knowledge cutoff falls, as regulatory effective dates and
enforcement priorities change frequently.

### Step B: Entity and Jurisdiction Verification

Conduct independent research to verify and supplement the business
registration and jurisdictional information provided by the assessor.
This step exists because analysts may have incomplete records, may be
unaware of subsidiary entities registered in additional jurisdictions, or
may not know the current regulatory classification of each entity. The
goal is to surface discrepancies and additional jurisdictions for analyst
review before they propagate into the legal and compliance sections of
the report.

**Research procedure:**

1. Search public registries and authoritative secondary sources for each
   jurisdiction mentioned in Questions 3 and 4. For each confirmed
   permanent office or registered entity, attempt to locate:
   - The legal entity name and type (LLC, Ltd, S.a r.l., etc.)
   - The registration or company number
   - The registered office address
   - The date of incorporation or registration
   - The activity or SIC/NACE code
   - Any regulatory authorization number (FCA FRN, SEC CRD, CSSF
     registration, FINRA CRD, etc.) and its current status
   Use: SEC IARD/EDGAR for US advisers; Companies House for UK entities;
   Luxembourg RCS (registre-de-commerce.lu) for Luxembourg entities;
   California Secretary of State for California entities; FCA Financial
   Services Register for UK-regulated firms; CSSF register for Luxembourg
   financial entities. Flag any authorization number found through a
   secondary source that has not been independently confirmed against the
   primary regulator's public register, and instruct the analyst to verify
   it directly.

2. Cross-reference the tenant data (domain names, guest user email
   domains, application integrations, sign-in geographic data, and
   organization metadata) for signals of jurisdictions or entities not
   mentioned by the assessor. Signals to look for include:
   - Domain names that suggest additional country-specific operations
     (e.g., .co.uk, .de, .lu, .fr suffixes on verified tenant domains)
   - Guest user home domains from countries not mentioned in Questions
     4 or 5, suggesting business relationships with entities in those
     countries whose employees' personal data may be processed
   - Application integrations with country-specific services
   - Sign-in geographic data from the behavioral analysis module showing
     authentication from countries not confirmed by the assessor
   - Organization display name variants that suggest related entities

3. Search for any related entities under the organization's name or
   brand that may not have been mentioned, including parent companies,
   subsidiaries, general partner entities, fund vehicles, and holding
   companies. For investment management firms, check Form D filings,
   Form ADV, and equivalent foreign filings for associated fund entities
   that may have separate registrations or regulatory obligations.

4. For each jurisdiction identified through Steps B.1 through B.3,
   determine whether the entity or activity found triggers regulatory
   obligations beyond those already identified in the assessor's answers,
   including:
   - Financial sector regulation (FCA, CSSF, SEC, FINRA, or equivalent)
   - Data protection registration requirements
   - AML/CTF registration or authorization
   - Local employment law or works council requirements triggered by
     having employees in that jurisdiction

**Present findings to the analyst before generating the report:**

After completing Steps A and B, present a structured pre-report briefing
to the analyst containing two sections:

SECTION 1 — ENTITY AND REGISTRATION FINDINGS
List each entity found, with: jurisdiction, legal name, registration
number, registered address, activity code, and any authorization numbers
with their verification status (confirmed from primary register, or
found via secondary source and requiring direct verification). For each
entity, note whether it matches, supplements, or conflicts with what the
assessor provided. Flag any jurisdiction or entity found through research
that was not mentioned by the assessor.

SECTION 2 — DISCREPANCIES AND UNCONFIRMED ITEMS REQUIRING ANALYST REVIEW
Present a numbered list of specific items that require the analyst's
attention before the report is finalized:
- Jurisdictions found in research but not mentioned by the assessor
  (potential missing offices, fund registrations, or data-subject
  populations)
- Authorization numbers found through secondary sources that require
  direct verification against the primary regulator's register
- Entities whose regulatory classification is ambiguous and requires
  legal confirmation (e.g., a GP vehicle that may or may not be subject
  to AIFM authorization requirements)
- Geographic signals from the tenant data that suggest business
  activity or data subject relationships in additional countries
- Any conflict between what the assessor stated and what public records
  show

Then ask: "Please review the findings above. Confirm which items are
accurate, correct any errors, and advise whether any flagged jurisdictions
or entities should be included in the report. Once you confirm, I will
generate the full report."

Wait for the analyst's response before generating any section of the
report. Incorporate the analyst's corrections and confirmations into the
regulatory context, the cover page Legal Entities box, and the appendix
methodology section.

Then generate the full report using the structure, content requirements,
and formatting rules below.

International frameworks triggered by data subject residence:
- European Union member states (including France, Germany, Netherlands,
  Spain, Sweden, and all others): GDPR (Regulation 2016/679). A permanent
  office in any EU member state makes GDPR mandatory as an establishment
  obligation, with the local supervisory authority as the competent
  authority for that office. Processing personal data of EU residents
  without an establishment triggers GDPR as a data-subject-based
  obligation and may require appointment of an EU representative.
- United Kingdom: UK GDPR and Data (Use and Access) Act 2025 (in force
  February 2026). A permanent UK office makes UK GDPR mandatory as an
  establishment obligation.
- Mexico: Ley Federal de Proteccion de Datos Personales en Posesion de
  los Particulares (LFPDPPP, 2010) and its regulations. Applies to
  processing personal data of Mexican residents.
- Canada: PIPEDA or provincial equivalents (Quebec Law 25 is stricter
  and requires privacy impact assessments and a privacy officer);
  Consumer Privacy Protection Act (CPPA, Bill C-27, pending as of 2026).
- Japan: Act on Protection of Personal Information (APPI, amended 2022).
  Applies to processing personal data of Japanese residents.
- Australia: Privacy Act 1988 and Australian Privacy Principles.
- Singapore: Personal Data Protection Act (PDPA).
- Switzerland: revised Federal Act on Data Protection (revFADP, in force
  September 2023).
- Brazil: Lei Geral de Protecao de Dados (LGPD).
- China: Personal Information Protection Law (PIPL).
- South Africa: Protection of Personal Information Act (POPIA).
- Israel: Privacy Protection Law and pending amendments.

Also cross-reference the tenant data for signals of jurisdictions not
mentioned by the assessor. Guest user domains, application integrations,
and domain names may indicate business relationships in additional
countries. Flag these for analyst confirmation.

---

## REPORT STRUCTURE

### Page 1: Cover Page

The cover page contains five elements in order, each spanning the full
content width (6.5 inches / 9360 DXA). Do not use centered paragraphs
for the detail content; use structured tables as specified below.

**Element 1: Title block (centered paragraphs)**
- Organization name: large (28pt+), bold, dark blue (#1F3864), centered
- Report title "Entra ID Security Posture Assessment": medium (18pt),
  bold, medium blue (#2E5496), centered
- Vertical space below before Element 2

**Element 2: Assessment Details box (full-width two-column table)**
A table spanning the full content width with a dark blue (#1F3864) header
bar containing the label "ASSESSMENT DETAILS" in white, followed by
two-column rows. Left column: shaded (#EEF2F7), bold dark blue label.
Right column: white background, value text. Rows:

| Label | Value |
|---|---|
| Assessment Date | Date the assessment was run |
| Analysis Window | Number of days and date range (start to end) |
| Records Collected | Total records and API call count from chain_of_custody |
| Tenant | Tenant domain (italicised) |
| Tenant GUID | Full untruncated tenant GUID — use a monospace font |
| Collector | Collector UPN (italicised) |
| Evidence Directory | Case directory name (italicised) |

**Element 3: Assessed Legal Entities box (full-width two-column table)**
A table spanning the full content width with a medium blue (#2E5496)
header bar containing the label "ASSESSED LEGAL ENTITIES" in white,
followed by one row per jurisdiction confirmed by the assessor. Left
column: shaded (#EEF2F7), bold dark blue jurisdiction name. Right column:
entity name in italics (larger), then registry identifiers and registered
address in smaller gray text below. Include only jurisdictions where a
confirmed permanent office or registered legal entity exists (from
Question 4). Do not include jurisdictions where only data subjects reside.

**Element 4: Finding counts bar (full-width five-column table)**
A single-row table spanning the full content width, five equal columns,
no borders between cells. Each cell: colored background, severity label
in white bold small caps, large white bold count number. Colors:
CRITICAL = #C00000, HIGH = #C55A11, MEDIUM = #997300, LOW = #375623,
INFO = #555555. All five columns must be the same width (total width
divided by 5) so the bar is visually uniform.

**Element 5: Confidentiality notice box (full-width single-column table)**
A prominent box spanning the full content width with a red (#C00000)
border on all four sides, light red (#FFF2F2) fill, containing:
- "COMPANY CONFIDENTIAL | NOT FOR EXTERNAL DISTRIBUTION" in red bold
  centered text
- A brief confidentiality statement naming the organization
- Never use Attorney-Client Privileged language unless the assessor
  explicitly instructs this

---

### Page 2 onward: Executive Summary

The executive summary begins on page 2 and is designed to be readable as
a standalone briefing for an executive audience that may not read the full
technical sections. It must be complete and self-contained. Do not
compress, abbreviate, or reduce font size. Write all content at the level
of detail required for senior leadership and legal and compliance review.

The executive summary contains the following subsections in this order:

**Subsection A: Purpose, Scope, and Method**

Open with two paragraphs of introductory prose before any tables or grade
boxes appear.

Paragraph 1: Introduce the assessment, the tenant assessed, the
organization and affiliated entities, and the purpose of the assessment.
Include the following explanation of Microsoft Entra ID in plain language:
Microsoft Entra ID is the organization's identity and resource access
management system, controlling who can sign in, what applications and data
they can reach, and what permissions are granted to users, administrators,
and third-party services; auditing it reveals misuse of credentials and
their associated permissions that could threaten the organization or
indicate active compromise.

Paragraph 2: Describe the assessment scope, the tool used (read-only
16-module Python-based tool, Entra ID Security Posture Assessment v2.0
by Shane Shook, available at
https://github.com/sdshook/Tools/tree/main/ModernCRA/Entra), the
two authentication sessions (Microsoft Graph API device code for modules
1 through 13 and 15 through 16; Exchange Online PowerShell device code
for module 14), the number of records collected, the number of API calls,
the analysis window dates, and the statement that no changes were made to
the tenant configuration, user accounts, permissions, or data during the
assessment.

These two paragraphs must appear as separate paragraphs, not combined.

**Subsection B: Overall Security Posture**

Three equal-width colored grade boxes appear immediately after the
introductory paragraphs. Each box contains a category label, a grade
word in large type, and a one-line count and summary statement.

Box 1: EXIGENT RISK
- Fill color: RED (#C00000)
- Grade word: RED
- Sub-label: critical finding count and one-line primary risk statement
  Example: "3 Critical | Active credential theft capability present"

Box 2: HYGIENE POSTURE
- Fill color: YELLOW (#FFC000) if Medium findings exist, otherwise GREEN
  (#375623)
- Grade word: YELLOW or GREEN
- Sub-label: medium finding count and one-line characterization
  Example: "16 Medium | Foundational gaps require remediation"

Box 3: CONFIGURATION AND USE ANOMALIES
- Fill color: RED (#C00000) if confirmed anomalies requiring incident
  response; YELLOW (#FFC000) if anomalies requiring investigation;
  GREEN (#375623) if no anomalies present
- Grade word: RED, YELLOW, or GREEN
- Sub-label: one-line characterization
  Example: "Unverified privileged activity requires investigation"

Color specification: RED = #C00000, YELLOW = #FFC000 (amber-yellow, not
brown or dark gold), GREEN = #375623. These exact hex values must be used.

**Subsection C: Finding Summary**

Immediately following the grade boxes, present a structured finding
summary table with one row per severity tier (CRITICAL, HIGH, MEDIUM,
LOW, INFO). Columns: severity (color-coded), count, and a one to two
sentence plain-language characterisation of the findings in that tier.
This table must appear before the critical headline box described below.

**Subsection D: Critical Headline**

After the finding summary table, present a prominent full-width red-
bordered box (border color #C00000, background #FFF2F2) containing a
concise plain-language statement of the most serious risk present in the
assessment. The headline box must appear on the same page as the finding
summary table or, if it does not fit, must begin at the top of the next
page together with its heading label. The heading "Critical Headline" and
the red box must never be split across pages: if the heading cannot fit
on the same page as the box, both must move to the next page together
using a keep-with-next control.

**Subsection E: Immediate Actions Required (P0, within 24 hours)**

Following the critical headline box, list each P0 action from the
remediation matrix in plain business language. Each item shows the P0
priority label, a short action title, and a one to two sentence
description of what to do and why. This subsection gives an executive
reader immediate actionable direction without requiring them to read
Section V.

**Subsection F: Re-Assessment**

A brief closing paragraph recommending re-assessment within 30 days of
completion of all P0 and P1 remediation actions, with specific focus areas
to verify.

---

### Section I: Exigent Risks Requiring Immediate Action

For each Critical finding and the most severe High findings that represent
immediately exploitable conditions:
- Label each finding EX-1, EX-2, etc.
- Write 3 to 5 paragraphs covering: what the finding is, why it is
  dangerous for this type of organization, the specific attack scenario,
  and the immediate remediation action
- Include a Microsoft documentation URL for each remediation
- Prioritize by immediacy of exploitability, not severity label alone
- Reference the applicable regulation by name and section where relevant

### Section II: Hygiene Issues With Recommendations

For each Medium finding and remaining High findings not covered in
Section I:
- Label each H-1, H-2, etc., prioritized by risk
- Explain what is misconfigured and why it matters for this organization
- Provide specific actionable remediation steps, not generic advice
- Include Microsoft documentation URLs
- Note the regulatory implication where one exists

Important guidance on legacy authentication blocking: when recommending
a Conditional Access policy to block legacy authentication, specify that
the policy should target the "Other clients" condition only (covering
SMTP AUTH, IMAP, POP3, and legacy MAPI). Do NOT recommend blocking
Exchange ActiveSync wholesale. Exchange ActiveSync with modern
authentication is a legitimate mobile mail client flow and should be
controlled via a separate device compliance CA policy, not blocked
outright. Conflating EAS with legacy authentication in the same blocking
policy will break mobile mail for compliant devices.

### Section III: Architectural Issues

Identify systemic patterns across findings that indicate structural
governance failures rather than isolated misconfigurations. Address each
of the following where evidence exists in the data:
- Third-party application permission governance
- Identity lifecycle management
- Privileged access architecture
- Device management architecture
- Authentication architecture
- Email security architecture

### Section IV: Configuration and Use History Anomalies

**Geographic Authentication Map (Figure IV-1)**

The first element in Section IV, before any anomaly finding text, is a
geographic map showing authentication origins observed during the analysis
window. Generate this map using Python/matplotlib/geopandas and embed the
resulting PNG as an inline image in the Word document.

Map generation procedure:

1. Use the naturalearth_lowres shapefile bundled with the pyogrio package.
   The path in this environment is:
   /usr/local/lib/python3.12/dist-packages/pyogrio/tests/fixtures/
   naturalearth_lowres/naturalearth_lowres.shp
   Load it with: world = gpd.read_file("<path>")

2. Figure size: 13 x 7.5 inches at 180 DPI. Background color: #0A1628
   (figure) and #0D1B2E (axes). World polygon fill: #1A2F4A. World
   polygon edge color: #2E4A6B at linewidth 0.4.

3. Plot authentication origin dots using IP geolocation data from the
   behavioral analysis findings (M-13 / high IP diversity, and any
   geographic anomaly findings). Apply four marker types:

   - Blue circles (#4DA8DA, edge #A0D8F0): US domestic authentication
     origins. Scale dot size proportionally to the number of users
     observed at that location (base 38 + users * 20).
   - Green circles (#50C878, edge #A0F0C0): international authentication
     origins that are consistent with confirmed office locations or
     confirmed data-subject jurisdictions from Questions 4 and 5.
   - Red circles (#FF4444, edge #FF9999): authentication origins in
     jurisdictions not confirmed as offices or known data-subject
     countries. These require analyst review. Annotate with an arrow
     callout reading "[Country] (analyst review required)".
   - Gold diamonds (#FFD700, edge #FFFFFF, marker='D'): permanent office
     locations as confirmed in Question 4. Do NOT place a gold diamond
     on a country merely because data subjects reside there. Only
     confirmed offices or registered entities from Q4 receive diamonds.

4. Label only prominent locations. For dense clusters (e.g., multiple Bay
   Area cities), use a single cluster label rather than individual dots.
   Use white path-effect strokes behind all labels to ensure legibility
   against the dark background. Avoid overlapping labels.

5. Include a four-item legend: US authentication origins; international
   authentication origins (expected); flagged authentication origins
   (under review); permanent office location. Place legend lower-left.
   Legend background: #0D1B2E with #2E4A6B border.

6. Title line (upper-left, color #D0E8FF, size 9pt):
   "Authentication Origin Map  |  [Org Name] Entra Assessment  |
   90-Day Window ([start date] - [end date])"

7. Source attribution (lower-right, color #5A7A9A, size 5.8pt):
   "Source: Module 15 Behavioral Analysis ([N] off-hours events,
   [N] high-diversity users)  |  Company Confidential"

8. Remove axis ticks and labels. Set xlim -175 to 178, ylim -58 to 82.

9. Save at 180 DPI with bbox_inches='tight'. Embed in the docx using
   ImageRun with transformation width=624, height=360 (representing
   6.5 x 3.75 inches in the document at 96 DPI). Center the image.

10. Immediately below the image, add a figure caption paragraph in gray
    text (color #595959, size 9.5pt), centered, reading:
    "Figure IV-1: Authentication origin map for the 90-day analysis
    window. [Describe the color encoding and what each category means
    in one or two sentences]. Gold diamonds mark the [N] permanent
    office location(s): [list them]. Source: Module 15 Behavioral
    Analysis."

For each anomaly in the audit log or behavioral analysis data:
- Label each AN-1, AN-2, etc.
- Describe exactly what was observed and when, using only data from the
  JSON file
- State whether it requires immediate incident response or verification
- Distinguish clearly between assessment preparation artifacts (such as
  permission grants made to prepare for the assessment run) and genuine
  anomalies requiring investigation
- Do not assert that compromise has occurred. State what the pattern is
  consistent with and what the assessor must confirm.
- Where a geographic anomaly is flagged (authentication from an
  unexpected jurisdiction), cross-reference the map and direct the
  reader to the flagged dot in Figure IV-1.

Mailbox forwarding findings require careful interpretation. Apply the
following severity logic, which the tool already encodes but the report
should explain:

Server-side SMTP forwarding (ForwardingSmtpAddress set on the mailbox):
CRITICAL regardless of destination. This setting silently copies or
redirects all inbound mail at the server level, persists through password
resets and MFA changes, and is invisible to the mailbox owner in Outlook.
It is the primary BEC persistence mechanism.

Inbox rules forwarding to external addresses (outside the tenant):
CRITICAL. Verify whether the destination is a known business-justified
service (expense management, CRM integration) or an unknown external
address. Even legitimate-looking destinations must be confirmed with the
mailbox owner. Consider recommending a transport rule blocking
auto-forwarding to external domains.

Inbox rules forwarding to internal addresses (within the tenant):
LOW. Internal forwarding is usually legitimate delegation or integration.
Flag for confirmation but do not present as a security event.

Disabled inbox rules: note their disabled state explicitly. A disabled
rule presents no active risk but indicates a former configuration that
should be reviewed and removed if no longer needed.

Delete rules: HIGH. Rules that delete messages can suppress wire transfer
replies, security alerts, and MFA notifications. Each must be confirmed
as a legitimate user preference.

### Section V: Priority Remediation Matrix

A five-column table. One row per finding. Color-code the Priority column:
- P0: RED background (#C00000), white text, Immediate or 24 hours
- P1: ORANGE background (#C55A11), white text, This week
- P2: YELLOW background (#FFC000), white text, 30 days
- P3: GREEN background (#375623), white text, 60 to 90 days

Columns:
1. Priority
2. Finding description
3. Action Owner
4. Timeframe
5. Standard / Regulation: cite the specific ISO 27001:2022 control number,
   NIST CSF function and subcategory, NIST SP document and section, CIS
   Control number, or regulation citation for every row. Never leave this
   column blank. Follow the citation rules below exactly.

**Section V citation rules — read before populating the matrix:**

Rule 1 — Consistency with the executive summary. The Standard / Regulation
column must cite only regulations that were established as applicable in
the executive summary regulatory context. If a regulation does not apply
to this organization's confirmed classification, it must not appear in
Section V. If the executive summary established a regulation as a
mandatory obligation, it should appear in Section V wherever a finding
implicates it.

Rule 2 — Jurisdiction completeness. Where EU GDPR applies (Article number),
UK GDPR must also be cited if the organization has a permanent UK office or
processes personal data of UK residents. Both obligations arise from the same
finding type and must appear together. Do not cite one without the other
where both are confirmed.

Rule 3 — Primary regulatory obligation first. Where a finding implicates a
sector-specific regulatory obligation confirmed in the executive summary
(such as Advisers Act Section 206, GLBA, HIPAA, or FCA SYSC), that
obligation is cited first in the cell, before ISO 27001 or NIST references.
Findings involving unauthorized access to client or fund communications,
privileged account compromise, data exfiltration capability, or fiduciary
data integrity must cite the primary sector obligation.

Rule 4 — State privacy law. Where a finding involves access controls,
identity lifecycle, authentication, or account hygiene, and the organization
has confirmed employees or data subjects in a state with active privacy law
(e.g., California CCPA/CPRA), that state law must be cited alongside GDPR
where the finding implicates personal data of those residents.

Rule 5 — ISO 27001:2022 controls only. Use the 2022 revision control
numbering throughout. Do not use 2013 revision control numbers (A.11.x,
A.12.x, A.13.x). The 2022 revision restructured and renumbered these
controls. Common correct mappings:
- Device management / endpoint security: A.8.1 (not A.11.2.8)
- Email security / electronic messaging: A.8.23, A.5.14 (not A.13.2.3)
- Event logging and monitoring: A.8.15, A.8.16 (not A.12.4.1)
- Vulnerability management: A.8.8 (not A.12.6.1)
- Privileged access / access rights: A.8.2, A.8.3, A.5.18 (not A.9.x
  where the 2022 revision moved the control)
- Cryptography and key management: A.8.24 (not A.10.1)
- Malware protection: A.8.7 (not A.12.2)
- Access control policy: A.5.15
- Identity management: A.5.16
- Authentication: A.5.17
- Access rights management: A.5.18
- Privileged access rights: A.8.2
- Information access restriction: A.8.3
- Secure authentication: A.8.5
- Capacity management: A.8.6
- Protection against malware: A.8.7
- Endpoint device management: A.8.1
- Web filtering: A.8.23
- Information transfer: A.5.14
- Monitoring activities: A.8.16
- Clock synchronization: A.8.17
- Use of privileged utility programs: A.8.18
- Installation on operational systems: A.8.19
- Network security: A.8.20
- Segregation of networks: A.8.22

Rule 6 — Conditional obligations. Regulations identified in the executive
summary as conditional (such as FCA SYSC obligations pending FRN
confirmation, or CSSF AIFM obligations pending classification review, or
DORA pending supervision determination) must be cited in Section V with
the same conditional qualifier: "FCA SYSC 13 (if FCA-authorised)" rather
than "FCA SYSC 13" stated as fact.

Rule 7 — Self-consistency check before finalizing. Before writing the
matrix, list the regulations confirmed as applicable in the executive
summary, then verify that each P0 and P1 finding cites at least one of
those regulations (in addition to framework controls) where the finding
implicates that regulation. A finding that involves credential compromise,
data access, or fiduciary data with no sector-specific regulatory citation
is likely missing one.

### Section VI: Regulatory and Industry Context

This section contains the full regulatory compliance analysis. It is
positioned after the remediation matrix so that executive readers encounter
the actionable findings before the legal detail, while compliance and legal
counsel can locate the full analysis in a dedicated section.

**Status label color coding — introduce this at the opening of Section VI:**

Before writing the first regulation entry, include a brief introductory
paragraph explaining the color-coded status labels used throughout this
section. The introduction should read approximately:

  "Each applicable regulation and obligation below carries a compliance
  status label indicating the organization's current posture against that
  requirement based on the findings in this assessment. Labels are:
  SATISFACTORY (green) — current controls are adequate for this
  obligation; PARTIAL (amber) — controls are partially implemented but
  material gaps exist; DEFICIENT (red) — controls are insufficient or
  absent for this obligation; CONDITIONAL (grey) — status cannot be
  confirmed pending external verification such as regulatory registration
  confirmation or legal classification review."

The status labels must be rendered as colored inline text boxes or shaded
inline runs matching the priority matrix palette:
- SATISFACTORY: fill #375623 (green), white text
- PARTIAL: fill #FFC000 (amber), white text
- DEFICIENT: fill #C00000 (red), white text
- CONDITIONAL: fill #595959 (grey), white text

**Format for each regulation entry:**

Each regulation or obligation is presented as a distinct paragraph opening
with the colored status label as an inline element, followed immediately
by the regulation name in bold, followed by the explanatory prose. The
status label must appear on the same line as the regulation name, not as
a separate heading. Example structure:

  [DEFICIENT] GDPR Article 32 (Security of Processing): [prose explaining
  the obligation, the specific findings driving the deficient status, and
  the compliance consequence...]

  [SATISFACTORY] Investment Advisers Act Section 206 Anti-Fraud: [prose
  explaining that no findings indicate a breach event has occurred,
  though the findings create conditions that increase Section 206 risk...]

**Content requirements for each entry:**

Include the following content for each applicable regulation:
- The specific citation (CFR section, article number, statute reference)
- Whether the obligation is mandatory (establishment) or data-subject-based
- The specific findings from this assessment that drive the status
  determination, referenced by finding label (EX-1, H-3, AN-2, etc.)
- The specific compliance consequence of the current status in plain
  language: examination exposure, notification obligation triggered,
  fiduciary duty implicated, supervisory authority notification required,
  or equivalent
- For SATISFACTORY entries: which controls are present and working that
  support the satisfactory determination — do not leave satisfactory
  entries as bare assertions

Also include:
- Applicable voluntary framework alignment: ISO/IEC 27001:2022, NIST CSF
  2.0, NIST SP 800-63B, CIS Controls v8, or sector-specific equivalents,
  with a PARTIAL or SATISFACTORY label reflecting the finding pattern

**Status determination rules:**

DEFICIENT: one or more P0 or P1 findings in Section V cite this regulation,
or a finding directly implicates a core requirement of this obligation
(e.g., a finding showing no Data Processing Agreements implicates GDPR
Article 28 as DEFICIENT regardless of P-level).

PARTIAL: findings exist that implicate this regulation but compensating
controls or partial compliance are also evidenced in the assessment data,
or the obligation has multiple requirements of which some are met and some
are not.

SATISFACTORY: no findings implicate this regulation's core requirements,
and the assessment data provides positive evidence of compliance (not
merely absence of a finding — absence of a finding alone is not sufficient
to assert SATISFACTORY where the assessment scope may not have covered
all relevant controls).

CONDITIONAL: the regulatory classification itself is uncertain (e.g., FCA
authorisation pending confirmation, CSSF classification requiring legal
review) and therefore the compliance status cannot be determined without
first confirming whether the obligation applies.

---

### Appendix A: Assessment Methodology and Limitations

- Tool used, authentication method, read-only nature of the assessment
- Two authentication sessions are used: Session 1 is a Microsoft Graph
  API device code login at startup covering modules 1 through 13 and 15
  through 16. Session 2 is a separate Exchange Online PowerShell device
  code login that occurs mid-run during module 14. Both sessions are
  read-only. Note this in the methodology section so the two device code
  events in any access log are correctly understood as expected assessment
  behavior, not anomalous sign-in activity.
- Chain of custody reference (case directory name, MANIFEST.json)
- Module 14 evidence is stored as a PowerShell output file in the raw
  evidence directory alongside the Graph API response files, with its
  own SHA-256 hash in MANIFEST.json.
- If module 07 (sign-in logs) produced an INFO finding stating no data
  was returned, this indicates a genuine permission or consent gap —
  not a transient Graph API indexing issue. Module 07 now issues two
  independent compound-filter queries (one for successful sign-ins,
  one for failures) that each include an equality predicate, which
  resolves the prior indexing limitation. If both queries return empty
  while module 15 returns data, the most likely cause is that the
  collecting account lacks Reports Reader or Security Reader role, or
  AuditLog.Read.All admin consent has not propagated. Document it as
  a permission gap in the appendix and recommend re-running after
  confirming consent and role assignment.
- Modules that returned no data and the reason (licensing gap, permission
  gap, scope propagation delay)
- Re-assessment recommendations where applicable

---

### Appendix B: References

The references appendix is divided into three subsections. Every URL must
be rendered in full with no truncation. Use a monospace or hyperlink style
to distinguish URLs from prose text.

**Subsection 1: Assessment Tool**

Entra Assessment Tool
Shane Shook, May 2026. Entra ID Security Posture Assessment v2.0 —
read-only 16-module Python tool using Microsoft Graph API and Exchange
Online PowerShell.
https://github.com/sdshook/Tools/tree/main/ModernCRA/Entra

**Subsection 2: Microsoft Entra and Microsoft 365 Documentation**

This subsection is a compiled output derived from the report content. It
is NOT a static list to be reproduced verbatim. Before writing this
subsection, review every remediation recommendation written in Sections I,
II, III, and IV of this report. For each Microsoft documentation URL
included in a remediation recommendation, extract the descriptive title
and the URL. Collect all such entries, deduplicate, and present them here
in the order they first appear in the report.

Do not copy URLs from memory or from any pre-existing list. Each URL
cited in a remediation must have been written into the report body as a
live reference. Verify that each URL resolves to current Microsoft
documentation before including it. If a remediation URL in the report
body is stale or has moved, correct it here and note the correction.
Do not include any Microsoft documentation URL that does not appear in
a remediation recommendation in this specific report.

Each entry is formatted as:
- Descriptive title of the documentation page in bold
- Full URL on its own line, untruncated

**Subsection 3: Regulations, Statutes, and Standards**

This subsection is a compiled output derived from the report content. It
is NOT a static list to be reproduced verbatim. Before writing this
subsection, perform the following derivation procedure:

STEP 1 — Compile from Section VI. Review every regulation, statute, and
voluntary framework entry written in Section VI (Regulatory and Industry
Context). For each entry that carries a SATISFACTORY, PARTIAL, DEFICIENT,
or CONDITIONAL status label, extract the full formal name of the
regulation or framework and its specific citation (CFR section, article
number, regulation number, or equivalent). Include every entry regardless
of status. Do not include regulations from the baseline reference guide
that were not written into Section VI for this specific report.

STEP 2 — Compile from Section V. Review every row of the Section V
(Priority Remediation Matrix). For each citation in the Standard /
Regulation column, extract any regulation, statute, or framework name
that was not already captured in Step 1. Add only items that appear in
this report's matrix and were not already included.

STEP 3 — Deduplicate. Where the same regulation appears multiple times
across Sections V and VI (e.g., GDPR Article 32 cited in multiple matrix
rows and in Section VI), include it once in the references list.

STEP 4 — Assign source URLs. For each unique regulation, statute, or
framework in the compiled list, search for and supply the official
primary source URL at the time of report generation. Use the issuing
authority's own website or official government registry as the source
(e.g., EUR-Lex for EU regulations, legislation.gov.uk for UK statutes,
sec.gov for US securities rules, iso.org for ISO standards, nist.gov for
NIST publications, fca.org.uk for FCA instruments). Do not use secondary
sources, aggregators, or law firm summaries as the cited URL. Do not
copy URLs from memory or from any static list. Search for each URL
individually to confirm it resolves to the current authoritative text.
Do not leave any entry without a URL.

STEP 5 — Organise into two groups. Present the compiled list in two
groups: (a) Regulations and Statutes, then (b) Standards and Frameworks.
Within each group, order entries by the sequence in which they first
appear in Section VI, so the references appendix mirrors the flow of the
regulatory analysis.

STEP 6 — Quality check. Verify that every regulation and framework cited
anywhere in Sections V or VI of this specific report appears in the
compiled list. Verify that no regulation or framework appears in the list
that was not cited in Sections V or VI of this specific report. Verify
that no URL is truncated.

Each entry in the compiled list is formatted as follows:
- Full formal name of the regulation or framework in bold
- One-line description identifying the issuing authority and the
  nature of the obligation
- Full official source URL on its own line, untruncated



---

## FORMATTING REQUIREMENTS

**Typography and layout**
- Font: Arial throughout, no exceptions
- Page size: US Letter (8.5 x 11 inches), 1-inch margins
- Footer on every page: organization name | report title | date |
  Company Confidential | page number
- H1 heading color: dark blue (#1F3864)
- H2 heading color: medium blue (#2E5496) with a colored underline rule
- H3 heading color: dark blue (#1F3864)

**Italics rule (strictly enforced)**
Every client-specific term must be rendered in italics wherever it appears
in body text and bullet points. This includes:
- All personal names and display names
- All email addresses and UPNs
- All application names and service principal names
- All domain names
- All device names
- All role group names
- All specific account identifiers

Plain text is reserved for generic descriptions, recommendations, and
regulatory references. Client-specific nouns are always italic.

**Finding tables**
Each finding in Sections I through IV uses a structured three-row table:
- Row 1 (header): severity label and finding title
- Row 2: Category and Detail
- Row 3: Evidence (complete bullet list of all items, never truncated)

**Punctuation**
Never use em-dashes, en-dashes, or double hyphens as separators or in
place of punctuation anywhere in the document. Use commas, colons,
semicolons, or parentheses instead. Hyphens are permitted only within
hyphenated compound words such as read-only, third-party, and well-known.
Use US English spelling and grammar throughout.

**No truncation**
All finding item lists must be reproduced in full. Do not use "and N more"
or any other abbreviated form. All GUIDs, tenant IDs, and identifiers must
be shown completely without truncation.

**No fabrication**
Every finding, metric, count, and detail must trace directly to data in
the attached JSON file. Do not invent findings, infer risk from data not
present, or generalize beyond what the data shows. If a module returned
no data, state that explicitly and explain why based on the data available.

---

## REGULATORY REFERENCE GUIDE BY SECTOR

These entries are a baseline starting point. Before writing the regulatory
context section, search for any amendments, finalized rules, or updated
enforcement guidance issued since your knowledge cutoff. Verify the
effective date and enforcement status of every regulation cited. Label
proposed or pending rules explicitly as such.

Regulations requiring active currency verification before each use:
- SEC cybersecurity and adviser rules (amended without fixed schedule)
- NIST SP 800-63B, SP 800-53, and CSF (under active revision)
- CMMC (implementation timelines change)
- PCI-DSS v4.0 (phased requirements with rolling compliance deadlines)
- HIPAA (OCR enforcement priorities and guidance evolve)
- FedRAMP (authorization baselines revised periodically)
- ISO/IEC 27001 (2022 revision differs materially from 2013)
- All state privacy laws (CCPA/CPRA, TDPSA, CDPA, CPA enforcement evolves)
- UK GDPR and Data (Use and Access) Act 2025 (recent changes)

---

**Financial Services / Investment Management**

Apply only the obligations matching the confirmed regulatory classification
from Question 2.

Registered Investment Adviser (RIA):
SEC Regulation S-P (17 CFR 248); SEC Cybersecurity Disclosure Rules
(August 2023); Investment Advisers Act Safeguarding Rule (Rule 206(4)-2
as amended 2024, compliance deadline June 3, 2026 for smaller firms);
Compliance Rule (Rule 206(4)-7); Books and Records Rule (Rule 204-2);
FINRA Rule 4370 if also a broker-dealer; applicable state privacy laws.
Framework: ISO 27001, NIST CSF, NIST SP 800-63B.

Exempt Reporting Adviser (ERA) under Section 203(l) or 203(m):
Investment Advisers Act Section 206 anti-fraud provisions (applies to all
advisers regardless of registration status); Rule 206(4)-5 pay-to-play;
Form ADV Part 2 disclosure accuracy obligations; state securities laws in
states of operation; applicable state and international privacy laws based
on Questions 3 through 5. State explicitly in the report that SEC
Regulation S-P, the Safeguarding Rule amendments, the Compliance Rule,
and the 2023 SEC Cybersecurity Disclosure Rules do not apply directly to
ERAs under their current text.
Framework: ISO 27001, NIST CSF, NIST SP 800-63B (voluntary, not mandated).

Unregistered private fund with no SEC filing obligation:
State securities laws; contractual obligations under investor side letters
and fund documents; applicable state and international privacy laws.
No federal adviser regulatory regime applies directly.

Registered Investment Company (fund):
Investment Company Act of 1940; SEC Regulation S-P; SEC cybersecurity
rules for registered funds; Form N-CEN reporting obligations.

**Financial Services / Banking and Credit**
Gramm-Leach-Bliley Act (GLBA) Safeguards Rule (16 CFR Part 314); OCC
Guidelines Establishing Information Security Standards (12 CFR Part 30
Appendix B); FDIC Part 364; FFIEC IT Examination Handbook; SOX Section
404 where applicable. Framework: FFIEC CAT, NIST CSF, ISO 27001, CIS
Controls v8.

**Healthcare and Health IT**
HIPAA Security Rule (45 CFR Part 164 Subpart C), specifically: 164.312(a)(1)
access control, 164.312(d) authentication, 164.312(e) transmission security;
HITECH Act Section 13402 breach notification; applicable state health data
privacy laws. Framework: NIST SP 800-66 Rev 2 (finalized 2024), ISO 27001,
HITRUST CSF.

**Critical Infrastructure**
NERC CIP-005 (Electronic Security Perimeters), NERC CIP-007 (System Security
Management), NERC CIP-011 (Information Protection); CISA Cybersecurity
Performance Goals; Executive Order 14028. Framework: NIST SP 800-82, IEC
62443, NIST CSF.

**Defense Industrial Base**
CMMC 2.0 Level 2 (based on NIST SP 800-171 Rev 3, finalized 2024); DFARS
Clause 252.204-7012. Key control families: 3.1 Access Control, 3.5
Identification and Authentication, 3.13 System and Communications Protection.
Framework: NIST SP 800-171, CMMC 2.0.

**Legal and Professional Services**
ABA Model Rules of Professional Conduct Rule 1.6 (confidentiality); state
bar cybersecurity guidelines (active in CA, NY, FL and others); NY SHIELD
Act; applicable state and international privacy laws. Framework: ISO 27001,
NIST CSF, CIS Controls v8.

**Technology and SaaS**
SOC 2 Type II (CC6 Logical and Physical Access, CC7 System Operations);
GDPR Article 32 (security of processing) where EU personal data processed;
applicable state privacy laws; ISO/IEC 27001:2022. Framework: NIST CSF,
CIS Controls v8, ISO 27001.

**Retail and E-Commerce**
PCI-DSS v4.0 Requirement 7 (access control), Requirement 8 (authentication),
Requirement 10 (logging and monitoring), Requirement 12.3 (risk assessment);
applicable state privacy laws. Framework: PCI-DSS v4.0, NIST CSF, ISO 27001.

**Government and Public Sector**
FISMA (44 USC 3551); FedRAMP Authorization Act; NIST SP 800-53 Rev 5 (AC,
IA, AU, SI control families); OMB Memorandum M-22-09 (Zero Trust). Framework:
NIST SP 800-53, NIST SP 800-63B, FedRAMP baselines.

**Education**
FERPA (20 USC 1232g); NIST SP 800-171 if handling controlled unclassified
information; applicable state student privacy laws. Framework: NIST CSF,
CIS Controls v8, ISO 27001.

---

## PRIORITY LOGIC

**P0: Immediate (within 24 hours)**
An active capability for harm exists without requiring additional attacker
steps. The condition is exploitable in its current state. Examples:
application permission sets that enable full mailbox compromise, external
party with write access to all security controls, vendor account holding
Global Administrator, active confirmed anomaly requiring incident response.

**P1: This week**
Condition significantly increases the probability or impact of a breach but
requires attacker action to exploit. Examples: no universal MFA policy,
legacy authentication protocols not blocked, missing email authentication,
no PIM, permanent privileged role assignments, stale passwords on admin
accounts, unconfirmed anomalies requiring investigation.

**P2: 30 days**
Hygiene gaps that expand attack surface but are not immediately exploitable.
Examples: expired app credentials with live permissions, app registrations
without owners, no phishing-resistant MFA registered, stale device
registrations, inactive enabled accounts, over-privileged but non-critical
application permissions.

**P3: 60 to 90 days**
Architectural and governance improvements that reduce systemic long-term
risk. Examples: full PIM deployment, application governance framework and
access review program, MDM coverage expansion, complete email authentication
rollout across all domains.

---

## QUALITY CHECKS BEFORE DELIVERING THE REPORT

Before finalizing, verify each of the following:

- Tenant GUID is shown in full in the Assessment Details box on the cover
  page with no truncation, rendered in a monospace font
- Every client-specific name, email address, application name, domain
  name, and account identifier appears in italics throughout
- No em-dashes, en-dashes, or double hyphens appear anywhere in the
  document used as separators or punctuation
- No finding item lists are truncated; all items from the JSON are present
- The executive summary opens with two separate introductory paragraphs:
  the first introducing the assessment and explaining what Microsoft
  Entra ID is and why it is audited; the second describing the scope,
  tool, records collected, analysis window, and read-only nature of the
  assessment. These must be separate paragraphs, not combined.
- The executive summary contains the posture grade boxes (Subsection B),
  followed by the finding summary table (Subsection C), followed by the
  critical headline box (Subsection D). The critical headline heading and
  its red box must never be split across pages.
- Section VI (Regulatory and Industry Context) opens with an introductory
  paragraph explaining the four status label colors before the first
  regulation entry appears
- Every applicable regulation entry in Section VI carries a colored status
  label (SATISFACTORY, PARTIAL, DEFICIENT, or CONDITIONAL); regulations
  that do not apply to this organization do not appear in the report
- DEFICIENT and PARTIAL entries each reference the specific finding
  labels (EX-1, H-3, AN-2, etc.) that drive the status determination;
  status is not asserted without evidential grounding in the finding data
- SATISFACTORY entries identify the specific controls present that
  support the determination; bare assertion of SATISFACTORY without
  supporting evidence is not permitted
- CONDITIONAL entries carry the same qualifier in Section V citations
  as in Section VI; a regulation that is CONDITIONAL in Section VI is
  not cited as a confirmed obligation in Section V
- Status labels use the correct colors: SATISFACTORY = #375623,
  PARTIAL = #FFC000, DEFICIENT = #C00000, CONDITIONAL = #595959
- The three posture grade boxes use the exact specified colors:
  RED = #C00000, YELLOW = #FFC000, GREEN = #375623
- YELLOW renders as amber-yellow, not brown or dark gold
- The priority matrix includes a regulatory or standards reference for
  every row with no blank entries in that column
- Every regulation cited in Section V was established as applicable in
  Section VI; regulations that do not apply to this organization do not
  appear in Section V
- Where EU GDPR is cited in Section V, UK GDPR is also cited in the same
  row unless the organization has no UK establishment and no UK data
  subjects, as confirmed in Questions 4 and 5
- Primary sector-specific regulatory obligations (Advisers Act, GLBA,
  HIPAA, FCA SYSC, or equivalent confirmed in Section VI) appear in
  Section V on all P0 and P1 findings that involve credential compromise,
  unauthorized data access, or fiduciary data integrity, not only on
  findings explicitly labeled as compliance issues
- State privacy laws confirmed as applicable in Section VI (CCPA/CPRA or
  equivalent) appear in Section V on rows involving identity lifecycle,
  authentication, account hygiene, and access controls where personal
  data of residents of that state is implicated
- All ISO 27001 control numbers in Section V use the 2022 revision
  numbering; 2013 revision numbers (such as A.11.2.8 for device
  management, A.12.4.1 for logging, A.13.2.3 for messaging) do not appear
- Conditional regulatory obligations (FCA, CSSF, DORA, or others flagged
  as requiring classification confirmation in Section VI) are cited in
  Section V with the same conditional qualifier, not as confirmed facts
- Classification reads "Company Confidential" with no attorney-client
  privilege language unless explicitly instructed
- Every remediation recommendation includes a Microsoft documentation URL
  or specific document reference
- No findings are invented; every finding traces to data in the JSON
- Assessment artifacts (permission grants or role assignments made to
  prepare for the assessment run) are identified as such in Section IV
  and not presented as security anomalies
- Regulatory citations have been verified current; no superseded rules
  are cited as in force; pending rules are labeled as proposed
- Entity registrations in the Legal Entities box on the cover page and
  in the regulatory context section reflect only confirmed information:
  entities confirmed by the assessor, supplemented by information
  confirmed through the Step B pre-report research. Authorization numbers
  found only through secondary sources are flagged as requiring direct
  verification against the primary regulator's register and are not
  stated as confirmed facts
- Any jurisdictions or entities surfaced during Step B research but not
  confirmed by the analyst are not included in the report as established
  facts; they may be referenced as items requiring further investigation
  if the analyst has noted them as unresolved
- If module 07 (sign-in logs) returned no data but module 15 (behavioral
  analysis) returned data, the finding is documented in the appendix as a
  permission or consent gap (not a transient indexing behavior), and is
  not elevated to a security finding or used to imply broader compromise
- Mailbox forwarding findings are correctly severity-classified: server-side
  SMTP forwarding and external inbox forwarding rules as CRITICAL, internal
  forwarding rules as LOW, and disabled rules are explicitly noted as
  inactive with no active risk
- Legacy authentication blocking recommendation specifies "Other clients"
  as the CA policy target, not "Exchange ActiveSync and Other clients"
- Section IV opens with a geographic authentication map (Figure IV-1)
  generated from Module 15 behavioral analysis data. Gold diamond
  markers appear only on countries confirmed as permanent offices in
  Question 4. Countries where only data subjects reside do not receive
  diamond markers. Flagged geographic signals (unexpected jurisdictions)
  are annotated with an arrow callout and "analyst review required".
  The figure caption correctly names all office locations shown.
- Appendix B is present and contains three subsections: (1) Assessment
  Tool with the GitHub URL
  https://github.com/sdshook/Tools/tree/main/ModernCRA/Entra attributed
  to Shane Shook, May 2026; (2) Microsoft Entra and Microsoft 365
  Documentation listing every learn.microsoft.com URL cited in the
  report; (3) Regulations, Statutes, and Standards compiled exclusively
  from the regulations, statutes, and frameworks actually cited in
  Sections V and VI of this specific report — not a static list, not a
  generic baseline. Every item in Section VI and every Standard /
  Regulation column entry in Section V must appear in the compiled list.
  No item appears in the list that was not cited in Sections V or VI.
  No URL in the references is truncated.

---
