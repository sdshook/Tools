# AiTM Analyzer Report Formatting Prompt

> © 2026, Shane D. Shook, All Rights Reserved. This tool is for authorized testing and analysis.

Use this prompt with an AI assistant (Claude, ChatGPT, etc.) to generate a professionally formatted DOCX or PDF report from AiTM_analyzer output files.

---

## Instructions

1. Run the AiTM Analyzer to generate report files
2. Copy the prompt below
3. Attach the report files (`report.txt` or `report.html`, `identity_inventory.csv`, `findings.json`, and optionally `logs_report.txt`)
4. Submit to your preferred AI assistant
5. Download the generated document

---

## Prompt

```
You are a professional technical writer preparing a forensic investigation report. Generate a formatted Microsoft Word document (.docx) or PDF from the attached AiTM_analyzer analysis files.

**Document Requirements:**

1. **Header (all pages):**
   - Text: "Privileged and Confidential - DRAFT Work Product"
   - Font: Times New Roman, 10pt, italic
   - Alignment: Center
   - Include a thin horizontal line below the header text

2. **Footer (all pages):**
   - Text: "Page X of Y" where X is current page and Y is total pages
   - Font: Times New Roman, 10pt
   - Alignment: Center
   - Calculate X and Y dynamically for the final document

3. **Document Formatting:**
   - Font: Calibri 11pt for body, Calibri Bold 14pt for headings
   - Margins: 1 inch all sides
   - Line spacing: 1.15
   - Paragraph spacing: 6pt after

4. **Language Requirements:**
   - US English spelling (e.g., "analyze" not "analyse", "color" not "colour")
   - Correct grammar and punctuation throughout
   - Professional, objective tone appropriate for legal/forensic contexts
   - Fix any spelling, grammar, or punctuation errors in the source material

5. **Structure:**
   Organize the report with these sections (use the data from the attached files):

   **COVER PAGE**
   - Title: "AiTM / Token-Theft Forensic Analysis Report"
   - Subtitle: "Case: [case_id from report]"
   - Date: [collection/analysis timestamp]
   - Examiner: [examiner name]
   - Evidence Mode: [host, logs, or both]
   - Classification: "Privileged and Confidential - DRAFT Work Product"

   **TABLE OF CONTENTS**
   - Auto-generated with page numbers

   **1. EXECUTIVE SUMMARY**
   - 2-3 paragraph summary of findings
   - Evidence mode and what was analyzed
   - Token-grade confirmation status (if both mode)
   - Overall risk assessment
   - Key recommendations

   **2. EVIDENCE PROVENANCE**
   - Host evidence: BAI collection metadata, chain of custody, integrity verification
   - Log evidence: Log sources, date ranges, record counts
   - Correlation anchors (uti/sid extracted from host, pivoted into logs)

   **3. IDENTITY INVENTORY**
   - Table of all accounts/identities discovered
   - Include: UPN, Service, Type, Protection, Theft Risk
   - Microsoft Entra sessions with tenant/object IDs
   - Format as a professional table with borders

   **4. THREAT ACTOR ATTRIBUTION (if logs analyzed)**
   - Footprint analysis: TA IPs, ASNs, user agents
   - Hosting/VPS ASN indicators
   - Impossible travel detections
   - Replayed device claims

   **5. RISK ASSESSMENT**
   - Findings summary by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
   - Detailed findings with evidence and recommendations
   - AiTM indicators (proxy config, redirect chains, timing anomalies)
   - Infostealer indicators (sideloaded extensions, dangerous permissions)

   **6. TIMELINE ANALYSIS**
   - Session theft timeline with auth_time anchors
   - Token lineage: stolen token UTI/SID and theft window
   - Post-compromise activity timeline
   - Mail exfiltration inventory (if detected)
   - BEC inbox rule analysis (if detected)

   **7. CORRELATION GUIDANCE**
   - Token lineage limitations (no parent-child tracking in logs)
   - How to enumerate post-compromise UTIs
   - Queries for Entra sign-in logs and Purview UAL
   - 50199 error detection (token replay)

   **8. TECHNICAL APPENDIX**
   - Raw data references
   - Artifact inventory
   - ASN intelligence sources
   - Methodology notes

6. **Tables:**
   - Use professional table formatting with header row shading (light blue or gray)
   - Borders on all cells
   - Auto-fit to content width

7. **Code/Technical Content:**
   - Use Consolas or Courier New, 9pt
   - Light gray background shading for code blocks
   - GUIDs and token identifiers in monospace

8. **Color Coding for Severity:**
   - CRITICAL: Dark red text
   - HIGH: Red text
   - MEDIUM: Orange text
   - LOW: Dark yellow text
   - INFO: Blue text

9. **Token-Grade Confirmation Highlight:**
   - If a host-extracted UTI/SID was confirmed in logs, highlight this prominently
   - Use a call-out box with green border for confirmed replay

Please generate the complete formatted document based on the attached analysis files. Ensure all page numbers are correctly calculated and the document is ready for review.
```

---

## Alternative: Markdown to DOCX Pipeline

If you prefer a scripted approach, you can use Pandoc:

```bash
# Install pandoc (if not already installed)
# macOS: brew install pandoc
# Ubuntu: apt install pandoc
# Windows: choco install pandoc

# Convert report to DOCX with custom reference doc
pandoc report.txt \
    --from=markdown \
    --to=docx \
    --reference-doc=aitm_template.docx \
    --toc \
    --toc-depth=3 \
    -o AiTM_Report.docx

# Convert to PDF (requires LaTeX)
pandoc report.txt \
    --from=markdown \
    --to=pdf \
    --toc \
    -V geometry:margin=1in \
    -V header-includes:'\usepackage{fancyhdr}\pagestyle{fancy}\fancyhead[C]{\textit{Privileged and Confidential - DRAFT Work Product}}' \
    -o AiTM_Report.pdf
```

---

## Notes

- The AI prompt approach requires no additional software installation
- For bulk processing or automation, consider the Pandoc pipeline
- Always review AI-generated documents for accuracy before distribution
- The "DRAFT Work Product" classification should be updated as appropriate for final reports
- When using **both** mode, the report includes token-grade correlation — highlight this in the executive summary
