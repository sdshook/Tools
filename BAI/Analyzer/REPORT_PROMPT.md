# BAI Report Formatting Prompt

> © 2026, Shane Shook, All Rights Reserved. This tool is for testing and analysis.

Use this prompt with an AI assistant (Claude, ChatGPT, etc.) to generate a professionally formatted DOCX or PDF report from BAI Analyzer output files.

---

## Instructions

1. Run the BAI Analyzer to generate report files
2. Copy the prompt below
3. Attach the report files (`report.txt` or `report.html`, `identity_inventory.csv`, `findings.json`)
4. Submit to your preferred AI assistant
5. Download the generated document

---

## Prompt

```
You are a professional technical writer preparing a forensic investigation report. Generate a formatted Microsoft Word document (.docx) or PDF from the attached BAI (Browser Audit Inventory) analysis files.

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
   - Title: "Browser Audit Inventory - Forensic Analysis Report"
   - Subtitle: "Case: [case_id from report]"
   - Date: [collection timestamp]
   - Examiner: [examiner name]
   - Classification: "Privileged and Confidential - DRAFT Work Product"

   **TABLE OF CONTENTS**
   - Auto-generated with page numbers

   **1. EXECUTIVE SUMMARY**
   - 2-3 paragraph summary of findings
   - Overall risk assessment
   - Key recommendations

   **2. EVIDENCE PROVENANCE**
   - Collection metadata
   - Chain of custody
   - Integrity verification

   **3. SYSTEM CONTEXT**
   - Computer and browser information
   - Collection environment

   **4. IDENTITY INVENTORY**
   - Table of all accounts/identities discovered
   - Include: Identity, IdP, Domain, MFA Status, Token Types, Validity
   - Format as a professional table with borders

   **5. RISK ASSESSMENT**
   - Findings summary by severity
   - Detailed findings with recommendations

   **6. TIMELINE ANALYSIS**
   - Authentication timeline
   - Session theft timeline (if applicable)
   - Suspicious activity timeline

   **7. TECHNICAL APPENDIX**
   - Raw data references
   - Artifact inventory
   - Methodology notes

6. **Tables:**
   - Use professional table formatting with header row shading (light blue or gray)
   - Borders on all cells
   - Auto-fit to content width

7. **Code/Technical Content:**
   - Use Consolas or Courier New, 9pt
   - Light gray background shading for code blocks

8. **Color Coding for Severity:**
   - CRITICAL: Dark red text
   - HIGH: Red text
   - MEDIUM: Orange text
   - LOW: Dark yellow text
   - INFO: Blue text

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
    --reference-doc=bai_template.docx \
    --toc \
    --toc-depth=3 \
    -o BAI_Report.docx

# Convert to PDF (requires LaTeX)
pandoc report.txt \
    --from=markdown \
    --to=pdf \
    --toc \
    -V geometry:margin=1in \
    -V header-includes:'\usepackage{fancyhdr}\pagestyle{fancy}\fancyhead[C]{\textit{Privileged and Confidential - DRAFT Work Product}}' \
    -o BAI_Report.pdf
```

---

## Notes

- The AI prompt approach requires no additional software installation
- For bulk processing or automation, consider the Pandoc pipeline
- Always review AI-generated documents for accuracy before distribution
- The "DRAFT Work Product" classification should be updated as appropriate for final reports
