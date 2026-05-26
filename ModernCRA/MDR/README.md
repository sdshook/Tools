# MDR Assessment Toolkit

<!-- (c) 2026, Shane D. Shook, PhD -->

This folder contains tools for conducting cyber risk assessments using Managed Detection and Response (MDR) platforms.

## Contents

### s1queries.txt

A comprehensive set of search queries designed to be executed against the SentinelOne Singularity XDR console. These queries extract security telemetry and risk indicators across five severity levels:

- **LVL1** - Data Transfer and Tool Risk (highest risk): Cloud storage, AI tools, USB usage
- **LVL2** - User Activity and Credential Risk: Profile propagation, credential theft, lateral movement
- **LVL3** - Network Risk: Tunnels, beacons, backdoors, suspicious DNS
- **LVL4** - Service and Configuration Risk: RMM tools, LOLBins, process injection, scheduled tasks
- **LVL5** - Build and Posture: OS versions, endpoint health, application inventory

Export the query results to the indicated CSV files for offline analysis.

### AnalysisPrompt.txt

A detailed prompt template for generating professional cyber risk assessment reports from the exported query results. This prompt guides the analysis process and ensures consistent, thorough reporting that includes:

- Executive summary for non-technical stakeholders
- Detailed technical findings organized by risk level
- OSINT threat correlation
- Priority remediation roadmap
- Supporting references and appendices

## Usage

1. Execute the queries from `s1queries.txt` against your SentinelOne console
2. Export results to the specified CSV filenames
3. Use the `AnalysisPrompt.txt` with your preferred AI assistant to generate the assessment report
4. Review and customize the generated report as needed for your client

## Notes

- Queries should be tailored according to the specific environment under evaluation
- Query syntax can be adapted for use with CrowdStrike or other SIEM platforms
- Data quality notes in the analysis prompt address known query limitations
