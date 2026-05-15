# Forgepoint Capital Entra ID Security Assessment

## Report Generation Prompt

You are a cybersecurity consultant preparing a formal security assessment report. Using the data and findings below, create a professional report with the following requirements:

**Formatting Requirements:**
- Use US English spelling and grammar
- Do not use em dashes or double dashes; use commas, semicolons, or separate sentences instead
- Use proper punctuation throughout
- Structure with clear headings, subheadings, and numbered sections
- Include an executive summary suitable for C-level executives
- Provide technical details suitable for IT security teams
- Include actionable recommendations with priority rankings

**Report Structure:**
1. Executive Summary
2. Scope and Methodology
3. Key Findings Summary
4. Detailed Findings
5. Risk Assessment Matrix
6. Recommendations and Remediation Plan
7. Appendices (data tables)

---

## Assessment Metadata

**Organization:** Forgepoint Capital  
**Assessment Date:** May 14, 2026  
**Assessment Type:** Microsoft Entra ID (Azure Active Directory) Security Posture Assessment  
**Tool Used:** ADVulture v1.0  
**Assessor Permissions:** Security Reader, Reports Reader, Authentication Administrator  
**Assessment Scope:** Cloud-only Entra ID tenant; no on-premises Active Directory hybrid  

---

## Data Collection Summary

### Enumeration Results

| Data Category | Count | Notes |
|---------------|-------|-------|
| Total Users | 103 | All user accounts in tenant |
| Enabled Users | ~100 | Accounts with active sign-in capability |
| Service Principals | 100 | Application registrations and managed identities |
| Directory Role Definitions | 143 | Built-in and custom Entra ID roles |
| Active Role Assignments | 97 | Users, groups, and service principals with assigned roles |
| Privileged Role Types | 19 | Roles classified as high privilege |
| OAuth Permission Grants | 107 | Third-party application consent grants |
| Conditional Access Policies | 0 (access denied) | Requires additional permissions to enumerate |
| PIM Eligible Assignments | 0 (access denied) | Requires Privileged Role Administrator |

### Log Collection Results (7-Day Window: May 7-14, 2026)

| Log Type | Count | Notes |
|----------|-------|-------|
| Sign-in Events | 895 | Interactive and non-interactive authentications |
| Directory Audit Events | 113 | Administrative and configuration changes |
| Identity Risk Detections | 2 | Identity Protection alerts (limited data due to API issue) |

---

## MFA Registration Analysis

### Overall MFA Posture

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Users Analyzed | 103 | 100% |
| Users with MFA Registered | 33 | 32% |
| Users with Strong MFA | 33 | 32% |
| Users with Weak MFA Only | 1 | 1% |
| Users WITHOUT Any MFA | 70 | 68% |

### MFA Method Distribution

**Strong MFA Methods (Phishing-Resistant):**
- Microsoft Authenticator App
- FIDO2 Security Keys
- Windows Hello for Business
- Software OATH Tokens (TOTP)

**Weak MFA Methods (Vulnerable to Phishing/SIM Swap):**
- SMS Text Message
- Email OTP

### Sample User MFA Status

| User Principal Name | MFA Registered | Strong MFA | Methods |
|---------------------|----------------|------------|---------|
| aandreu@forgepointcap.com | Yes | Yes | Authenticator, TOTP |
| amacdonald@forgepointcap.com | Yes | Yes | Windows Hello, Authenticator, TOTP |
| amcclure@forgepointcap.com | Yes | Yes | Windows Hello, Phone, Authenticator, TOTP |
| admin.sshook@forgepointcap.com | No | No | None |
| aiyer@forgepointcap.com | No | No | None |

---

## Privileged Role Analysis

### Role Assignment Summary

The tenant has 97 active role assignments across 143 defined roles. Of these, 19 roles are classified as high privilege based on their ability to:
- Modify directory configuration
- Access sensitive data
- Manage other privileged accounts
- Control authentication policies

### High-Privilege Roles Identified

1. Global Administrator
2. Privileged Role Administrator
3. Privileged Authentication Administrator
4. Security Administrator
5. User Administrator
6. Exchange Administrator
7. SharePoint Administrator
8. Intune Administrator
9. Application Administrator
10. Cloud Application Administrator
11. Authentication Administrator
12. Helpdesk Administrator
13. Password Administrator
14. Groups Administrator
15. License Administrator
16. Directory Writers
17. Directory Synchronization Accounts
18. Partner Tier1 Support
19. Partner Tier2 Support

### Principals with Multiple Privileged Roles

Analysis identified principals holding three or more privileged roles, which violates the principle of least privilege and increases the blast radius of account compromise.

---

## Service Principal Analysis

### Overview

- Total Service Principals: 100
- Service Principals with Privileged Roles: Multiple identified

Service principals (applications) with privileged directory roles represent a significant risk because:
1. They often have credentials stored in code or configuration
2. They may not be subject to the same access reviews as user accounts
3. Compromise provides persistent, often unmonitored access

---

## OAuth Consent Grant Analysis

### Overview

- Total OAuth Permission Grants: 107

OAuth consent grants allow third-party applications to access organizational data on behalf of users. High-risk scopes include:
- Mail.ReadWrite / Mail.ReadWrite.All
- Files.ReadWrite.All
- Directory.ReadWrite.All
- User.ReadWrite.All

These grants should be reviewed to ensure:
1. The application is still in use
2. The permissions are necessary for the application's function
3. The application vendor is trusted

---

## Sign-in Activity Analysis (7 Days)

### Summary

- Total Sign-in Events: 895
- Audit Events: 113
- Risk Detections: 2

### Authentication Patterns

Sign-in logs should be analyzed for:
- Legacy authentication protocol usage (bypasses MFA)
- Sign-ins from unexpected geographic locations
- Sign-ins at unusual times
- Failed authentication attempts (potential brute force)
- Risky sign-ins flagged by Identity Protection

---

## Security Findings

### Finding 1: Critical MFA Gap

**Severity:** CRITICAL  
**Category:** Authentication Security  
**CVSS-Like Score:** 9.0/10  

**Description:**  
70 of 103 users (68%) have no multi-factor authentication methods registered. This leaves the majority of user accounts protected only by passwords, which are vulnerable to:
- Phishing attacks
- Credential stuffing
- Password spray attacks
- Brute force attacks

**Impact:**  
An attacker who obtains a user password through any means can immediately access the account and all associated organizational data without any additional authentication challenge.

**Affected Users:** 70 users including:
- admin.sshook@forgepointcap.com (ADMIN ACCOUNT)
- aiyer@forgepointcap.com
- Multiple other standard user accounts

**Recommendation:**  
1. Implement a mandatory MFA enrollment policy immediately
2. Use Conditional Access to require MFA for all sign-ins
3. Prioritize privileged accounts for immediate enrollment
4. Consider Security Defaults if Conditional Access is not available

---

### Finding 2: Administrative Account Without MFA

**Severity:** HIGH  
**Category:** Privileged Access Management  
**CVSS-Like Score:** 8.5/10  

**Description:**  
The administrative account admin.sshook@forgepointcap.com has privileged role assignments but no MFA methods registered. Administrative accounts are high-value targets for attackers.

**Impact:**  
Compromise of this account would provide an attacker with elevated privileges to:
- Modify tenant configuration
- Access sensitive data
- Create persistence mechanisms
- Compromise other accounts

**Recommendation:**  
1. Immediately enroll this account in phishing-resistant MFA (FIDO2 or Windows Hello)
2. Review all role assignments for this account
3. Consider using Privileged Identity Management (PIM) for just-in-time access
4. Implement break-glass account procedures

---

### Finding 3: Excessive Privileged Role Assignments

**Severity:** HIGH  
**Category:** Identity Governance  
**CVSS-Like Score:** 7.5/10  

**Description:**  
The tenant has 97 active role assignments across 19 privileged role types. The user noted that 27 privileged roles seemed excessive for the organization's size and needs.

**Impact:**  
Excessive privileged access:
- Increases the attack surface
- Violates least privilege principles
- Makes access reviews more complex
- Increases the impact of any single account compromise

**Recommendation:**  
1. Conduct a comprehensive access review of all privileged role assignments
2. Remove unnecessary role assignments
3. Implement role-based access control with minimal permissions
4. Use PIM for just-in-time privileged access
5. Establish a regular access review cadence (quarterly recommended)

---

### Finding 4: Service Principals with Privileged Roles

**Severity:** MEDIUM  
**Category:** Application Security  
**CVSS-Like Score:** 6.5/10  

**Description:**  
Multiple service principals have been assigned privileged directory roles. These automated accounts often have credentials stored in application configurations.

**Impact:**  
- Credentials may be exposed in source code or configuration files
- Service principals may not be subject to regular access reviews
- Compromise provides persistent access without MFA challenges

**Recommendation:**  
1. Audit all service principal role assignments
2. Apply least privilege; remove unnecessary permissions
3. Use managed identities where possible instead of client secrets
4. Implement credential rotation policies
5. Monitor service principal sign-in activity

---

### Finding 5: Unreviewed OAuth Consent Grants

**Severity:** MEDIUM  
**Category:** Data Protection  
**CVSS-Like Score:** 6.0/10  

**Description:**  
107 OAuth permission grants exist in the tenant. These grants allow third-party applications to access organizational data.

**Impact:**  
- Malicious or compromised applications can exfiltrate data
- Overly permissive grants expose more data than necessary
- Unused grants represent unnecessary risk

**Recommendation:**  
1. Review all OAuth consent grants
2. Revoke grants for applications no longer in use
3. Reduce permissions to minimum required
4. Implement admin consent workflow for new applications
5. Block user consent for high-risk permissions

---

### Finding 6: Weak MFA Methods in Use

**Severity:** MEDIUM  
**Category:** Authentication Security  
**CVSS-Like Score:** 5.5/10  

**Description:**  
One user has only weak MFA methods (SMS or email) registered. These methods are vulnerable to:
- SIM swapping attacks
- Email account compromise
- SS7 protocol vulnerabilities
- Real-time phishing (adversary-in-the-middle)

**Recommendation:**  
1. Migrate users from SMS/email MFA to phishing-resistant methods
2. Disable SMS and email as MFA options in authentication methods policy
3. Provide FIDO2 security keys to users who cannot use Authenticator app

---

### Finding 7: Conditional Access Policy Enumeration Failed

**Severity:** INFO  
**Category:** Assessment Limitation  

**Description:**  
The assessment was unable to enumerate Conditional Access policies due to insufficient permissions (403 Forbidden). This limits the ability to assess authentication policy coverage.

**Recommendation:**  
1. Grant Security Reader access to Conditional Access policies
2. Alternatively, provide a manual export of CA policies for review
3. Rerun assessment with appropriate permissions

---

## Risk Assessment Matrix

| Finding | Likelihood | Impact | Overall Risk | Priority |
|---------|------------|--------|--------------|----------|
| Users Without MFA (68%) | High | Critical | Critical | P1 |
| Admin Account Without MFA | High | Critical | Critical | P1 |
| Excessive Privileged Roles | Medium | High | High | P2 |
| Service Principal Privileges | Medium | Medium | Medium | P3 |
| Unreviewed OAuth Grants | Medium | Medium | Medium | P3 |
| Weak MFA Methods | Low | Medium | Low | P4 |

---

## Remediation Roadmap

### Immediate Actions (Week 1)

1. **Enable MFA for admin.sshook@forgepointcap.com**
   - Register FIDO2 security key or Windows Hello
   - Verify MFA is working before proceeding

2. **Implement Security Defaults or Basic Conditional Access**
   - Require MFA for all users
   - Block legacy authentication

3. **Communicate MFA Rollout to Users**
   - Provide enrollment instructions
   - Set enrollment deadline

### Short-Term Actions (Weeks 2-4)

4. **Complete MFA Enrollment for All Users**
   - Track enrollment progress
   - Follow up with non-compliant users
   - Escalate to management if needed

5. **Review Privileged Role Assignments**
   - Document current state
   - Identify unnecessary assignments
   - Create removal plan

6. **Review OAuth Consent Grants**
   - Identify unused applications
   - Revoke unnecessary grants

### Medium-Term Actions (Months 2-3)

7. **Implement Privileged Identity Management**
   - Convert permanent assignments to eligible
   - Require justification for activation
   - Set time-limited access

8. **Establish Access Review Processes**
   - Quarterly reviews for privileged roles
   - Annual reviews for standard access
   - Automated reminders and escalation

9. **Migrate Away from Weak MFA**
   - Disable SMS/email MFA options
   - Provide alternative methods

---

## Appendix A: User MFA Status (Partial List)

| User | Account Enabled | MFA Registered | MFA Capable | Methods |
|------|-----------------|----------------|-------------|---------|
| admin.sshook@forgepointcap.com | Yes | No | No | None |
| aandreu@forgepointcap.com | Yes | Yes | Yes | Authenticator, TOTP |
| aiyer@forgepointcap.com | Yes | No | No | None |
| amacdonald@forgepointcap.com | Yes | Yes | Yes | WHfB, Authenticator, TOTP |
| amcclure@forgepointcap.com | Yes | Yes | Yes | WHfB, Phone, Authenticator, TOTP |

(Full list of 103 users available upon request)

---

## Appendix B: Role Definitions Summary

- Total Role Definitions: 143
- Built-in Roles: ~130
- Custom Roles: ~13
- High-Privilege Roles: 19

---

## Appendix C: Assessment Permissions Used

| Permission | Purpose |
|------------|---------|
| Security Reader | Read security configuration and logs |
| Reports Reader | Access MFA registration reports |
| Authentication Administrator | Read authentication method details |

**Permissions Not Available (Caused Limitations):**
- Conditional Access Administrator (CA policy enumeration)
- Privileged Role Administrator (PIM assignment enumeration)

---

## End of Assessment Data

Please generate a professional security assessment report using this data. The report should be suitable for presentation to executive leadership and the IT security team. Include specific, actionable recommendations with clear ownership and timelines.
