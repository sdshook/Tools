# (c) 2025 Shane D. Shook, PhD - All Rights Reserved
"""
ADVulture — Audit Module Tests
"""

from __future__ import annotations
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import os


class TestOfflineUser:
    """Test OfflineUser dataclass and property methods."""
    
    def test_user_enabled_flag(self):
        from advulture.audit import OfflineUser
        
        # Enabled user (UAC without ACCOUNTDISABLE)
        user = OfflineUser(
            sam_account_name="testuser",
            distinguished_name="CN=Test User,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1001",
            user_account_control=0x200,  # NORMAL_ACCOUNT only
        )
        assert user.enabled is True
        
        # Disabled user (UAC with ACCOUNTDISABLE = 0x0002)
        disabled_user = OfflineUser(
            sam_account_name="disableduser",
            distinguished_name="CN=Disabled User,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1002",
            user_account_control=0x202,  # NORMAL_ACCOUNT + ACCOUNTDISABLE
        )
        assert disabled_user.enabled is False
    
    def test_kerberoastable_detection(self):
        from advulture.audit import OfflineUser
        
        # Kerberoastable: enabled with SPN
        svc_account = OfflineUser(
            sam_account_name="svc_sql",
            distinguished_name="CN=SQL Service,OU=Services,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-2001",
            user_account_control=0x200,
            service_principal_names=["MSSQLSvc/sql01.corp.local:1433"],
        )
        assert svc_account.is_kerberoastable is True
        
        # Not Kerberoastable: no SPN
        regular_user = OfflineUser(
            sam_account_name="regularuser",
            distinguished_name="CN=Regular User,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1003",
            user_account_control=0x200,
            service_principal_names=[],
        )
        assert regular_user.is_kerberoastable is False
        
        # Not Kerberoastable: disabled even with SPN
        disabled_svc = OfflineUser(
            sam_account_name="svc_old",
            distinguished_name="CN=Old Service,OU=Services,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-2002",
            user_account_control=0x202,  # Disabled
            service_principal_names=["HTTP/old.corp.local"],
        )
        assert disabled_svc.is_kerberoastable is False
    
    def test_asrep_roastable_detection(self):
        from advulture.audit import OfflineUser
        
        # AS-REP Roastable: DONT_REQ_PREAUTH = 0x400000
        asrep_user = OfflineUser(
            sam_account_name="asrepuser",
            distinguished_name="CN=ASREP User,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1004",
            user_account_control=0x400200,  # NORMAL + DONT_REQ_PREAUTH
        )
        assert asrep_user.is_asrep_roastable is True
        assert asrep_user.dont_require_preauth is True
        
        # Not AS-REP Roastable: preauth required
        normal_user = OfflineUser(
            sam_account_name="normaluser",
            distinguished_name="CN=Normal User,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1005",
            user_account_control=0x200,
        )
        assert normal_user.is_asrep_roastable is False
    
    def test_password_age_calculation(self):
        from advulture.audit import OfflineUser
        
        # User with recent password change
        recent_pwd = OfflineUser(
            sam_account_name="recentpwd",
            distinguished_name="CN=Recent,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1006",
            user_account_control=0x200,
            pwd_last_set=datetime.now(timezone.utc) - timedelta(days=30),
        )
        assert recent_pwd.password_age_days is not None
        assert 29 <= recent_pwd.password_age_days <= 31
        
        # User with no password set date
        no_pwd_date = OfflineUser(
            sam_account_name="nopwddate",
            distinguished_name="CN=NoPwdDate,OU=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1007",
            user_account_control=0x200,
            pwd_last_set=None,
        )
        assert no_pwd_date.password_age_days is None
    
    def test_delegation_flags(self):
        from advulture.audit import OfflineUser
        
        # User trusted for delegation (0x80000)
        delegated = OfflineUser(
            sam_account_name="svc_delegated",
            distinguished_name="CN=Delegated,OU=Services,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-2003",
            user_account_control=0x80200,  # TRUSTED_FOR_DELEGATION
        )
        assert delegated.trusted_for_delegation is True


class TestOfflineComputer:
    """Test OfflineComputer dataclass."""
    
    def test_domain_controller_detection(self):
        from advulture.audit import OfflineComputer
        
        # Domain Controller (SERVER_TRUST_ACCOUNT = 0x2000)
        dc = OfflineComputer(
            sam_account_name="DC01$",
            distinguished_name="CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-1000",
            user_account_control=0x82000,  # DC + TRUSTED_FOR_DELEGATION
            operating_system="Windows Server 2022 Datacenter",
        )
        assert dc.is_domain_controller is True
        
        # Regular server
        server = OfflineComputer(
            sam_account_name="SERVER01$",
            distinguished_name="CN=SERVER01,OU=Servers,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-3001",
            user_account_control=0x1000,  # WORKSTATION_TRUST_ACCOUNT
            operating_system="Windows Server 2022 Standard",
        )
        assert server.is_domain_controller is False
    
    def test_unconstrained_delegation(self):
        from advulture.audit import OfflineComputer
        
        # Computer with unconstrained delegation
        unconstrained = OfflineComputer(
            sam_account_name="APP01$",
            distinguished_name="CN=APP01,OU=Servers,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-3002",
            user_account_control=0x81000,  # TRUSTED_FOR_DELEGATION
        )
        assert unconstrained.trusted_for_delegation is True


class TestOfflineGroup:
    """Test OfflineGroup dataclass."""
    
    def test_privileged_group_detection(self):
        from advulture.audit import OfflineGroup
        
        # Domain Admins (ends with -512)
        domain_admins = OfflineGroup(
            sam_account_name="Domain Admins",
            distinguished_name="CN=Domain Admins,CN=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-512",
        )
        assert domain_admins.is_privileged is True
        
        # Enterprise Admins (ends with -519)
        enterprise_admins = OfflineGroup(
            sam_account_name="Enterprise Admins",
            distinguished_name="CN=Enterprise Admins,CN=Users,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-519",
        )
        assert enterprise_admins.is_privileged is True
        
        # Regular group
        regular_group = OfflineGroup(
            sam_account_name="IT Support",
            distinguished_name="CN=IT Support,OU=Groups,DC=corp,DC=local",
            sid="S-1-5-21-1234-5678-9012-5001",
        )
        assert regular_group.is_privileged is False
        
        # Group with adminCount=1
        protected_group = OfflineGroup(
            sam_account_name="Server Operators",
            distinguished_name="CN=Server Operators,CN=Builtin,DC=corp,DC=local",
            sid="S-1-5-32-549",
            admin_count=1,
        )
        assert protected_group.is_privileged is True


class TestAuditFinding:
    """Test AuditFinding dataclass."""
    
    def test_finding_to_dict(self):
        from advulture.audit import AuditFinding
        
        finding = AuditFinding(
            category="kerberoast",
            title="Kerberoastable Accounts: 5",
            severity="HIGH",
            description="Service accounts with SPNs are vulnerable.",
            affected_objects=["svc_sql", "svc_iis", "svc_app", "svc_web", "svc_db"],
            recommendations=["Convert to gMSA", "Enable AES encryption"],
            mitre_techniques=["T1558.003"],
        )
        
        result = finding.to_dict()
        
        assert result["category"] == "kerberoast"
        assert result["severity"] == "HIGH"
        assert result["affected_count"] == 5
        assert len(result["recommendations"]) == 2
        assert "T1558.003" in result["mitre_techniques"]


class TestAuditReport:
    """Test AuditReport dataclass."""
    
    def test_severity_counting(self):
        from advulture.audit import AuditReport, AuditFinding, OfflineSnapshot
        
        snapshot = OfflineSnapshot(
            domain="corp.local",
            domain_sid="S-1-5-21-1234-5678-9012",
            forest_name="corp.local",
            functional_level="2016",
            timestamp=datetime.now(timezone.utc),
            ntds_path="/test/ntds.dit",
        )
        
        findings = [
            AuditFinding(category="a", title="Critical 1", severity="CRITICAL", description=""),
            AuditFinding(category="b", title="Critical 2", severity="CRITICAL", description=""),
            AuditFinding(category="c", title="High 1", severity="HIGH", description=""),
            AuditFinding(category="d", title="Medium 1", severity="MEDIUM", description=""),
            AuditFinding(category="e", title="Medium 2", severity="MEDIUM", description=""),
            AuditFinding(category="f", title="Low 1", severity="LOW", description=""),
        ]
        
        report = AuditReport(
            timestamp=datetime.now(timezone.utc),
            snapshot=snapshot,
            findings=findings,
        )
        
        report.compute_counts()
        
        assert report.critical_count == 2
        assert report.high_count == 1
        assert report.medium_count == 2
        assert report.low_count == 1
    
    def test_report_summary(self):
        from advulture.audit import AuditReport, OfflineSnapshot, OfflineUser
        
        snapshot = OfflineSnapshot(
            domain="corp.local",
            domain_sid="S-1-5-21-1234-5678-9012",
            forest_name="corp.local",
            functional_level="2016",
            timestamp=datetime.now(timezone.utc),
            ntds_path="/test/ntds.dit",
            users=[
                OfflineUser(sam_account_name="user1", distinguished_name="", sid="", user_account_control=0x200),
                OfflineUser(sam_account_name="user2", distinguished_name="", sid="", user_account_control=0x200),
            ],
        )
        
        report = AuditReport(
            timestamp=datetime.now(timezone.utc),
            snapshot=snapshot,
            findings=[],
        )
        
        summary = report.summary()
        assert "corp.local" in summary
        assert "Users: 2" in summary


class TestOfflineAuditor:
    """Test OfflineAuditor functionality."""
    
    def test_kerberoastable_audit(self):
        from advulture.audit import OfflineAuditor, OfflineSnapshot, OfflineUser
        
        auditor = OfflineAuditor()
        
        # Create test snapshot with kerberoastable accounts
        auditor.snapshot = OfflineSnapshot(
            domain="corp.local",
            domain_sid="S-1-5-21-1234-5678-9012",
            forest_name="corp.local",
            functional_level="2016",
            timestamp=datetime.now(timezone.utc),
            ntds_path="/test/ntds.dit",
            users=[
                # Privileged kerberoastable
                OfflineUser(
                    sam_account_name="svc_admin",
                    distinguished_name="CN=Admin Svc,OU=Services,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-2001",
                    user_account_control=0x200,
                    admin_count=1,
                    service_principal_names=["HTTP/admin.corp.local"],
                ),
                # Regular kerberoastable
                OfflineUser(
                    sam_account_name="svc_web",
                    distinguished_name="CN=Web Svc,OU=Services,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-2002",
                    user_account_control=0x200,
                    admin_count=0,
                    service_principal_names=["HTTP/web.corp.local"],
                ),
                # Not kerberoastable (no SPN)
                OfflineUser(
                    sam_account_name="normaluser",
                    distinguished_name="CN=Normal,OU=Users,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-1001",
                    user_account_control=0x200,
                    service_principal_names=[],
                ),
            ],
        )
        
        findings = auditor._audit_kerberoastable()
        
        # Should find both privileged and regular kerberoastable
        assert len(findings) == 2
        
        # Check privileged finding
        priv_finding = next((f for f in findings if f.category == "kerberoast_privileged"), None)
        assert priv_finding is not None
        assert priv_finding.severity == "CRITICAL"
        assert "svc_admin" in priv_finding.affected_objects
        
        # Check regular finding
        std_finding = next((f for f in findings if f.category == "kerberoast_standard"), None)
        assert std_finding is not None
        assert std_finding.severity == "HIGH"
    
    def test_asrep_roastable_audit(self):
        from advulture.audit import OfflineAuditor, OfflineSnapshot, OfflineUser
        
        auditor = OfflineAuditor()
        
        auditor.snapshot = OfflineSnapshot(
            domain="corp.local",
            domain_sid="S-1-5-21-1234-5678-9012",
            forest_name="corp.local",
            functional_level="2016",
            timestamp=datetime.now(timezone.utc),
            ntds_path="/test/ntds.dit",
            users=[
                # AS-REP roastable
                OfflineUser(
                    sam_account_name="asrepuser",
                    distinguished_name="CN=ASREP,OU=Users,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-1001",
                    user_account_control=0x400200,  # DONT_REQ_PREAUTH
                ),
                # Normal user
                OfflineUser(
                    sam_account_name="normaluser",
                    distinguished_name="CN=Normal,OU=Users,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-1002",
                    user_account_control=0x200,
                ),
            ],
        )
        
        findings = auditor._audit_asrep_roastable()
        
        assert len(findings) == 1
        assert findings[0].category == "asrep_roast"
        assert findings[0].severity == "HIGH"
        assert "asrepuser" in findings[0].affected_objects
        assert "T1558.004" in findings[0].mitre_techniques
    
    def test_unconstrained_delegation_audit(self):
        from advulture.audit import OfflineAuditor, OfflineSnapshot, OfflineComputer
        
        auditor = OfflineAuditor()
        
        auditor.snapshot = OfflineSnapshot(
            domain="corp.local",
            domain_sid="S-1-5-21-1234-5678-9012",
            forest_name="corp.local",
            functional_level="2016",
            timestamp=datetime.now(timezone.utc),
            ntds_path="/test/ntds.dit",
            computers=[
                # Domain Controller (unconstrained delegation is expected)
                OfflineComputer(
                    sam_account_name="DC01$",
                    distinguished_name="CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-1000",
                    user_account_control=0x82000,  # DC + TRUSTED_FOR_DELEGATION
                ),
                # Non-DC with unconstrained delegation (bad!)
                OfflineComputer(
                    sam_account_name="APP01$",
                    distinguished_name="CN=APP01,OU=Servers,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-3001",
                    user_account_control=0x81000,  # TRUSTED_FOR_DELEGATION
                ),
                # Normal server
                OfflineComputer(
                    sam_account_name="WEB01$",
                    distinguished_name="CN=WEB01,OU=Servers,DC=corp,DC=local",
                    sid="S-1-5-21-1234-5678-9012-3002",
                    user_account_control=0x1000,
                ),
            ],
        )
        
        findings = auditor._audit_unconstrained_delegation()
        
        # Should only flag non-DC with unconstrained delegation
        assert len(findings) == 1
        assert findings[0].category == "computer_unconstrained_delegation"
        assert findings[0].severity == "CRITICAL"
        assert "APP01$" in findings[0].affected_objects
        # DC should NOT be flagged
        assert "DC01$" not in findings[0].affected_objects


class TestRunAuditFunction:
    """Test the run_audit convenience function."""
    
    def test_run_audit_with_no_files(self):
        """Should handle gracefully when no valid files provided."""
        from advulture.audit import run_audit
        
        # This should not crash even with non-existent file
        # (since we catch the NTDSParseError in the function)
        with pytest.raises(Exception):
            # Expected to fail since file doesn't exist
            run_audit(ntds_path="/nonexistent/ntds.dit")
