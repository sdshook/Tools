# (c) 2025-2026 Shane D. Shook, PhD - All Rights Reserved

"""
ADVulture Analysis Module

Provides security analysis capabilities for:
- Entra ID (Azure AD)
- On-Premise Active Directory
- Hybrid Identity environments
"""

from advulture.analysis.finding import Finding, RiskClass, Severity
from advulture.analysis.behavioral import (
    BehavioralAnalyzer,
    ServiceAccountAnalyzer,
    AuthEvent,
    BehavioralAnomaly,
    normalize_entra_signin,
    normalize_windows_event,
    normalize_adfs_event,
)
from advulture.analysis.onprem_baseline import (
    OnPremSecurityBaseline,
    BaselineFinding,
)
from advulture.analysis.hybrid_monitor import (
    HybridIdentityAnalyzer,
    SyncAccountMonitor,
    SeamlessSSOMonitor,
    HybridSyncValidator,
    ADFSMonitor,
    HybridFinding,
)

__all__ = [
    # Core finding model
    "Finding",
    "RiskClass",
    "Severity",
    # Behavioral analysis
    "BehavioralAnalyzer",
    "ServiceAccountAnalyzer",
    "AuthEvent",
    "BehavioralAnomaly",
    "normalize_entra_signin",
    "normalize_windows_event",
    "normalize_adfs_event",
    # On-prem baseline
    "OnPremSecurityBaseline",
    "BaselineFinding",
    # Hybrid monitoring
    "HybridIdentityAnalyzer",
    "SyncAccountMonitor",
    "SeamlessSSOMonitor",
    "HybridSyncValidator",
    "ADFSMonitor",
    "HybridFinding",
]