/*
   WebGuard YARA Rules
   Generated: 2025-11-24 16:06:06
   Source: WebGuard Experiential Learning
*/


rule WebGuard_Pattern_1
{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "1.00"
        threat_score = "1.00"
        source = "WebGuard Experiential Learning"
        discovery_method = "ThreatValidation"
        validation_count = "11"
        tags = "lfi,traversal"
        created = "2025-11-24"
    
    strings:
        $pattern = "../../../etc/passwd" nocase
        $pattern_encoded = "\.\./\.\./\.\./etc/passwd" nocase
    
    condition:
        any of ($pattern*)
}

rule WebGuard_Pattern_2
{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "1.00"
        threat_score = "1.00"
        source = "WebGuard Experiential Learning"
        discovery_method = "ThreatValidation"
        validation_count = "11"
        tags = "sql,union"
        created = "2025-11-24"
    
    strings:
        $pattern = "UNION SELECT * FROM users" nocase
        $pattern_encoded = "UNION(\s|%20|\+)SELECT(\s|%20|\+)\*(\s|%20|\+)FROM(\s|%20|\+)users" nocase
    
    condition:
        any of ($pattern*)
}

rule WebGuard_Pattern_3
{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "1.00"
        threat_score = "1.00"
        source = "WebGuard Experiential Learning"
        discovery_method = "ThreatValidation"
        validation_count = "11"
        tags = "sql,injection"
        created = "2025-11-24"
    
    strings:
        $pattern = "' OR 1=1 --" nocase
        $pattern_encoded = "'(\s|%20|\+)OR(\s|%20|\+)1=1(\s|%20|\+)\-\-" nocase
    
    condition:
        any of ($pattern*)
}

rule WebGuard_Pattern_4
{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "1.00"
        threat_score = "1.00"
        source = "WebGuard Experiential Learning"
        discovery_method = "ThreatValidation"
        validation_count = "11"
        tags = "xss,javascript"
        created = "2025-11-24"
    
    strings:
        $pattern = "<script>alert('xss')</script>" nocase
        $pattern_encoded = "<script>alert\('xss'\)</script>" nocase
    
    condition:
        any of ($pattern*)
}

rule WebGuard_Pattern_5
{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "1.00"
        threat_score = "1.00"
        source = "WebGuard Experiential Learning"
        discovery_method = "ThreatValidation"
        validation_count = "11"
        tags = "xss,javascript"
        created = "2025-11-24"
    
    strings:
        $pattern = "javascript:alert(1)" nocase
        $pattern_encoded = "javascript:alert\(1\)" nocase
    
    condition:
        any of ($pattern*)
}