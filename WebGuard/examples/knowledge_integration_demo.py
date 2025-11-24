#!/usr/bin/env python3
"""
WebGuard Knowledge Integration Demo

This script demonstrates how to load and integrate WebGuard's exported
knowledge into various security systems including ModSecurity, Snort,
YARA, and SIEM platforms.
"""

import json
import re
import time
from typing import Dict, List, Any
from datetime import datetime

class WebGuardKnowledgeAdapter:
    """Adapter for converting WebGuard knowledge to various security system formats"""
    
    def __init__(self, knowledge_file: str):
        """Load WebGuard knowledge from exported JSON file"""
        with open(knowledge_file, 'r') as f:
            self.knowledge = json.load(f)
        
        self.patterns = self._extract_high_confidence_patterns()
        print(f"📚 Loaded {len(self.patterns)} high-confidence patterns from WebGuard")
        
    def _extract_high_confidence_patterns(self) -> List[Dict[str, Any]]:
        """Extract patterns with high confidence for use in other systems"""
        patterns = []
        
        for pattern_id, pattern_data in self.knowledge.get('patterns', {}).items():
            if pattern_data.get('confidence', 0) > 0.75:
                patterns.append({
                    'id': pattern_id,
                    'pattern': pattern_data['pattern'],
                    'threat_score': pattern_data['threat_weight'],
                    'confidence': pattern_data['confidence'],
                    'tags': pattern_data.get('context_tags', []),
                    'validation_count': pattern_data.get('validation_count', 0),
                    'success_rate': pattern_data.get('success_rate', 0),
                    'discovery_method': pattern_data.get('discovery_method', 'Unknown'),
                    'regex': self._convert_to_regex(pattern_data['pattern'])
                })
        
        return patterns
    
    def _convert_to_regex(self, pattern: str) -> str:
        """Convert WebGuard pattern to regex for other systems"""
        # Escape special regex characters
        escaped = re.escape(pattern)
        
        # Allow for URL encoding variations
        escaped = escaped.replace(r'\ ', r'(\s|%20|\+)')
        escaped = escaped.replace(r'\'', r'(\'|%27)')
        escaped = escaped.replace(r'\"', r'(\"|%22)')
        escaped = escaped.replace(r'\<', r'(\<|%3C)')
        escaped = escaped.replace(r'\>', r'(\>|%3E)')
        
        return escaped
    
    def generate_modsecurity_rules(self) -> str:
        """Generate ModSecurity rules from learned patterns"""
        rules = []
        rule_id = 100000
        
        print("\n🛡️  Generating ModSecurity Rules")
        print("=" * 40)
        
        for pattern in self.patterns:
            if pattern['threat_score'] > 0.6:
                # Determine severity based on threat score and confidence
                if pattern['threat_score'] > 0.9 and pattern['confidence'] > 0.9:
                    severity = 'CRITICAL'
                    action = 'deny'
                elif pattern['threat_score'] > 0.7:
                    severity = 'ERROR'
                    action = 'block'
                else:
                    severity = 'WARNING'
                    action = 'log'
                
                # Create ModSecurity rule
                rule = f'''
# WebGuard Learned Pattern: {pattern['id']}
# Confidence: {pattern['confidence']:.2f} | Success Rate: {pattern['success_rate']:.2f}
# Discovery Method: {pattern['discovery_method']} | Validations: {pattern['validation_count']}
SecRule ARGS "@contains {pattern['pattern']}" \\
    "id:{rule_id},\\
     phase:2,\\
     {action},\\
     msg:'WebGuard Learned Threat: {pattern['pattern'][:50]}...',\\
     logdata:'Pattern confidence: {pattern['confidence']:.2f}, Success rate: {pattern['success_rate']:.2f}',\\
     severity:'{severity}',\\
     tag:'webguard-learned',\\
     tag:'attack-{pattern['tags'][0] if pattern['tags'] else 'generic'}',\\
     tag:'confidence-{int(pattern['confidence'] * 100)}'\\
     "
'''
                rules.append(rule)
                print(f"  ✅ Rule {rule_id}: {pattern['pattern'][:30]}... (confidence: {pattern['confidence']:.2f})")
                rule_id += 1
        
        return '\n'.join(rules)
    
    def generate_snort_rules(self) -> str:
        """Generate Snort rules from learned patterns"""
        rules = []
        sid = 1000000
        
        print("\n🔍 Generating Snort Rules")
        print("=" * 30)
        
        for pattern in self.patterns:
            if pattern['threat_score'] > 0.7:
                # Determine priority based on confidence and threat score
                priority = 1 if pattern['confidence'] > 0.9 else 2 if pattern['confidence'] > 0.8 else 3
                
                # Create content match with case insensitive option
                content_match = pattern['pattern'].replace('"', '\\"')
                
                rule = (f'alert tcp any any -> any any ('
                       f'msg:"WebGuard Learned Pattern: {pattern["id"][:30]}"; '
                       f'content:"{content_match}"; nocase; '
                       f'priority:{priority}; '
                       f'sid:{sid}; rev:1; '
                       f'metadata:policy balanced-ips drop, '
                       f'policy security-ips alert, '
                       f'webguard_confidence {pattern["confidence"]:.2f};)')
                
                rules.append(rule)
                print(f"  ✅ SID {sid}: {pattern['pattern'][:30]}... (priority: {priority})")
                sid += 1
        
        return '\n'.join(rules)
    
    def generate_yara_rules(self) -> str:
        """Generate YARA rules from learned patterns"""
        rules = []
        
        print("\n🎯 Generating YARA Rules")
        print("=" * 25)
        
        for i, pattern in enumerate(self.patterns):
            if pattern['threat_score'] > 0.8:
                # Clean pattern ID for YARA rule name
                rule_name = f"WebGuard_Pattern_{i+1}"
                
                rule = f'''
rule {rule_name}
{{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "{pattern['confidence']:.2f}"
        threat_score = "{pattern['threat_score']:.2f}"
        source = "WebGuard Experiential Learning"
        discovery_method = "{pattern['discovery_method']}"
        validation_count = "{pattern['validation_count']}"
        tags = "{','.join(pattern['tags'])}"
        created = "{datetime.now().strftime('%Y-%m-%d')}"
    
    strings:
        $pattern = "{pattern['pattern']}" nocase
        $pattern_encoded = "{pattern['regex']}" nocase
    
    condition:
        any of ($pattern*)
}}'''
                rules.append(rule)
                print(f"  ✅ {rule_name}: {pattern['pattern'][:30]}... (confidence: {pattern['confidence']:.2f})")
        
        return '\n'.join(rules)
    
    def generate_siem_indicators(self) -> List[Dict[str, Any]]:
        """Generate SIEM threat indicators from learned patterns"""
        indicators = []
        
        print("\n📊 Generating SIEM Indicators")
        print("=" * 30)
        
        for pattern in self.patterns:
            if pattern['confidence'] > 0.7:
                # Determine threat level
                if pattern['threat_score'] > 0.9:
                    threat_level = 'HIGH'
                elif pattern['threat_score'] > 0.7:
                    threat_level = 'MEDIUM'
                else:
                    threat_level = 'LOW'
                
                indicator = {
                    'type': 'pattern',
                    'value': pattern['pattern'],
                    'threat_level': threat_level,
                    'confidence': pattern['confidence'],
                    'source': 'WebGuard Experiential Learning',
                    'tags': pattern['tags'],
                    'created': datetime.now().isoformat(),
                    'valid_until': datetime.fromtimestamp(time.time() + 30*24*3600).isoformat(),  # 30 days
                    'metadata': {
                        'discovery_method': pattern['discovery_method'],
                        'validation_count': pattern['validation_count'],
                        'success_rate': pattern['success_rate'],
                        'false_positive_rate': 1.0 - pattern['success_rate']
                    }
                }
                
                indicators.append(indicator)
                print(f"  ✅ {threat_level} threat: {pattern['pattern'][:40]}...")
        
        return indicators
    
    def generate_ml_training_data(self) -> Dict[str, Any]:
        """Generate ML training dataset from WebGuard knowledge"""
        training_data = {
            'features': [],
            'labels': [],
            'metadata': []
        }
        
        print("\n🤖 Generating ML Training Data")
        print("=" * 35)
        
        for pattern in self.patterns:
            # Create feature vector from pattern characteristics
            features = {
                'pattern_length': len(pattern['pattern']),
                'has_sql_keywords': any(keyword in pattern['pattern'].lower() 
                                      for keyword in ['select', 'union', 'or', 'and', 'where']),
                'has_script_tags': '<script>' in pattern['pattern'].lower(),
                'has_special_chars': any(char in pattern['pattern'] 
                                       for char in ['<', '>', '\'', '"', '&', '%']),
                'confidence': pattern['confidence'],
                'validation_count': pattern['validation_count'],
                'success_rate': pattern['success_rate']
            }
            
            training_data['features'].append(features)
            training_data['labels'].append(1 if pattern['threat_score'] > 0.5 else 0)
            training_data['metadata'].append({
                'pattern': pattern['pattern'],
                'tags': pattern['tags'],
                'discovery_method': pattern['discovery_method']
            })
            
            print(f"  ✅ Training sample: {pattern['pattern'][:30]}... (label: {training_data['labels'][-1]})")
        
        return training_data
    
    def export_knowledge_summary(self) -> Dict[str, Any]:
        """Generate a comprehensive summary of exported knowledge"""
        stats = self.knowledge.get('learning_stats', {})
        
        summary = {
            'export_info': {
                'version': self.knowledge.get('version', 'unknown'),
                'export_timestamp': self.knowledge.get('export_timestamp', 0),
                'source_instance': self.knowledge.get('source_instance', 'unknown'),
                'export_date': datetime.fromtimestamp(
                    self.knowledge.get('export_timestamp', 0)
                ).strftime('%Y-%m-%d %H:%M:%S')
            },
            'pattern_statistics': {
                'total_patterns': len(self.knowledge.get('patterns', {})),
                'high_confidence_patterns': len([p for p in self.patterns if p['confidence'] > 0.8]),
                'threat_patterns': len([p for p in self.patterns if p['threat_score'] > 0.5]),
                'average_confidence': sum(p['confidence'] for p in self.patterns) / len(self.patterns) if self.patterns else 0,
                'average_validation_count': sum(p['validation_count'] for p in self.patterns) / len(self.patterns) if self.patterns else 0
            },
            'learning_statistics': stats,
            'integration_readiness': {
                'modsecurity_rules': len([p for p in self.patterns if p['threat_score'] > 0.6]),
                'snort_rules': len([p for p in self.patterns if p['threat_score'] > 0.7]),
                'yara_rules': len([p for p in self.patterns if p['threat_score'] > 0.8]),
                'siem_indicators': len([p for p in self.patterns if p['confidence'] > 0.7])
            }
        }
        
        return summary

def main():
    """Main demonstration function"""
    print("🧠 WebGuard Knowledge Integration Demo")
    print("=" * 50)
    
    # Load WebGuard knowledge
    knowledge_file = "examples/exported_knowledge.json"
    try:
        adapter = WebGuardKnowledgeAdapter(knowledge_file)
    except FileNotFoundError:
        print(f"❌ Knowledge file not found: {knowledge_file}")
        print("   Please run the knowledge_export_demo first:")
        print("   cargo run --bin knowledge_export_demo")
        return
    
    # Generate knowledge summary
    print("\n📋 Knowledge Summary")
    print("=" * 20)
    summary = adapter.export_knowledge_summary()
    
    print(f"Export Date: {summary['export_info']['export_date']}")
    print(f"Source: {summary['export_info']['source_instance']}")
    print(f"Total Patterns: {summary['pattern_statistics']['total_patterns']}")
    print(f"High Confidence: {summary['pattern_statistics']['high_confidence_patterns']}")
    print(f"Average Confidence: {summary['pattern_statistics']['average_confidence']:.2f}")
    print(f"Average Validations: {summary['pattern_statistics']['average_validation_count']:.1f}")
    
    # Generate ModSecurity rules
    modsec_rules = adapter.generate_modsecurity_rules()
    with open('examples/webguard_modsecurity.conf', 'w') as f:
        f.write(f"# WebGuard ModSecurity Rules\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Source: WebGuard Experiential Learning\n\n")
        f.write(modsec_rules)
    print(f"💾 Saved ModSecurity rules to: examples/webguard_modsecurity.conf")
    
    # Generate Snort rules
    snort_rules = adapter.generate_snort_rules()
    with open('examples/webguard_snort.rules', 'w') as f:
        f.write(f"# WebGuard Snort Rules\n")
        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Source: WebGuard Experiential Learning\n\n")
        f.write(snort_rules)
    print(f"💾 Saved Snort rules to: examples/webguard_snort.rules")
    
    # Generate YARA rules
    yara_rules = adapter.generate_yara_rules()
    with open('examples/webguard_patterns.yar', 'w') as f:
        f.write(f"/*\n")
        f.write(f"   WebGuard YARA Rules\n")
        f.write(f"   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"   Source: WebGuard Experiential Learning\n")
        f.write(f"*/\n\n")
        f.write(yara_rules)
    print(f"💾 Saved YARA rules to: examples/webguard_patterns.yar")
    
    # Generate SIEM indicators
    siem_indicators = adapter.generate_siem_indicators()
    with open('examples/webguard_siem_indicators.json', 'w') as f:
        json.dump({
            'metadata': {
                'generated': datetime.now().isoformat(),
                'source': 'WebGuard Experiential Learning',
                'total_indicators': len(siem_indicators)
            },
            'indicators': siem_indicators
        }, f, indent=2)
    print(f"💾 Saved SIEM indicators to: examples/webguard_siem_indicators.json")
    
    # Generate ML training data
    ml_data = adapter.generate_ml_training_data()
    with open('examples/webguard_ml_training.json', 'w') as f:
        json.dump(ml_data, f, indent=2)
    print(f"💾 Saved ML training data to: examples/webguard_ml_training.json")
    
    # Save comprehensive summary
    with open('examples/webguard_knowledge_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"💾 Saved knowledge summary to: examples/webguard_knowledge_summary.json")
    
    print("\n🎉 Knowledge integration demo completed!")
    print("\n📁 Generated Files:")
    print("   • webguard_modsecurity.conf - ModSecurity rules")
    print("   • webguard_snort.rules - Snort detection rules")
    print("   • webguard_patterns.yar - YARA pattern rules")
    print("   • webguard_siem_indicators.json - SIEM threat indicators")
    print("   • webguard_ml_training.json - ML training dataset")
    print("   • webguard_knowledge_summary.json - Comprehensive summary")
    
    print(f"\n🔧 Integration Readiness:")
    print(f"   • ModSecurity: {summary['integration_readiness']['modsecurity_rules']} rules ready")
    print(f"   • Snort: {summary['integration_readiness']['snort_rules']} rules ready")
    print(f"   • YARA: {summary['integration_readiness']['yara_rules']} rules ready")
    print(f"   • SIEM: {summary['integration_readiness']['siem_indicators']} indicators ready")

if __name__ == "__main__":
    main()