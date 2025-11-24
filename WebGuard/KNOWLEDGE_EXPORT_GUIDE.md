# WebGuard Knowledge Export & Integration Guide

## 🧠 Overview

WebGuard's experiential learning system can export learned patterns and knowledge for use in other systems. This guide explains how to extract, format, and integrate WebGuard's learned knowledge into external security systems.

## 📤 Exporting Learned Knowledge

### 1. Programmatic Export (Rust API)

```rust
use webguard::enhanced_pattern_recognition::ExperientialKnowledgeBase;

// Create or load your WebGuard knowledge base
let mut knowledge_base = ExperientialKnowledgeBase::new();

// After learning from traffic...
// Export high-confidence patterns
match knowledge_base.export_knowledge() {
    Ok(json_knowledge) => {
        // Save to file
        std::fs::write("webguard_knowledge.json", &json_knowledge)?;
        println!("Exported {} bytes of knowledge", json_knowledge.len());
    }
    Err(e) => eprintln!("Export failed: {}", e),
}
```

### 2. Command Line Export

```bash
# Run WebGuard with export flag
cargo run --bin webguard_enhanced_diagnostic -- --export-knowledge knowledge.json

# Or use the test suite to generate knowledge
cargo test experiential_learning_demo -- --nocapture
# Knowledge will be exported to tests/results/
```

### 3. Export via Web API (if implemented)

```bash
# GET request to export endpoint
curl -X GET "http://localhost:8080/api/knowledge/export" \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -o webguard_knowledge.json
```

## 📋 Knowledge Export Format

The exported knowledge is in JSON format with the following structure:

```json
{
  "version": "1.0",
  "export_timestamp": 1700000000,
  "source_instance": "webguard-instance-1",
  "patterns": {
    "sql_injection_pattern_1": {
      "pattern": "' OR 1=1",
      "threat_weight": 0.95,
      "benign_weight": 0.05,
      "confidence": 0.92,
      "learning_source": "local",
      "validation_count": 15,
      "success_rate": 0.93,
      "false_positive_rate": 0.02,
      "context_tags": ["sql", "injection", "authentication"],
      "learned_timestamp": 1699000000,
      "last_updated": 1700000000,
      "discovery_method": "ExperientialLearning"
    }
  },
  "behavioral_indicators": {
    "rapid_requests": {
      "indicator_type": "RequestFrequency",
      "threshold": 100.0,
      "confidence": 0.85,
      "description": "Unusually high request frequency"
    }
  },
  "learning_stats": {
    "total_patterns_learned": 45,
    "threat_patterns_learned": 23,
    "benign_patterns_learned": 22,
    "imported_patterns": 0,
    "exported_patterns": 15,
    "average_confidence": 0.78,
    "learning_start_time": 1698000000
  }
}
```

## 🔄 Integration with Other Systems

### 1. SIEM Integration (Splunk, ELK, etc.)

```python
import json
import requests

# Load WebGuard knowledge
with open('webguard_knowledge.json', 'r') as f:
    knowledge = json.load(f)

# Convert to SIEM rules
def convert_to_splunk_rules(knowledge):
    rules = []
    for pattern_id, pattern in knowledge['patterns'].items():
        if pattern['confidence'] > 0.8:
            rule = {
                'name': f"WebGuard_{pattern_id}",
                'search': f'index=web_logs | search "{pattern["pattern"]}"',
                'severity': 'high' if pattern['threat_weight'] > 0.8 else 'medium',
                'confidence': pattern['confidence'],
                'description': f"Pattern learned by WebGuard: {pattern['pattern']}"
            }
            rules.append(rule)
    return rules

# Upload to Splunk
splunk_rules = convert_to_splunk_rules(knowledge)
for rule in splunk_rules:
    # POST to Splunk API
    response = requests.post(
        'https://your-splunk.com/services/saved/searches',
        auth=('admin', 'password'),
        data=rule
    )
```

### 2. WAF Integration (ModSecurity, Cloudflare, etc.)

```python
def convert_to_modsecurity_rules(knowledge):
    rules = []
    rule_id = 100000
    
    for pattern_id, pattern in knowledge['patterns'].items():
        if pattern['confidence'] > 0.7 and pattern['threat_weight'] > 0.6:
            # Create ModSecurity rule
            rule = f'''
# WebGuard Learned Pattern: {pattern_id}
# Confidence: {pattern['confidence']:.2f}
# Success Rate: {pattern['success_rate']:.2f}
SecRule ARGS "@contains {pattern['pattern']}" \\
    "id:{rule_id},\\
     phase:2,\\
     block,\\
     msg:'WebGuard Learned Threat Pattern: {pattern['pattern']}',\\
     logdata:'Pattern confidence: {pattern['confidence']:.2f}',\\
     severity:'WARNING',\\
     tag:'webguard-learned',\\
     tag:'attack-{pattern['context_tags'][0] if pattern['context_tags'] else 'generic'}'"
'''
            rules.append(rule)
            rule_id += 1
    
    return '\n'.join(rules)

# Generate ModSecurity rules file
with open('webguard_knowledge.json', 'r') as f:
    knowledge = json.load(f)

modsec_rules = convert_to_modsecurity_rules(knowledge)
with open('webguard_learned_rules.conf', 'w') as f:
    f.write(modsec_rules)
```

### 3. Custom Security System Integration

```python
class WebGuardKnowledgeAdapter:
    def __init__(self, knowledge_file):
        with open(knowledge_file, 'r') as f:
            self.knowledge = json.load(f)
        self.patterns = self._extract_high_confidence_patterns()
    
    def _extract_high_confidence_patterns(self):
        """Extract patterns with high confidence for use in other systems"""
        patterns = []
        for pattern_id, pattern in self.knowledge['patterns'].items():
            if pattern['confidence'] > 0.75:
                patterns.append({
                    'id': pattern_id,
                    'pattern': pattern['pattern'],
                    'threat_score': pattern['threat_weight'],
                    'confidence': pattern['confidence'],
                    'tags': pattern['context_tags'],
                    'regex': self._convert_to_regex(pattern['pattern'])
                })
        return patterns
    
    def _convert_to_regex(self, pattern):
        """Convert WebGuard pattern to regex for other systems"""
        import re
        # Escape special regex characters
        escaped = re.escape(pattern)
        # Allow for URL encoding variations
        escaped = escaped.replace(r'\ ', r'(\s|%20|\+)')
        escaped = escaped.replace(r'\'', r'(\'|%27)')
        escaped = escaped.replace(r'\"', r'(\"|%22)')
        return escaped
    
    def get_yara_rules(self):
        """Generate YARA rules from learned patterns"""
        rules = []
        for pattern in self.patterns:
            if pattern['threat_score'] > 0.8:
                rule = f'''
rule WebGuard_{pattern['id']}
{{
    meta:
        description = "WebGuard learned threat pattern"
        confidence = "{pattern['confidence']:.2f}"
        source = "WebGuard Experiential Learning"
        tags = "{','.join(pattern['tags'])}"
    
    strings:
        $pattern = "{pattern['pattern']}" nocase
    
    condition:
        $pattern
}}'''
                rules.append(rule)
        return '\n'.join(rules)
    
    def get_snort_rules(self):
        """Generate Snort rules from learned patterns"""
        rules = []
        sid = 1000000
        
        for pattern in self.patterns:
            if pattern['threat_score'] > 0.7:
                rule = f'alert tcp any any -> any any (msg:"WebGuard Learned Pattern: {pattern["id"]}"; content:"{pattern["pattern"]}"; nocase; sid:{sid}; rev:1;)'
                rules.append(rule)
                sid += 1
        
        return '\n'.join(rules)

# Usage example
adapter = WebGuardKnowledgeAdapter('webguard_knowledge.json')

# Generate YARA rules
yara_rules = adapter.get_yara_rules()
with open('webguard_patterns.yar', 'w') as f:
    f.write(yara_rules)

# Generate Snort rules
snort_rules = adapter.get_snort_rules()
with open('webguard_patterns.rules', 'w') as f:
    f.write(snort_rules)
```

### 4. Machine Learning Pipeline Integration

```python
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

def create_ml_dataset_from_webguard(knowledge):
    """Convert WebGuard knowledge to ML training data"""
    data = []
    
    for pattern_id, pattern in knowledge['patterns'].items():
        # Create training samples
        data.append({
            'pattern': pattern['pattern'],
            'is_threat': 1 if pattern['threat_weight'] > 0.5 else 0,
            'confidence': pattern['confidence'],
            'validation_count': pattern['validation_count'],
            'success_rate': pattern['success_rate'],
            'context': ' '.join(pattern['context_tags'])
        })
    
    return pd.DataFrame(data)

# Load WebGuard knowledge
with open('webguard_knowledge.json', 'r') as f:
    knowledge = json.load(f)

# Create ML dataset
df = create_ml_dataset_from_webguard(knowledge)

# Train a model using WebGuard's learned patterns
vectorizer = TfidfVectorizer(max_features=1000)
X = vectorizer.fit_transform(df['pattern'])
y = df['is_threat']

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# Save the model for use in other systems
import joblib
joblib.dump(model, 'webguard_learned_model.pkl')
joblib.dump(vectorizer, 'webguard_vectorizer.pkl')
```

## 🔧 Advanced Integration Patterns

### 1. Real-time Knowledge Streaming

```python
import asyncio
import websockets
import json

class WebGuardKnowledgeStreamer:
    def __init__(self, webguard_endpoint):
        self.endpoint = webguard_endpoint
        self.subscribers = []
    
    async def stream_knowledge_updates(self):
        """Stream real-time knowledge updates to subscribers"""
        async with websockets.connect(f"ws://{self.endpoint}/knowledge/stream") as websocket:
            async for message in websocket:
                update = json.loads(message)
                await self.broadcast_update(update)
    
    async def broadcast_update(self, update):
        """Broadcast knowledge updates to all subscribers"""
        for subscriber in self.subscribers:
            await subscriber.send(json.dumps(update))
    
    def subscribe(self, subscriber_websocket):
        """Add a new subscriber for knowledge updates"""
        self.subscribers.append(subscriber_websocket)
```

### 2. Knowledge Validation and Quality Scoring

```python
def validate_knowledge_quality(knowledge):
    """Validate and score the quality of exported knowledge"""
    quality_score = 0
    total_patterns = len(knowledge['patterns'])
    
    if total_patterns == 0:
        return 0
    
    high_confidence_patterns = 0
    well_validated_patterns = 0
    recent_patterns = 0
    current_time = time.time()
    
    for pattern in knowledge['patterns'].values():
        # Check confidence
        if pattern['confidence'] > 0.8:
            high_confidence_patterns += 1
        
        # Check validation count
        if pattern['validation_count'] >= 5:
            well_validated_patterns += 1
        
        # Check recency (patterns learned in last 30 days)
        if (current_time - pattern['learned_timestamp']) < (30 * 24 * 3600):
            recent_patterns += 1
    
    # Calculate quality metrics
    confidence_score = high_confidence_patterns / total_patterns
    validation_score = well_validated_patterns / total_patterns
    recency_score = recent_patterns / total_patterns
    
    # Weighted quality score
    quality_score = (confidence_score * 0.4 + 
                    validation_score * 0.4 + 
                    recency_score * 0.2)
    
    return {
        'overall_quality': quality_score,
        'confidence_ratio': confidence_score,
        'validation_ratio': validation_score,
        'recency_ratio': recency_score,
        'total_patterns': total_patterns,
        'recommendation': 'high' if quality_score > 0.7 else 'medium' if quality_score > 0.4 else 'low'
    }
```

## 📊 Knowledge Export Best Practices

### 1. Export Scheduling
- **Frequency**: Export knowledge daily or after significant learning events
- **Thresholds**: Only export patterns with confidence > 0.7 and validation_count > 3
- **Age Limits**: Don't export patterns older than 30 days without recent validation

### 2. Quality Control
- **Validation**: Always validate exported knowledge before integration
- **Testing**: Test patterns in a staging environment first
- **Monitoring**: Monitor false positive rates after integration

### 3. Security Considerations
- **Sanitization**: Remove sensitive information from exported patterns
- **Encryption**: Encrypt knowledge exports when transferring between systems
- **Access Control**: Limit access to knowledge exports to authorized systems

### 4. Version Management
- **Versioning**: Track knowledge export versions for rollback capability
- **Compatibility**: Ensure exported knowledge is compatible with target systems
- **Documentation**: Document what each export contains and its intended use

## 🚀 Example Integration Workflow

```bash
#!/bin/bash
# Complete knowledge export and integration workflow

# 1. Export knowledge from WebGuard
cargo run --bin webguard_enhanced_diagnostic -- --export-knowledge /tmp/webguard_knowledge.json

# 2. Validate knowledge quality
python3 validate_knowledge.py /tmp/webguard_knowledge.json

# 3. Convert to different formats
python3 convert_to_modsecurity.py /tmp/webguard_knowledge.json > /etc/modsecurity/webguard_rules.conf
python3 convert_to_snort.py /tmp/webguard_knowledge.json > /etc/snort/rules/webguard.rules
python3 convert_to_yara.py /tmp/webguard_knowledge.json > /var/lib/yara/webguard_patterns.yar

# 4. Deploy to target systems
systemctl reload modsecurity
systemctl reload snort
systemctl reload yara

# 5. Monitor integration success
tail -f /var/log/security/integration.log
```

This comprehensive guide provides multiple pathways for exporting and integrating WebGuard's learned knowledge into various security systems, ensuring maximum value from the experiential learning capabilities.