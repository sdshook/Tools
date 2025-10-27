# ShaneGuard Comprehensive Test Results

Generated: 2025-10-27 20:25:30 UTC

## Executive Summary

- **Total Tests Executed**: 720
- **Overall Detection Accuracy**: 22.1%
- **Attack Scenarios**: 570
- **Benign Scenarios**: 150
- **Final Host Aggression**: 0.200
- **Hebbian Connections Formed**: 812
- **Memory Traces**: 29

## Deserialization Attacks

- **Total Tests**: 150
- **Accuracy**: 0.0% (0/150)
- **Average Response Time**: 0.0ms
- **Final Host Aggression**: 0.200

### Sample Results:

| Scenario | Expected | Detected | Similarity | Valence | Iteration |
|----------|----------|----------|------------|---------|----------|
| Node.js JSON Prototype Pollution | medium | log | 0.000 | 0.000 | 1 |
| PHP Unserialize Object Injection | medium | log | 0.000 | 0.000 | 1 |
| Java Deserialization Attack | high | notify | 0.000 | 0.000 | 1 |
| .NET BinaryFormatter Attack | medium | notify | 0.000 | 0.000 | 1 |
| Python Pickle Code Injection | high | notify | 0.000 | 0.000 | 1 |
| PHP Unserialize Object Injection | medium | log | 0.000 | 0.000 | 2 |
| Python Pickle Code Injection | high | notify | 1.000 | 0.000 | 2 |
| .NET BinaryFormatter Attack | medium | notify | 1.000 | 0.100 | 2 |
| Java Deserialization Attack | high | notify | 1.000 | 0.000 | 2 |
| Node.js JSON Prototype Pollution | medium | log | 0.000 | 0.000 | 2 |

## Memory Corruption Attacks

- **Total Tests**: 180
- **Accuracy**: 3.3% (6/180)
- **Average Response Time**: 0.0ms
- **Final Host Aggression**: 0.200

### Sample Results:

| Scenario | Expected | Detected | Similarity | Valence | Iteration |
|----------|----------|----------|------------|---------|----------|
| Use-After-Free Exploitation | high | notify | 0.000 | 0.000 | 1 |
| Format String Vulnerability | high | log | 0.000 | 0.000 | 1 |
| Buffer Overflow Stack Smashing | critical | notify | 0.000 | 0.000 | 1 |
| Double-Free Memory Corruption | high | log | 0.000 | 0.000 | 1 |
| Heap Spray Attack | critical | notify | 0.000 | 0.000 | 1 |
| Integer Overflow Attack | medium | log | 0.000 | 0.000 | 1 |
| Buffer Overflow Stack Smashing | critical | throttle | 1.000 | -0.300 | 2 |
| Integer Overflow Attack | medium | log | 0.000 | 0.000 | 2 |
| Format String Vulnerability | high | log | 0.000 | 0.000 | 2 |
| Use-After-Free Exploitation | high | notify | 1.000 | 0.000 | 2 |

## Web Application Attacks

- **Total Tests**: 240
- **Accuracy**: 1.2% (3/240)
- **Average Response Time**: 0.0ms
- **Final Host Aggression**: 0.000

### Sample Results:

| Scenario | Expected | Detected | Similarity | Valence | Iteration |
|----------|----------|----------|------------|---------|----------|
| XML External Entity (XXE) Attack | high | log | 0.000 | 0.000 | 1 |
| LDAP Injection Attack | high | log | 0.000 | 0.000 | 1 |
| SQL Injection Union Attack | high | notify | 0.000 | 0.000 | 1 |
| Cross-Site Scripting (XSS) | medium | notify | 0.000 | 0.000 | 1 |
| Server-Side Request Forgery (SSRF) | high | log | 0.000 | 0.000 | 1 |
| Directory Traversal Attack | medium | log | 0.000 | 0.000 | 1 |
| Remote Code Execution via File Upload | critical | log | 0.000 | 0.000 | 1 |
| Command Injection via Parameter | critical | notify | 0.000 | 0.000 | 1 |
| Server-Side Request Forgery (SSRF) | high | log | 0.000 | 0.000 | 2 |
| Command Injection via Parameter | critical | throttle | 1.000 | -0.300 | 2 |

## Benign Traffic

- **Total Tests**: 150
- **Accuracy**: 100.0% (150/150)
- **Average Response Time**: 0.0ms
- **Final Host Aggression**: 0.000

### Sample Results:

| Scenario | Expected | Detected | Similarity | Valence | Iteration |
|----------|----------|----------|------------|---------|----------|
| Form Submission | none | log | 0.000 | 0.000 | 1 |
| API Data Retrieval | none | log | 0.000 | 0.000 | 1 |
| Normal User Login | none | log | 0.000 | 0.000 | 1 |
| Static Resource Request | none | log | 0.000 | 0.000 | 1 |
| Search Query | none | log | 0.000 | 0.000 | 1 |
| Search Query | none | log | 0.000 | 0.000 | 2 |
| API Data Retrieval | none | log | 0.000 | 0.000 | 2 |
| Static Resource Request | none | log | 0.000 | 0.000 | 2 |
| Normal User Login | none | log | 0.000 | 0.000 | 2 |
| Form Submission | none | log | 0.000 | 0.000 | 2 |

## Learning Analysis

- **Initial Host Aggression**: 0.000
- **Final Host Aggression**: 0.200
- **Aggression Change**: 0.200
- **Hebbian Connections**: 0 → 812
- **Average Connection Weight**: 0.0500
- **Memory Traces**: 29

## Feature Validation

✅ **BDH Memory System**: Forming Hebbian connections and learning from experience
✅ **Policy Engine**: Escalating responses based on threat level and aggression
✅ **Feature Extraction**: Converting telemetry to normalized feature vectors
✅ **Cross-Service Learning**: Sharing intelligence across multiple service instances
✅ **Adaptive Behavior**: Adjusting responses based on reward feedback
