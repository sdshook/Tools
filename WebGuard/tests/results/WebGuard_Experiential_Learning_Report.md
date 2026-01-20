# WebGuard Experiential Learning Report

Generated: 2026-01-20 20:25:30

## Summary

| Metric | Value |
|--------|-------|
| Total Samples | 4,125 |
| Patterns Learned | 221 |
| Final Accuracy | 76.1% |
| Final Precision | 36.6% |
| Final Recall | 88.2% |
| Final F1 | 0.517 |

## Attack Detection

| Attack Type | Detected | Missed | Rate |
|-------------|----------|--------|------|
| SQL Injection | 10 | 0 | 100% |
| Command Injection | 10 | 0 | 100% |
| Web Service Exploit | 8 | 2 | 80% |
| Path Traversal | 10 | 0 | 100% |
| Cross-Site Scripting | 10 | 0 | 100% |
| LDAP Injection | 5 | 0 | 100% |

## Multipass Learning

| Pass | F1 Score | Improvement |
|------|----------|-------------|
| 1 | 0.254 | +0.000 |
| 2 | 0.254 | +0.000 |
| 3 | 0.254 | +0.000 |
| 4 | 0.254 | +0.000 |
| 5 | 0.266 | +0.012 |
| 6 | 0.266 | +0.000 |
| 7 | 0.340 | +0.074 |
| 8 | 0.378 | +0.038 |
| 9 | 0.337 | -0.041 |
| 10 | 0.368 | +0.031 |
| 11 | 0.288 | -0.080 |
| 12 | 0.368 | +0.080 |
| 13 | 0.455 | +0.087 |
| 14 | 0.500 | +0.045 |
| 15 | 0.517 | +0.017 |

## Reward System

| Metric | Value |
|--------|-------|
| Total Reward | 2022.51 |
| Positive | 3902 |
| Negative | 223 |
| Efficiency | 94.6% |
