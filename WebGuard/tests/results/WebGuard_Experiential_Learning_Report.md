# WebGuard Experiential Learning Report

Generated: 2026-01-20 19:45:51

## Summary

| Metric | Value |
|--------|-------|
| Total Samples | 6,930 |
| Patterns Learned | 185 |
| Final Accuracy | 91.8% |
| Final Precision | 79.3% |
| Final Recall | 83.6% |
| Final F1 | 0.814 |

## Attack Detection

| Attack Type | Detected | Missed | Rate |
|-------------|----------|--------|------|
| LDAP Injection | 4 | 1 | 80% |
| Command Injection | 8 | 2 | 80% |
| Cross-Site Scripting | 5 | 5 | 50% |
| Web Service Exploit | 6 | 4 | 60% |
| SQL Injection | 3 | 7 | 30% |
| Path Traversal | 9 | 1 | 90% |

## Multipass Learning

| Pass | F1 Score | Improvement |
|------|----------|-------------|
| 1 | 0.759 | +0.000 |
| 2 | 0.720 | -0.039 |
| 3 | 0.726 | +0.006 |
| 4 | 0.744 | +0.018 |
| 5 | 0.750 | +0.006 |
| 6 | 0.752 | +0.002 |
| 7 | 0.752 | +0.000 |
| 8 | 0.765 | +0.013 |
| 9 | 0.772 | +0.007 |
| 10 | 0.779 | +0.007 |
| 11 | 0.786 | +0.007 |
| 12 | 0.796 | +0.011 |
| 13 | 0.807 | +0.011 |
| 14 | 0.814 | +0.007 |
| 15 | 0.814 | +0.000 |
| 16 | 0.804 | -0.011 |
| 17 | 0.804 | +0.000 |
| 18 | 0.804 | +0.000 |
| 19 | 0.804 | +0.000 |
| 20 | 0.804 | +0.000 |
| 21 | 0.814 | +0.011 |
| 22 | 0.814 | +0.000 |
| 23 | 0.814 | +0.000 |
| 24 | 0.814 | +0.000 |
| 25 | 0.814 | +0.000 |

## Reward System

| Metric | Value |
|--------|-------|
| Total Reward | 937.17 |
| Positive | 6272 |
| Negative | 658 |
| Efficiency | 90.5% |
