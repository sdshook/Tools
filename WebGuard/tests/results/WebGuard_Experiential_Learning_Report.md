# WebGuard Experiential Learning Report

Generated: 2026-01-20 19:38:11

## Summary

| Metric | Value |
|--------|-------|
| Total Samples | 6,930 |
| Patterns Learned | 185 |
| Final Accuracy | 92.5% |
| Final Precision | 81.0% |
| Final Recall | 85.5% |
| Final F1 | 0.832 |

## Attack Detection

| Attack Type | Detected | Missed | Rate |
|-------------|----------|--------|------|
| SQL Injection | 3 | 7 | 30% |
| Command Injection | 8 | 2 | 80% |
| Web Service Exploit | 6 | 4 | 60% |
| Cross-Site Scripting | 5 | 5 | 50% |
| Path Traversal | 9 | 1 | 90% |
| LDAP Injection | 4 | 1 | 80% |

## Multipass Learning

| Pass | F1 Score | Improvement |
|------|----------|-------------|
| 1 | 0.772 | +0.000 |
| 2 | 0.726 | -0.046 |
| 3 | 0.748 | +0.022 |
| 4 | 0.760 | +0.012 |
| 5 | 0.750 | -0.010 |
| 6 | 0.773 | +0.023 |
| 7 | 0.769 | -0.004 |
| 8 | 0.759 | -0.011 |
| 9 | 0.772 | +0.013 |
| 10 | 0.772 | +0.000 |
| 11 | 0.772 | +0.000 |
| 12 | 0.779 | +0.007 |
| 13 | 0.786 | +0.007 |
| 14 | 0.786 | +0.000 |
| 15 | 0.796 | +0.011 |
| 16 | 0.796 | +0.000 |
| 17 | 0.807 | +0.011 |
| 18 | 0.807 | +0.000 |
| 19 | 0.807 | +0.000 |
| 20 | 0.807 | +0.000 |
| 21 | 0.825 | +0.018 |
| 22 | 0.821 | -0.003 |
| 23 | 0.832 | +0.010 |
| 24 | 0.832 | +0.000 |
| 25 | 0.832 | +0.000 |

## Reward System

| Metric | Value |
|--------|-------|
| Total Reward | 847.08 |
| Positive | 6278 |
| Negative | 652 |
| Efficiency | 90.6% |
