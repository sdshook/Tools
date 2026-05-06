# ADVulture Test Results Summary

**(c) 2025 Shane D. Shook, PhD - All Rights Reserved**

**Test Run:** 2025-05-06
**Python Version:** 3.13.13
**Platform:** Linux

## Results Overview

| Status | Count |
|--------|-------|
| ✅ Passed | 34 |
| ❌ Failed | 0 |
| **Total** | **34** |

**Pass Rate:** 100%

## Test Categories

### Collection Module Tests (7 tests)
| Test | Status |
|------|--------|
| UAC flag parsing | ✅ PASSED |
| ESC1 detection | ✅ PASSED |
| ESC1 manager approval suppression | ✅ PASSED |
| Event filtering by ID | ✅ PASSED |
| RC4 downgrade detection | ✅ PASSED |
| DCSync detection | ✅ PASSED |
| Edge tensor anomaly scoring | ✅ PASSED |

### Finding Module Tests (5 tests)
| Test | Status |
|------|--------|
| Finding ID determinism | ✅ PASSED |
| Risk class uniqueness | ✅ PASSED |
| Kerberoast finding template | ✅ PASSED |
| LPE finding is Class D | ✅ PASSED |
| Finding weighted priority | ✅ PASSED |

### Markov Chain Tests (3 tests)
| Test | Status |
|------|--------|
| Steady state sums to one | ✅ PASSED |
| Tier0 is absorbing | ✅ PASSED |
| Gradient flows through theta | ✅ PASSED |

### Kill Chain HMM Tests (3 tests)
| Test | Status |
|------|--------|
| Clean sequence detects clean phase | ✅ PASSED |
| Spray sequence detects compromise | ✅ PASSED |
| Phase distribution sums to one | ✅ PASSED |

### Posture Analyzer Integration (1 test)
| Test | Status |
|------|--------|
| Analyze with empty snapshot | ✅ PASSED |

### Audit Module Tests (15 tests)
| Test | Status |
|------|--------|
| User enabled flag | ✅ PASSED |
| Kerberoastable detection | ✅ PASSED |
| AS-REP roastable detection | ✅ PASSED |
| Password age calculation | ✅ PASSED |
| Delegation flags | ✅ PASSED |
| Domain controller detection | ✅ PASSED |
| Unconstrained delegation (computer) | ✅ PASSED |
| Privileged group detection | ✅ PASSED |
| Audit finding to_dict | ✅ PASSED |
| Audit report severity counting | ✅ PASSED |
| Audit report summary | ✅ PASSED |
| Kerberoastable audit | ✅ PASSED |
| AS-REP roastable audit | ✅ PASSED |
| Unconstrained delegation audit | ✅ PASSED |
| Run audit with no files | ✅ PASSED |

## Fixes Applied

### Markov Chain Module (ml/markov/chain.py)

1. **build_transition_matrix()**: Added proper control suppression that maintains gradient flow through theta parameters

2. **steady_state()**: Improved power iteration convergence and numerical stability

3. **analyze()**: Fixed numpy view mutation bug where `pi.detach().numpy()` returned a view that was being modified, corrupting the original tensor. Now uses `.copy()` to avoid this.

4. **GradientEngine.compute_ranking()**: Added numerical gradient fallback when autograd fails, ensuring gradient computation always succeeds

## Files

- `test_report.html` - Interactive HTML report
- `test_output.txt` - Full test console output
- `SUMMARY.md` - This summary
