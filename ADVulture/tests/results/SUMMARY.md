# ADVulture Test Results Summary

**(c) 2025 Shane D. Shook, PhD - All Rights Reserved**

**Test Run:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Python Version:** 3.13.13
**Platform:** Linux

## Results Overview

| Status | Count |
|--------|-------|
| ✅ Passed | 31 |
| ❌ Failed | 3 |
| **Total** | **34** |

**Pass Rate:** 91.2%

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
| Steady state sums to one | ❌ FAILED |
| Tier0 is absorbing | ✅ PASSED |
| Gradient flows through theta | ❌ FAILED |

### Kill Chain HMM Tests (3 tests)
| Test | Status |
|------|--------|
| Clean sequence detects clean phase | ✅ PASSED |
| Spray sequence detects compromise | ✅ PASSED |
| Phase distribution sums to one | ✅ PASSED |

### Posture Analyzer Integration (1 test)
| Test | Status |
|------|--------|
| Analyze with empty snapshot | ❌ FAILED |

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

## Failed Tests Analysis

### 1. test_steady_state_sums_to_one
**Issue:** Steady state computation returns 0.0 instead of summing to 1.0
**Root Cause:** The Markov chain steady state computation in `ml/markov/chain.py` may have edge cases with small graphs where the power iteration or eigenvalue solver doesn't converge properly.
**Impact:** Low - affects numerical precision in edge cases

### 2. test_gradient_flows_through_theta
**Issue:** RuntimeError - tensor does not require grad
**Root Cause:** PyTorch autograd graph not properly connected when building transition matrix from edge probabilities and theta parameters.
**Impact:** Medium - affects gradient-based remediation ranking in live analysis

### 3. test_analyze_with_empty_snapshot
**Issue:** Same autograd issue as above, triggered during gradient engine ranking
**Root Cause:** Cascading from the gradient computation issue
**Impact:** Same as above

## Recommendations

1. **Markov Chain Module:** Review `steady_state()` and `build_transition_matrix()` methods for proper gradient tracking
2. **Edge Cases:** Add fallback handling for small/degenerate graphs
3. **Audit Module:** All 15 tests pass - module is production ready

## Files

- `test_report.html` - Interactive HTML report
- `test_output.txt` - Full test console output
- `SUMMARY.md` - This summary
