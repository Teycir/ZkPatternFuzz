# ZkPatternFuzz Validation Dataset Summary

Generated: 2026-02-13T20:47:59.979280

## Overview

**Total Targets:** 125

### By Source

| Source | Count |
|--------|-------|
| 0xparc | 9 |
| zk0d | 6 |
| zkbugs | 110 |

### By DSL

| DSL | Count |
|-----|-------|
| circom | 56 |
| halo2 | 35 |
| plonky3 | 8 |
| cairo | 8 |
| bellperson | 7 |
| arkworks | 5 |
| risc0 | 3 |
| pil | 2 |
| gnark | 1 |

### By Vulnerability Type

| Type | Count |
|------|-------|
| Under-Constrained | 109 |
| Computational Issues | 6 |
| Unknown | 6 |
| Fiat-Shamir Issue | 2 |
| Backend Issue | 1 |
| Over-Constrained | 1 |

## Sample Targets

1. **Soundness failure due to 0 value not enforced** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

2. **Under-constrained outputs in reduce_sym** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

3. **Multicase number of defaults not enforced** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

4. **Vectors not constrained to be of the same size** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

5. **Soundness failure due toaccumulator 1 initial value not enforced** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

6. **Zero padding not enforced** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

7. **Add missing public input for replica-id** (bellperson)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

8. **Underconstrained vulnerability in division** (risc0)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

9. **Insufficient zkVM validation of multi-step instruction modes** (risc0)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

10. **zkVM underconstrained vulnerability in 3-register instructions** (risc0)
   - Source: zkbugs
   - Vulnerability: Under-Constrained
   - Severity: Critical

