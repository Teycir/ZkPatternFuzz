# Soundness Violation Bug

## Vulnerability Type
Soundness / Witness Uniqueness

## Severity
CRITICAL

## Description
The circuit contains unconstrained signals or non-deterministic witness generation. This allows multiple valid witnesses for the same public statement, violating the "unique witness" property required for soundness.

## Root Cause
1. **Unused signals**: Private input `unused` is never constrained
2. **Non-binary selectors**: Selector signals not constrained to {0, 1}

```circom
// Bug 1: Unused signal
signal input unused;  // Never appears in constraints

// Bug 2: Non-binary selector
signal input selector;
result <== a + selector * (b - a);
// Missing: selector * (1 - selector) === 0;
```

## Exploit Scenario
1. Prover A creates proof with `unused = 0`
2. Prover B creates proof with `unused = 12345`
3. Both proofs are valid for same public output
4. Verifier cannot distinguish between provers
5. In voting: same person votes multiple times with different "unused" values

## Detection Method
- Generate witness W1 with random private inputs
- Generate witness W2 by modifying unconstrained signal
- If both witnesses produce valid proofs, soundness is violated

## Fix
1. Remove unused signals or add constraints:
```circom
unused === 0;  // Or remove the signal entirely
```

2. Add binary constraints:
```circom
selector * (1 - selector) === 0;
```

## References
- ZK Soundness definition
- Groth16 witness uniqueness requirements
