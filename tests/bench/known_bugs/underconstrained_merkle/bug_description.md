# Underconstrained Merkle Tree Bug

## Vulnerability Type
Underconstrained / Missing Constraint

## Severity
CRITICAL

## Description
The Merkle tree path verification circuit does not constrain `pathIndices` to be binary (0 or 1). This allows an attacker to use arbitrary field elements as path indices, enabling:

1. **Membership Proof Forgery**: Construct fake proofs for leaves that are not in the tree
2. **Path Manipulation**: Choose arbitrary intermediate combinations instead of valid left/right selections

## Root Cause
Missing constraint:
```circom
// Should have:
pathIndices[i] * (1 - pathIndices[i]) === 0;
```

## Exploit Scenario
1. Attacker wants to prove leaf `L` is in tree with root `R`
2. Instead of providing correct path, attacker uses `pathIndices[0] = 0.5`
3. This creates an invalid intermediate value that was never committed to
4. By carefully choosing fractional indices, attacker can construct path to any root

## Detection Method
- Generate two witnesses with different `pathIndices` values (e.g., `0` and `2`)
- Both should produce valid proofs with same public outputs
- If they do, the circuit is underconstrained

## Fix
Add binary constraint for each path index:
```circom
signal pathIndexBinary[levels];
for (var i = 0; i < levels; i++) {
    pathIndexBinary[i] <== pathIndices[i] * (1 - pathIndices[i]);
    pathIndexBinary[i] === 0;
}
```

## References
- CVE-2022-XXXXX (similar vulnerability in production)
- Trail of Bits ZK Bug Report #42
