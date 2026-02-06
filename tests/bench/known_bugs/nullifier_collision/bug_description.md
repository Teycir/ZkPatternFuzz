# Nullifier Collision Bug

## Vulnerability Type
Collision / Weak Nullifier Derivation

## Severity
CRITICAL

## Description
The nullifier derivation only uses part of the secret material (ignoring `randomness`). This allows:

1. **Double Spending**: Same nullifier for different commitments with same secret
2. **Linkability**: Link multiple transactions from same user via nullifier patterns
3. **Front-running**: Predict nullifiers before they're revealed

## Root Cause
Nullifier hash doesn't include all commitment inputs:
```circom
// Bug: Only uses secret
nullHasher.inputs[0] <== secret;

// Should include randomness too:
// nullHasher.inputs[0] <== secret;
// nullHasher.inputs[1] <== randomness;
```

## Exploit Scenario
1. Alice creates commitment C1 with (secret=S, randomness=R1)
2. Alice creates commitment C2 with (secret=S, randomness=R2)
3. Both produce nullifier N = Hash(S)
4. When Alice spends C1 with nullifier N, C2 becomes unspendable
5. Or: Attacker monitors for N and front-runs the transaction

## Detection Method
- Generate two inputs with same secret, different randomness
- Compute both nullifiers
- If nullifiers match, vulnerability exists

## Fix
Include all entropy sources in nullifier derivation:
```circom
component nullHasher = Poseidon(2);
nullHasher.inputs[0] <== secret;
nullHasher.inputs[1] <== randomness;
nullifier <== nullHasher.out;
```

## References
- Tornado Cash cryptographic primitives
- Semaphore nullifier scheme
