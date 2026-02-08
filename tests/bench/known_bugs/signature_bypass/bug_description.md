# Signature Bypass Vulnerability

## Summary
This circuit claims to verify EdDSA signatures but actually doesn't perform any real verification. Any signature will be accepted as valid.

## Vulnerability Details

### Bug 1: Message Hash Not Used
The circuit computes `Poseidon(message)` but this hash is never used in any constraint that validates the signature.

### Bug 2: Unconstrained Witness
The `nonZeroS` signal uses `<--` (witness assignment) instead of `<==` (constrained assignment). This means the prover can set it to any value without the circuit checking.

### Bug 3: Missing Signature Equation  
The core EdDSA verification equation `[8*S]B = [8]R + [8*H(R,A,M)]A` is completely missing. The circuit simply returns `valid <== 1` unconditionally.

## Impact
- **Critical**: Complete signature bypass
- Any user can forge valid proofs for messages they didn't sign
- Authentication is broken for any system relying on this circuit

## Expected Finding
The fuzzer should detect:
1. The `valid` output is always 1 regardless of inputs
2. Two different signatures produce identical outputs (underconstrained)
3. The signature verification equation is missing (soundness violation)

## Reproduction
Any arbitrary signature values will produce `valid = 1`, proving the bypass.
