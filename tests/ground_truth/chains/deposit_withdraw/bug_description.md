# Deposit-Withdraw Nullifier Reuse Bug

## Bug Class
Nullifier Reuse Across Steps

## Description
The deposit circuit computes nullifier = Poseidon(nonce) instead of 
nullifier = Poseidon(secret, nonce). This means different users with 
different secrets but the same nonce will produce identical nullifiers.

## Impact
- Double-spend attacks possible
- Same nullifier can be reused across multiple deposits
- Loss of funds for protocol

## Expected L_min
2 (requires both deposit and withdraw steps to manifest)

## Violated Assertion
`unique(step[*].out[0])` - nullifier should be unique across all steps

## Fix
Change deposit nullifier computation to:
```circom
component nullifierHash = Poseidon(2);
nullifierHash.inputs[0] <== secret;
nullifierHash.inputs[1] <== nonce;
nullifier <== nullifierHash.out;
```
