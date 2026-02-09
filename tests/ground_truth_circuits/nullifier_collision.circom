// Ground Truth Circuit: Nullifier Collision
// Vulnerability: Nullifier hash doesn't include all necessary inputs
// Attack Type: Collision
// Expected: Fuzzer should find two different inputs producing same nullifier

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// VULNERABLE: Nullifier computation ignores critical identity components
template NullifierCollision() {
    // User's secret identity components
    signal input identity_nullifier;  // Used in hash
    signal input identity_trapdoor;   // BUG: NOT used in hash!
    signal input external_nullifier;  // External nullifier (e.g., voting topic)
    
    signal output nullifier_hash;
    
    component hasher = Poseidon(2);
    
    // BUG: identity_trapdoor is NOT included in the hash
    // This means two users with the same identity_nullifier but different
    // identity_trapdoors will produce the same nullifier_hash
    hasher.inputs[0] <== identity_nullifier;
    hasher.inputs[1] <== external_nullifier;
    // MISSING: Should also include identity_trapdoor
    
    nullifier_hash <== hasher.out;
    
    // There's no constraint on identity_trapdoor at all!
    // A malicious prover can use any value for identity_trapdoor
    // and still produce a valid proof
}

// Another vulnerable pattern: truncated nullifier
template NullifierTruncated() {
    signal input secret;
    signal input nonce;
    
    signal output nullifier;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== nonce;
    
    // BUG: Truncating the hash loses entropy
    // This increases collision probability
    signal full_hash;
    full_hash <== hasher.out;
    
    // Only use lower 128 bits (simulated by modular reduction)
    // BUG: This creates birthday attack vulnerability
    nullifier <-- full_hash % (1 << 128);
    
    // MISSING: No constraint to verify the truncation!
    // Prover can output any value they want
}

component main = NullifierCollision();
