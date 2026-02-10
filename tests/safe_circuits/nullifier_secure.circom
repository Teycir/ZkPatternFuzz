// Secure Nullifier Implementation
// FIXED: Uses cryptographically secure Poseidon hash
// FIXED: Proper domain separation and binding

pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";

template SecureNullifier() {
    // Private inputs
    signal input secret;
    signal input identityTrapdoor;
    signal input externalNullifier;
    
    // Public output
    signal output nullifierHash;
    signal output identityCommitment;

    // Domain separator for nullifier computation
    // Prevents cross-domain attacks
    var NULLIFIER_DOMAIN = 1234567890;
    
    // Compute identity commitment = Poseidon(identityTrapdoor, secret)
    component identityHasher = Poseidon(2);
    identityHasher.inputs[0] <== identityTrapdoor;
    identityHasher.inputs[1] <== secret;
    identityCommitment <== identityHasher.out;

    // SECURITY: Compute nullifier with domain separation
    // nullifierHash = Poseidon(DOMAIN, identitySecret, externalNullifier)
    component nullifierHasher = Poseidon(3);
    nullifierHasher.inputs[0] <== NULLIFIER_DOMAIN;
    nullifierHasher.inputs[1] <== secret;
    nullifierHasher.inputs[2] <== externalNullifier;
    
    nullifierHash <== nullifierHasher.out;
}

// Nullifier with additional binding to prevent replay
template SecureNullifierWithBinding() {
    signal input secret;
    signal input identityTrapdoor;
    signal input externalNullifier;
    signal input actionHash;  // Binds nullifier to specific action
    
    signal output nullifierHash;

    // Include all relevant inputs in nullifier computation
    component hasher = Poseidon(4);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== identityTrapdoor;
    hasher.inputs[2] <== externalNullifier;
    hasher.inputs[3] <== actionHash;
    
    nullifierHash <== hasher.out;
}

component main {public [nullifierHash, identityCommitment]} = SecureNullifier();
