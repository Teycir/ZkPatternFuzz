pragma circom 2.0.0;

include "circomlib/poseidon.circom";

// Simple nullifier circuit for testing collision detection
// Commonly used in privacy protocols like Tornado Cash, Semaphore
template Nullifier() {
    signal input secret;
    signal input nonce;
    signal output nullifier;
    
    // Compute nullifier as hash(secret, nonce)
    component hasher = Poseidon(2);
    hasher.inputs[0] <== secret;
    hasher.inputs[1] <== nonce;
    
    nullifier <== hasher.out;
}

component main { public [nonce] } = Nullifier();
