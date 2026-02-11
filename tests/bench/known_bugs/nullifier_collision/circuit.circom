// Nullifier Collision Circuit
// Bug: Nullifier derivation uses only partial secret
// Different secrets can produce same nullifier

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template NullifierCollision() {
    signal input secret;        // 256-bit secret
    signal input randomness;    // Additional randomness
    signal input nullifier;
    signal input commitment;
    
    // Compute commitment correctly using both values
    component commitHasher = Poseidon(2);
    commitHasher.inputs[0] <== secret;
    commitHasher.inputs[1] <== randomness;
    commitment === commitHasher.out;
    
    // BUG: Nullifier only uses secret, ignoring randomness
    // This means different (secret, randomness) pairs can
    // produce the same nullifier if they share the same secret
    component nullHasher = Poseidon(1);
    nullHasher.inputs[0] <== secret;
    nullifier === nullHasher.out;
    
    // CORRECT would be:
    // component nullHasher = Poseidon(2);
    // nullHasher.inputs[0] <== secret;
    // nullHasher.inputs[1] <== randomness;
    // nullifier <== nullHasher.out;
}

component main {public [nullifier, commitment]} = NullifierCollision();
