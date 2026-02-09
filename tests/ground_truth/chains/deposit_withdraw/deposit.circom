// Ground Truth: Deposit Circuit (intentionally buggy)
// Bug: Does not properly bind nullifier to commitment
// Expected: unique(step[*].out[0]) assertion should be violated

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template Deposit() {
    signal input secret;
    signal input amount;
    signal input nonce;
    
    signal output nullifier;
    signal output commitment;
    signal output newRoot;

    // BUG: Nullifier is only based on nonce, not secret
    // This allows different secrets with same nonce to produce same nullifier
    component nullifierHash = Poseidon(1);
    nullifierHash.inputs[0] <== nonce;
    nullifier <== nullifierHash.out;

    // Commitment is correct
    component commitHash = Poseidon(3);
    commitHash.inputs[0] <== secret;
    commitHash.inputs[1] <== amount;
    commitHash.inputs[2] <== nonce;
    commitment <== commitHash.out;

    // Simplified new root (for testing)
    component rootHash = Poseidon(2);
    rootHash.inputs[0] <== commitment;
    rootHash.inputs[1] <== nonce;
    newRoot <== rootHash.out;
}

component main = Deposit();
