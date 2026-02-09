// Ground Truth: Clean Deposit Circuit (correctly implemented)
// No bugs - this is a true negative test case

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template CleanDeposit() {
    signal input secret;
    signal input amount;
    signal input nonce;
    
    signal output nullifier;
    signal output commitment;
    signal output newRoot;

    // CORRECT: Nullifier includes both secret and nonce
    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== secret;
    nullifierHash.inputs[1] <== nonce;
    nullifier <== nullifierHash.out;

    // Commitment is correct
    component commitHash = Poseidon(3);
    commitHash.inputs[0] <== secret;
    commitHash.inputs[1] <== amount;
    commitHash.inputs[2] <== nonce;
    commitment <== commitHash.out;

    // Simplified new root
    component rootHash = Poseidon(2);
    rootHash.inputs[0] <== commitment;
    rootHash.inputs[1] <== nonce;
    newRoot <== rootHash.out;
}

component main = CleanDeposit();
