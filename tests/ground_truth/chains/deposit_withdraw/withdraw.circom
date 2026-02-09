// Ground Truth: Withdraw Circuit
// Works with buggy deposit - uses nullifier from deposit

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template Withdraw() {
    signal input secret;
    signal input amount;
    signal input nullifierIn;
    signal input root;
    
    signal output nullifierOut;
    signal output newRoot;
    signal output amountOut;

    // Pass through the nullifier (should be checked for uniqueness across steps)
    nullifierOut <== nullifierIn;

    // Verify commitment exists in tree (simplified)
    component commitHash = Poseidon(2);
    commitHash.inputs[0] <== secret;
    commitHash.inputs[1] <== amount;
    
    // Simplified root update
    component newRootHash = Poseidon(2);
    newRootHash.inputs[0] <== root;
    newRootHash.inputs[1] <== nullifierIn;
    newRoot <== newRootHash.out;

    amountOut <== amount;
}

component main = Withdraw();
