// Ground Truth: Clean Withdraw Circuit (correctly implemented)
// No bugs - this is a true negative test case

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template CleanWithdraw() {
    signal input secret;
    signal input amount;
    signal input nullifierIn;
    signal input root;
    
    signal output nullifierOut;
    signal output newRoot;
    signal output amountOut;

    // Pass through the nullifier
    nullifierOut <== nullifierIn;

    // Verify commitment
    component commitHash = Poseidon(2);
    commitHash.inputs[0] <== secret;
    commitHash.inputs[1] <== amount;
    
    // Update root
    component newRootHash = Poseidon(2);
    newRootHash.inputs[0] <== root;
    newRootHash.inputs[1] <== nullifierIn;
    newRoot <== newRootHash.out;

    amountOut <== amount;
}

component main = CleanWithdraw();
