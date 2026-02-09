// Ground Truth: Update Root Circuit (intentionally buggy)
// Bug: Does not properly propagate new root
// Expected: root_consistency assertion should be violated

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template UpdateRoot() {
    signal input leaf;
    signal input oldRoot;
    signal input pathIndex;
    
    signal output leafOut;
    signal output newRoot;

    // BUG: newRoot doesn't actually include the leaf properly
    // It just hashes oldRoot with a constant, not the actual leaf
    component rootHash = Poseidon(2);
    rootHash.inputs[0] <== oldRoot;
    rootHash.inputs[1] <== pathIndex;  // Should be leaf, not pathIndex!
    
    newRoot <== rootHash.out;
    leafOut <== leaf;
}

component main = UpdateRoot();
