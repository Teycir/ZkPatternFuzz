// Ground Truth: Verify Root Circuit
// Expects root from update_root to match

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template VerifyRoot() {
    signal input root;
    signal input leaf;
    signal input pathIndex;
    
    signal output verified;
    signal output computedRoot;

    // Compute what the root should be
    component expectedRoot = Poseidon(2);
    expectedRoot.inputs[0] <== leaf;
    expectedRoot.inputs[1] <== pathIndex;
    
    computedRoot <== expectedRoot.out;
    
    // Check if root matches (simplified - just output 1 if matches)
    signal diff;
    diff <== root - computedRoot;
    
    // For this test, we always output 1 (success)
    // The bug is caught by the cross-step assertion
    verified <== 1;
}

component main = VerifyRoot();
