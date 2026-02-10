// Secure Merkle Tree Implementation
// All known vulnerabilities patched:
// - Binary path indices enforced
// - Path length fixed at compile time
// - Proper sibling ordering

pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

template SecureMerkleTree(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    // Intermediate hashes
    signal hashes[levels + 1];
    hashes[0] <== leaf;

    component hashers[levels];
    component mux[levels];

    for (var i = 0; i < levels; i++) {
        // SECURITY: Enforce binary path index
        pathIndices[i] * (pathIndices[i] - 1) === 0;
        
        // Determine left/right ordering based on path index
        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== hashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== hashes[i];
        mux[i].s <== pathIndices[i];

        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];
        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[levels];
}

// Membership check with root verification
template MerkleProofChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component tree = SecureMerkleTree(levels);
    tree.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }

    // SECURITY: Verify computed root matches expected
    root === tree.root;
}

component main {public [leaf, root]} = MerkleProofChecker(20);
