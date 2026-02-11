// Underconstrained Merkle Tree Circuit
// Bug: Path indices are not constrained to be binary (0 or 1)
// This allows invalid paths that can forge membership proofs

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template UnderconstrainedMerkle(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];  // BUG: Not constrained to be 0 or 1
    signal input root;

    signal intermediate[levels + 1];
    intermediate[0] <== leaf;

    component hashers[levels];
    signal left[levels];
    signal right[levels];

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // BUG: pathIndices[i] could be any field element, not just 0 or 1
        // This allows choosing arbitrary combinations that don't represent
        // a valid binary path
        left[i] <== intermediate[i] + pathIndices[i] * (pathElements[i] - intermediate[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (intermediate[i] - pathElements[i]);
        
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        intermediate[i + 1] <== hashers[i].out;
    }

    root === intermediate[levels];
}

component main {public [root]} = UnderconstrainedMerkle(20);
