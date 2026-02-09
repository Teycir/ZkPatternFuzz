// Ground Truth Circuit: Merkle Path Index Unconstrained
// Vulnerability: Path indices are not constrained to binary (0 or 1)
// Attack Type: Underconstrained
// Expected: Fuzzer should find inputs where path_indices[i] ∉ {0, 1}

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// VULNERABLE: This circuit does NOT constrain path indices to be binary
template MerkleTreeUnconstrained(levels) {
    signal input leaf;
    signal input root;
    signal input path_elements[levels];
    signal input path_indices[levels];  // BUG: Should be constrained to 0 or 1
    
    signal output computed_root;
    
    signal intermediate[levels + 1];
    intermediate[0] <== leaf;
    
    component hashers[levels];
    component mux[levels];
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // BUG: path_indices[i] is used as a selector but NOT constrained
        // An attacker can use path_indices[i] = 2, 3, or any field element
        // This allows computing different "roots" from the same leaf
        
        // Left input: if path_indices[i] == 0, use intermediate; else use path_elements
        hashers[i].inputs[0] <== intermediate[i] + path_indices[i] * (path_elements[i] - intermediate[i]);
        
        // Right input: if path_indices[i] == 0, use path_elements; else use intermediate
        hashers[i].inputs[1] <== path_elements[i] + path_indices[i] * (intermediate[i] - path_elements[i]);
        
        intermediate[i + 1] <== hashers[i].out;
    }
    
    computed_root <== intermediate[levels];
    
    // Check that computed root matches expected root
    root === computed_root;
    
    // MISSING: The following constraints should be present but are not:
    // for (var i = 0; i < levels; i++) {
    //     path_indices[i] * (1 - path_indices[i]) === 0;  // Force binary
    // }
}

component main {public [root]} = MerkleTreeUnconstrained(3);
