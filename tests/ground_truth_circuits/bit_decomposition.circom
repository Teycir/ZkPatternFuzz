// Ground Truth Circuit: Bit Decomposition Missing Constraint
// Vulnerability: Bits don't sum back to the original value
// Attack Type: Underconstrained
// Expected: Fuzzer should find multiple valid bit patterns for same input

pragma circom 2.0.0;

// VULNERABLE: Bit decomposition without reconstruction check
template BitDecompositionUnconstrained(n) {
    signal input value;
    signal output bits[n];
    
    // Decompose into bits
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        
        // Constrain each bit to be 0 or 1
        bits[i] * (1 - bits[i]) === 0;
    }
    
    // BUG: MISSING the crucial constraint that bits sum to value!
    // var sum = 0;
    // for (var i = 0; i < n; i++) {
    //     sum += bits[i] * (1 << i);
    // }
    // value === sum;  // MISSING!
    
    // Without this constraint, the prover can output any valid bit pattern
    // regardless of the input value
}

// Another vulnerable pattern: inconsistent bit check
template BitDecompositionWrongSum(n) {
    signal input value;
    signal output bits[n];
    signal output reconstructed;
    
    signal partial_sums[n + 1];
    partial_sums[0] <== 0;
    
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
        
        // BUG: Using wrong power of 2 (off by one)
        partial_sums[i + 1] <== partial_sums[i] + bits[i] * (1 << (i + 1));
    }
    
    reconstructed <== partial_sums[n];
    
    // This constraint will never be satisfied correctly due to the bug above
    // But if the prover knows about the bug, they can exploit it
}

// Correct implementation for reference (not used in test)
template BitDecompositionCorrect(n) {
    signal input value;
    signal output bits[n];
    
    signal partial_sums[n + 1];
    partial_sums[0] <== 0;
    
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
        partial_sums[i + 1] <== partial_sums[i] + bits[i] * (1 << i);
    }
    
    // Correct: verify reconstruction matches input
    value === partial_sums[n];
}

component main = BitDecompositionUnconstrained(8);
