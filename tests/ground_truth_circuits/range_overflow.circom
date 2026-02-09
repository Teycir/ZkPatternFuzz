// Ground Truth Circuit: Range Proof Overflow
// Vulnerability: Range check doesn't properly constrain upper bound
// Attack Type: ArithmeticOverflow, Boundary
// Expected: Fuzzer should find values that pass but are >= 2^n

pragma circom 2.0.0;

// VULNERABLE: This range proof has an off-by-one error in the upper bound
template RangeProofOverflow(n) {
    signal input value;
    signal output valid;
    
    signal bits[n];
    signal running_sum[n + 1];
    
    running_sum[0] <== 0;
    
    // Decompose value into bits
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        
        // BUG: We constrain bits to be 0 or 1...
        bits[i] * (1 - bits[i]) === 0;
        
        // ...but we don't properly verify that the sum equals the original value!
        running_sum[i + 1] <== running_sum[i] + bits[i] * (1 << i);
    }
    
    // BUG: This constraint is <= instead of ===
    // An attacker can provide a value >= 2^n and still pass
    // because the bit decomposition just truncates the high bits
    signal diff;
    diff <== value - running_sum[n];
    
    // BUG: We only check that diff is "small" but not that it's zero
    // This allows values up to 2^n + (2^n - 1) to pass
    signal diff_squared;
    diff_squared <== diff * diff;
    
    // MISSING: diff === 0; (This would fix the vulnerability)
    
    valid <== 1;
}

// This template is also vulnerable to bit aliasing
template RangeProofBitAlias(n) {
    signal input value;
    signal output in_range;
    
    signal bits[n];
    
    var sum = 0;
    for (var i = 0; i < n; i++) {
        bits[i] <-- (value >> i) & 1;
        bits[i] * (1 - bits[i]) === 0;
        sum = sum + bits[i] * (1 << i);
    }
    
    // BUG: sum is a var (not signal), so this doesn't create a constraint
    // The prover can lie about the bit decomposition
    in_range <== 1;
}

component main = RangeProofOverflow(8);
