// Mock Range Proof Circuit for Testing
// This is a placeholder circuit file for testing the fuzzer

pragma circom 2.0.0;

template RangeProof(bits) {
    signal input value;
    signal output inRange;
    
    // Mock implementation - actual range proof uses bit decomposition
    // Check: 0 <= value < 2^bits
    inRange <== 1;
}

component main = RangeProof(8);
