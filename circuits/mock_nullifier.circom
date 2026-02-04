// Mock Nullifier Circuit for Testing
// This is a placeholder circuit file for testing the fuzzer

pragma circom 2.0.0;

template Nullifier() {
    signal input secret;
    signal input nonce;
    
    signal output nullifier;
    
    // Mock implementation - actual nullifier computation would use Poseidon/MiMC
    nullifier <== secret * nonce;
}

component main = Nullifier();
