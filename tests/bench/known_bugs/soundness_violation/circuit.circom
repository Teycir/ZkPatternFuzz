// Soundness Violation Circuit
// Bug: Non-deterministic witness allows multiple valid witnesses
// for the same statement

pragma circom 2.0.0;

template SoundnessViolation() {
    signal input x;
    signal input y;
    signal input unused;  // BUG: Unused signal creates soundness issue
    signal output sum;
    
    // Main computation
    sum <== x + y;
    
    // BUG: 'unused' signal is never constrained
    // This means prover can set it to any value
    // Two different provers can create valid proofs with different 'unused' values
    // This is a witness uniqueness violation
    
    // What should exist:
    // unused === 0;  // Or some constraint
}

template SoundnessViolation2() {
    signal input a;
    signal input b;
    signal input selector;  // BUG: selector not binary constrained
    signal output result;
    
    // Result depends on selector
    // BUG: selector can be any field element, not just 0/1
    result <== a + selector * (b - a);
    
    // Missing:
    // selector * (1 - selector) === 0;
}

component main {public [sum]} = SoundnessViolation();
