// Ground Truth Circuit: Non-Binding Commitment
// Vulnerability: Commitment scheme allows multiple openings
// Attack Type: Underconstrained, Collision
// Expected: Fuzzer should find (value1, blinding1) and (value2, blinding2) 
//           that produce the same commitment

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// VULNERABLE: Weak commitment that can be opened to multiple values
template NonBindingCommitment() {
    signal input value;
    signal input blinding;
    signal output commitment;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    
    commitment <== hasher.out;
    
    // This looks correct, but the issue is that the circuit doesn't
    // verify that the value satisfies any meaningful constraint.
    // An attacker can find collisions in the hash function or
    // use algebraic attacks if the field size is small.
}

// More obviously vulnerable: XOR-based commitment
template WeakXorCommitment() {
    signal input value;
    signal input blinding;
    signal output commitment;
    
    // BUG: XOR is not collision resistant
    // value XOR blinding = commitment
    // (value + 1) XOR (blinding + 1) = same commitment (in some cases)
    
    signal xor_result;
    // Simulating XOR with field arithmetic (incorrect but demonstrative)
    xor_result <== value + blinding - 2 * value * blinding;
    
    commitment <== xor_result;
    
    // This is trivially collision-prone
}

// Vulnerable: commitment without domain separation
template CommitmentNoDomainSeparation() {
    signal input value;
    signal input blinding;
    signal input context;  // BUG: context not included properly
    
    signal output commitment;
    
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== blinding;
    // BUG: context is ignored! 
    // Different contexts can have the same commitment
    
    commitment <== hasher.out;
    
    // This allows replay attacks across different contexts
}

component main = NonBindingCommitment();
