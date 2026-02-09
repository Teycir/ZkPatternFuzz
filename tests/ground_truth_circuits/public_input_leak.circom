// Ground Truth Circuit: Private Input Information Leakage
// Vulnerability: Private input leaks through public output due to weak derivation
// CVE Reference: Synthetic
// Attack Type: InformationLeakage
// Expected: Fuzzer should detect that private data can be derived from public outputs

pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";

// VULNERABLE: This circuit leaks private input through public output
template PublicInputLeak() {
    // Private inputs (should remain confidential)
    signal input secret_key;
    signal input secret_nonce;
    signal input private_amount;
    
    // Public inputs
    signal input public_identifier;
    
    // Public outputs
    signal output commitment;
    signal output nullifier;
    signal output leaked_value;  // BUG: This directly reveals private_amount
    
    // Compute commitment (secure)
    component commitment_hash = Poseidon(3);
    commitment_hash.inputs[0] <== secret_key;
    commitment_hash.inputs[1] <== secret_nonce;
    commitment_hash.inputs[2] <== private_amount;
    commitment <== commitment_hash.out;
    
    // Compute nullifier (secure)
    component nullifier_hash = Poseidon(2);
    nullifier_hash.inputs[0] <== secret_key;
    nullifier_hash.inputs[1] <== public_identifier;
    nullifier <== nullifier_hash.out;
    
    // BUG: Private amount is leaked directly as public output!
    // An observer can see exactly how much was transferred
    leaked_value <== private_amount;
    
    // ALSO VULNERABLE: Even a "derived" value can leak information
    // signal derived_leak;
    // derived_leak <== private_amount + 1;  // Still reveals amount
    
    // CORRECT APPROACH would be:
    // - Only output cryptographic commitments
    // - Use range proofs that don't reveal exact values
    // - Apply proper blinding factors
}

// Alternative: Weak Derivation Leak
template WeakDerivationLeak() {
    signal input secret;
    signal input public_input;
    
    signal output commitment;
    signal output weak_output;  // BUG: Weak derivation allows brute-force
    
    // Strong commitment (OK)
    component strong_hash = Poseidon(2);
    strong_hash.inputs[0] <== secret;
    strong_hash.inputs[1] <== public_input;
    commitment <== strong_hash.out;
    
    // VULNERABLE: Weak derivation (only uses low bits of secret)
    // If secret has low entropy or attacker knows partial info,
    // this can be brute-forced
    component bits = Num2Bits(254);
    bits.in <== secret;
    
    // Only use bottom 32 bits - massively reduces search space!
    signal low_bits;
    low_bits <== bits.out[0] + bits.out[1] * 2 + bits.out[2] * 4 + bits.out[3] * 8
              + bits.out[4] * 16 + bits.out[5] * 32 + bits.out[6] * 64 + bits.out[7] * 128;
    
    weak_output <== low_bits;  // Only 256 possible values!
}

component main {public [public_identifier]} = PublicInputLeak();
