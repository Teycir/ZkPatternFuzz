// Ground Truth Circuit: EdDSA Signature Malleability
// Vulnerability: S component not range-checked to canonical form
// CVE Reference: ZK-CVE-2022-001 (synthetic)
// Attack Type: Boundary, Soundness
// Expected: Fuzzer should find malleable signatures where s > q/2

pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

// VULNERABLE: This circuit does NOT enforce canonical signature form (s < q/2)
template EdDSAMalleability() {
    // Signature components
    signal input R8x;
    signal input R8y;
    signal input S;            // BUG: S is not constrained to be < q/2
    
    // Public key
    signal input Ax;
    signal input Ay;
    
    // Message to sign
    signal input M;
    
    // Output: verification result (1 = valid, 0 = invalid)
    signal output valid;
    
    // Compute hash: H(R || A || M)
    component hasher = Poseidon(5);
    hasher.inputs[0] <== R8x;
    hasher.inputs[1] <== R8y;
    hasher.inputs[2] <== Ax;
    hasher.inputs[3] <== Ay;
    hasher.inputs[4] <== M;
    
    signal h;
    h <== hasher.out;
    
    // In a real EdDSA circuit, we would verify:
    // S * G == R + h * A (point operations)
    // 
    // VULNERABILITY: We don't check that S < q/2 (canonical form)
    // An attacker can submit S' = q - S, and both (R, S) and (R, S') verify
    // This is signature malleability!
    
    // Simplified verification (symbolic)
    // For this ground truth circuit, we just check basic structure
    signal verification_check;
    verification_check <== S * R8x + h * Ax;
    
    // Check that S is non-zero (but MISSING: S < q/2 check!)
    component isZero = IsZero();
    isZero.in <== S;
    
    valid <== 1 - isZero.out;
    
    // MISSING CONSTRAINT (the vulnerability):
    // The following should be present but is NOT:
    // component lessThan = LessThan(254);
    // lessThan.in[0] <== S;
    // lessThan.in[1] <== 14474011154664524427946373126085988481658748083205070504932198000989141204992; // q/2
    // lessThan.out === 1;
}

component main {public [Ax, Ay, M]} = EdDSAMalleability();
