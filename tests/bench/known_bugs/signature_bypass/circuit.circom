// Signature Bypass Circuit
// Bug: EdDSA signature check can be bypassed with crafted inputs
// The circuit checks signature but doesn't constrain message hash properly

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

template SignatureBypass() {
    // Public inputs
    signal input pubKeyX;
    signal input pubKeyY;
    signal input message;
    
    // Private inputs (signature components)
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    
    // Output
    signal output valid;
    
    // BUG 1: Message hash is computed but never linked to signature
    component messageHash = Poseidon(1);
    messageHash.inputs[0] <== message;
    signal msgHash;
    msgHash <== messageHash.out;
    
    // BUG 2: Signature "verification" doesn't actually verify anything
    // It just checks that the signature components are non-zero
    signal nonZeroR;
    nonZeroR <== sigR8x * sigR8y;  // Will be non-zero if both non-zero
    
    signal nonZeroS;
    nonZeroS <-- sigS != 0 ? 1 : 0;  // BUG: Uses <-- not <==
    
    // BUG 3: Never actually verifies the EdDSA equation:
    // [8*S]B = [8]R + [8*H(R,A,M)]A
    // Instead just outputs 1 if components look "valid"
    
    // This should verify the signature but doesn't:
    // The equation is completely missing, circuit just returns 1
    valid <== 1;
    
    // CORRECT implementation would:
    // 1. Compute H = Poseidon(R8x, R8y, pubKeyX, pubKeyY, message)
    // 2. Verify [8*S]B == [8]R + [8*H]A using elliptic curve operations
    // 3. Constrain the output based on this verification
}

// Simpler variant: Missing point-on-curve check
template SignatureBypassSimple() {
    signal input pubKeyX;
    signal input pubKeyY;
    signal input sigValid;  // BUG: Prover claims validity directly
    signal output verified;
    
    // BUG: Trust the prover's claim about signature validity
    // This is a classic "trusted input" vulnerability
    // Prover can set sigValid = 1 for any invalid signature
    verified <== sigValid;
    
    // Missing: Actual signature verification constraints
    // Missing: Point-on-curve check for pubKey
    // Missing: Point-on-curve check for signature point
}

component main {public [pubKeyX, pubKeyY, message]} = SignatureBypass();
