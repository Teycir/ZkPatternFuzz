// Ground Truth: Sign Circuit (intentionally buggy)
// Bug: Signature malleability - accepts both s and p-s
// Expected: Both steps succeed with different witnesses for same message

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template Sign() {
    signal input privateKey;
    signal input message;
    
    signal output signatureR;
    signal output signatureS;
    signal output messageOut;

    // Compute signature (simplified EdDSA-like)
    component rHash = Poseidon(2);
    rHash.inputs[0] <== privateKey;
    rHash.inputs[1] <== message;
    signatureR <== rHash.out;

    // BUG: s is computed without proper reduction
    // This allows s' = p - s to also be valid
    component sHash = Poseidon(2);
    sHash.inputs[0] <== signatureR;
    sHash.inputs[1] <== privateKey;
    signatureS <== sHash.out;

    messageOut <== message;
}

component main = Sign();
