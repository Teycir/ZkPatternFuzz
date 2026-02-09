// Ground Truth: Verify Circuit
// Bug: Accepts malleable signatures

pragma circom 2.1.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";

template Verify() {
    signal input signatureR;
    signal input signatureS;
    signal input message;
    signal input publicKey;
    
    signal output verified;
    signal output messageOut;

    // BUG: Does not check that s < p/2 (malleability check)
    // This means both s and p-s will verify for the same message
    
    // Simplified verification (just check non-zero)
    signal rNonZero;
    signal sNonZero;
    
    rNonZero <-- (signatureR != 0) ? 1 : 0;
    sNonZero <-- (signatureS != 0) ? 1 : 0;
    
    // Always succeed for non-zero signatures
    verified <== rNonZero * sNonZero;
    messageOut <== message;
}

component main = Verify();
