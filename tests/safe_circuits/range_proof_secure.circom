// Secure Range Proof Implementation
// FIXED: Includes recomposition check to prevent overflow attacks
// Reference: ZK-CVE-2023-001 remediation

pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template SecureRangeProof(n) {
    signal input value;
    signal output inRange;

    // Decompose value into n bits
    component bits = Num2Bits(n);
    bits.in <== value;

    // SECURITY FIX: Recompose from bits and verify equality
    // This prevents field overflow attacks where value > 2^n wraps around
    signal recomposed[n + 1];
    recomposed[0] <== 0;
    
    for (var i = 0; i < n; i++) {
        // Ensure each bit is binary
        bits.out[i] * (bits.out[i] - 1) === 0;
        
        // Recompose: recomposed[i+1] = recomposed[i] + bit * 2^i
        recomposed[i + 1] <== recomposed[i] + bits.out[i] * (1 << i);
    }

    // CRITICAL: Verify recomposed value equals original
    // Without this, value = p + small (where p is field modulus) would pass
    value === recomposed[n];

    // Value is proven to be in range [0, 2^n - 1]
    inRange <== 1;
}

// Range proof with explicit bounds
template SecureBoundedRange(min, max) {
    signal input value;
    signal output inRange;

    // Check value >= min
    component geMin = GreaterEqThan(252);
    geMin.in[0] <== value;
    geMin.in[1] <== min;

    // Check value <= max
    component leMax = LessEqThan(252);
    leMax.in[0] <== value;
    leMax.in[1] <== max;

    // Both conditions must hold
    signal check;
    check <== geMin.out * leMax.out;
    check === 1;

    inRange <== 1;
}

component main {public [value]} = SecureRangeProof(64);
