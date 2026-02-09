// Ground Truth Circuit: Multi-Scalar Multiplication Soundness
// Vulnerability: Unconstrained scalars in multi-exponentiation
// CVE Reference: Synthetic  
// Attack Type: Underconstrained
// Expected: Fuzzer should find that arbitrary scalars satisfy the constraint

pragma circom 2.0.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// VULNERABLE: This circuit performs multi-scalar multiplication with unconstrained scalars
template MultiExpSoundness() {
    // Base points (public generators)
    signal input G1_x;
    signal input G1_y;
    signal input G2_x;
    signal input G2_y;
    
    // Scalars (should be constrained but are NOT)
    signal input scalar1;  // BUG: Unconstrained
    signal input scalar2;  // BUG: Unconstrained
    
    // Claimed result of scalar1 * G1 + scalar2 * G2
    signal input result_x;
    signal input result_y;
    
    signal output valid;
    
    // VULNERABILITY: We only check the "shape" of the computation,
    // not that the scalars are actually used correctly.
    // 
    // In a proper implementation, we would verify:
    // result = scalar1 * G1 + scalar2 * G2 (elliptic curve operations)
    //
    // But here, we have a simplified check that can be bypassed
    
    // "Verification" that's too weak
    signal combined_scalar;
    combined_scalar <== scalar1 + scalar2;
    
    // BUG: This constraint can be satisfied with any (scalar1, scalar2) that sum correctly
    // An attacker can use (0, combined_scalar) or (combined_scalar, 0) or any split
    signal check;
    check <== combined_scalar * G1_x + result_x;
    
    // Even weaker: just check result is on curve (not that it's the RIGHT point)
    // In real EC, y^2 = x^3 + b (simplified)
    signal x_cubed;
    x_cubed <== result_x * result_x * result_x;
    
    signal y_squared;
    y_squared <== result_y * result_y;
    
    // This just checks the point is on SOME curve, not that the computation is correct
    // Attacker can provide any valid curve point
    signal curve_check;
    curve_check <== y_squared - x_cubed;  // Should subtract b too
    
    valid <== 1;
    
    // MISSING CONSTRAINTS:
    // 1. Proper EC scalar multiplication verification
    // 2. Scalar range checks (0 <= scalar < curve_order)
    // 3. Discrete log relation proofs
}

// More realistic example: Pedersen commitment
template WeakPedersenCommitment() {
    // Generators (public)
    signal input G_x;
    signal input G_y;
    signal input H_x;
    signal input H_y;
    
    // Committed value and blinding factor
    signal input value;        // Value to commit
    signal input blinding;     // Blinding factor (BUG: unconstrained range)
    
    // Claimed commitment C = value * G + blinding * H
    signal input C_x;
    signal input C_y;
    
    signal output commitment_valid;
    
    // VULNERABILITY: blinding factor is not range-checked
    // This allows:
    // 1. Overflow attacks in field arithmetic
    // 2. Finding alternative (value', blinding') pairs for same commitment
    
    // Simplified "verification" (vulnerable)
    signal expected;
    expected <== value * G_x + blinding * H_x;
    
    signal diff;
    diff <== expected - C_x;
    
    component isZero = IsZero();
    isZero.in <== diff;
    
    commitment_valid <== isZero.out;
    
    // MISSING:
    // 1. Full EC point verification
    // 2. Range proof on blinding: 0 <= blinding < curve_order
    // 3. Discrete log security assumptions verified
}

template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    
    out <== 1 - in * inv;
    in * out === 0;
}

component main {public [G1_x, G1_y, G2_x, G2_y]} = MultiExpSoundness();
