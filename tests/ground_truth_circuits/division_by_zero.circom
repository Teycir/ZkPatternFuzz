// Ground Truth Circuit: Division by Zero Vulnerability
// Vulnerability: Division constraint doesn't check for zero divisor
// CVE Reference: Synthetic
// Attack Type: ArithmeticOverflow, Boundary
// Expected: Fuzzer should find inputs where divisor = 0 causes unexpected behavior

pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

// VULNERABLE: This circuit performs division without checking for zero divisor
template DivisionByZero() {
    signal input dividend;
    signal input divisor;      // BUG: No constraint that divisor != 0
    signal input quotient;     // Claimed quotient
    signal input remainder;    // Claimed remainder
    
    signal output verified;    // 1 if division is valid
    
    // Division constraint: dividend = quotient * divisor + remainder
    // 
    // VULNERABILITY: When divisor = 0, this becomes:
    // dividend = quotient * 0 + remainder
    // dividend = remainder
    // 
    // Any quotient works! The prover can claim arbitrary quotient values
    // when divisor = 0, breaking the mathematical invariant.
    
    signal product;
    product <== quotient * divisor;
    
    signal sum;
    sum <== product + remainder;
    
    // This constraint is satisfied even when divisor = 0
    dividend === sum;
    
    // Additional constraint: remainder < divisor (for Euclidean division)
    // BUG: This ALSO fails when divisor = 0 because 0 < 0 is false,
    // but in field arithmetic it's more subtle
    // circomlib LessThan requires n <= 252.
    component lt = LessThan(252);
    lt.in[0] <== remainder;
    lt.in[1] <== divisor;
    // Note: We're not even enforcing this constraint strictly
    
    verified <== 1;
    
    // MISSING CONSTRAINT (the vulnerability):
    // The following should be present but is NOT:
    // component isZeroDivisor = IsZero();
    // isZeroDivisor.in <== divisor;
    // isZeroDivisor.out === 0;  // Force divisor to be non-zero
}

// More realistic example: Fee calculation with division
template FeeCalculation() {
    signal input total_amount;
    signal input fee_divisor;    // e.g., 100 for 1% fee
    signal input claimed_fee;
    
    signal output fee_valid;
    
    // Calculate expected fee: fee = total_amount / fee_divisor
    // 
    // VULNERABILITY: If fee_divisor = 0, the constraint becomes:
    // total_amount = claimed_fee * 0
    // total_amount = 0
    // 
    // But we don't enforce total_amount = 0, so this is broken
    
    signal calculated_product;
    calculated_product <== claimed_fee * fee_divisor;
    
    // This should be: total_amount === calculated_product
    // But due to integer division, we use: calculated_product <= total_amount < calculated_product + fee_divisor
    
    component lte = LessEqThan(252);
    lte.in[0] <== calculated_product;
    lte.in[1] <== total_amount;
    
    component lt = LessThan(252);
    lt.in[0] <== total_amount;
    lt.in[1] <== calculated_product + fee_divisor;
    
    // BUG: When fee_divisor = 0, the range check breaks down
    fee_valid <== lte.out * lt.out;
}

component main {public [dividend]} = DivisionByZero();
