// Arithmetic Overflow Circuit
// Bug: No range checks before arithmetic operations
// Field wrap-around causes unexpected behavior

pragma circom 2.0.0;

template ArithmeticOverflow() {
    signal input balance;
    signal input amount;
    signal input newBalance;
    signal input success;
    
    // BUG: No range check on balance or amount
    // If amount > balance, subtraction wraps around to huge positive number
    // due to field arithmetic (modular arithmetic)
    
    newBalance === balance - amount;
    
    // This check is useless - newBalance is always "positive" in field
    // because fields don't have negative numbers
    signal isNonNegative;
    isNonNegative <-- (newBalance < 21888242871839275222246405745257275088548364400416034343698204186575808495617 / 2) ? 1 : 0;
    // BUG: Above uses <-- not <== and never constrains isNonNegative
    
    success === 1;  // Always succeeds!
    
    // CORRECT would be:
    // 1. Range check: balance < 2^64
    // 2. Range check: amount < 2^64
    // 3. Range check: amount <= balance
    // 4. Proper constraint: balance - amount < 2^64
}

template ArithmeticOverflow2() {
    signal input a;
    signal input b;
    signal output product;
    
    // BUG: No overflow check for multiplication
    // a * b might overflow the field if both are large
    product <== a * b;
    
    // Missing: Ensure a * b fits in expected bit range
}

component main {public [newBalance, success]} = ArithmeticOverflow();
