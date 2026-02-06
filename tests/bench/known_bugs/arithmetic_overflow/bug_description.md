# Arithmetic Overflow Bug

## Vulnerability Type
Arithmetic Overflow / Missing Range Check

## Severity
CRITICAL

## Description
The circuit performs arithmetic operations without proper range checks. In finite field arithmetic, there are no overflows in the traditional sense, but wrap-around behavior can cause:

1. **Balance Underflow**: `balance - amount` wraps to huge number when amount > balance
2. **Multiplication Overflow**: `a * b` produces unexpected results for large inputs
3. **Integer vs Field Confusion**: Using field elements where bounded integers are expected

## Root Cause
1. No range checks on inputs:
```circom
// Missing:
// component balanceCheck = LessThan(64);
// balanceCheck.in[0] <== balance;
// balanceCheck.in[1] <== 2**64;
// balanceCheck.out === 1;
```

2. Unconstrained witness computation:
```circom
// Bug: Uses <-- (witness computation) not <== (constraint)
isNonNegative <-- (newBalance < ...) ? 1 : 0;
// The value is computed but never constrained!
```

## Exploit Scenario
1. User has balance = 100
2. User tries to withdraw amount = 101
3. newBalance = 100 - 101 = p - 1 (field modulus minus 1)
4. This is a huge positive number, not -1
5. User now has effectively infinite balance

## Detection Method
- Test with balance = 0, amount = 1
- Check if newBalance wraps to field max
- Verify range check constraint existence

## Fix
Add proper range checks:
```circom
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

// Check inputs are in valid range
component balanceBits = Num2Bits(64);
balanceBits.in <== balance;

component amountBits = Num2Bits(64);
amountBits.in <== amount;

// Check amount <= balance
component leq = LessEqThan(64);
leq.in[0] <== amount;
leq.in[1] <== balance;
leq.out === 1;

// Now subtraction is safe
newBalance <== balance - amount;
```

## References
- Circom field arithmetic semantics
- Common DeFi vulnerabilities
