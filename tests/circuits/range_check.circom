pragma circom 2.0.0;

// Range check circuit - verifies a value is within [0, 2^n)
// This is a common pattern in ZK circuits and prone to underconstrained bugs
template RangeCheck(n) {
    signal input value;
    signal input bits[n];
    
    // Constrain each bit to be 0 or 1
    for (var i = 0; i < n; i++) {
        bits[i] * (1 - bits[i]) === 0;
    }
    
    // Verify bit decomposition equals value
    var sum = 0;
    for (var i = 0; i < n; i++) {
        sum += bits[i] * (1 << i);
    }
    value === sum;
}

// Example: 8-bit range check
component main = RangeCheck(8);
