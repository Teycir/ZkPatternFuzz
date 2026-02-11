// Range Check Bypass Circuit
// Bug: Bit decomposition without recomposition check
// Allows values outside the intended range

pragma circom 2.0.0;

template RangeBypass(n) {
    signal input value;
    signal input bits[n];
    signal input inRange;
    
    // BUG: We decompose to bits but never verify the recomposition
    // Attacker can provide arbitrary bits that don't match value
    
    // Check each bit is binary
    for (var i = 0; i < n; i++) {
        bits[i] * (1 - bits[i]) === 0;
    }

    // Keep `value` referenced without enforcing recomposition.
    // This preserves the intended bug while ensuring range inference can see `value`.
    value === value;
    
    // BUG: Missing recomposition check:
    // var sum = 0;
    // for (var i = 0; i < n; i++) {
    //     sum = sum + bits[i] * (1 << i);
    // }
    // sum === value;
    
    // Dummy output - always "in range" if bits are binary
    inRange === 1;
}

component main {public [inRange]} = RangeBypass(64);
