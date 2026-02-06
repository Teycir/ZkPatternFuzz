# Range Check Bypass Bug

## Vulnerability Type
Missing Constraint / Bit Decomposition Error

## Severity
HIGH

## Description
The range check circuit decomposes a value into bits and checks that each bit is binary (0 or 1). However, it fails to verify that the bit decomposition actually equals the original value. This allows:

1. **Range Bypass**: Pass any value and claim it's in range by providing arbitrary bits
2. **Balance Inflation**: In financial circuits, claim amounts that don't match actual values

## Root Cause
Missing constraint that ties bits back to original value:
```circom
// Missing:
var sum = 0;
for (var i = 0; i < n; i++) {
    sum = sum + bits[i] * (1 << i);
}
sum === value;
```

## Exploit Scenario
1. User wants to prove `value = 2^100` (way above u64 range)
2. User provides `bits = [0, 0, 0, ..., 0]` (all zeros)
3. All bits are binary (constraint satisfied)
4. No check that `sum(bits * 2^i) == value`
5. User successfully "proves" a huge value is in range

## Detection Method
- Input `value = p - 1` (max field element)
- Provide `bits = [0, 0, 0, ...]`
- If proof succeeds, constraint is missing

## Fix
Add recomposition check:
```circom
signal bitValue[n];
signal bitSum[n + 1];
bitSum[0] <== 0;
for (var i = 0; i < n; i++) {
    bitValue[i] <== bits[i] * (1 << i);
    bitSum[i + 1] <== bitSum[i] + bitValue[i];
}
bitSum[n] === value;
```

## References
- Common pattern in Circom circuits
- Trail of Bits Audit Finding #15
