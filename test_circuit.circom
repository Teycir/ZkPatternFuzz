pragma circom 2.0.0;

template TestCircuit() {
    signal input a;
    signal output out;

    // Keep the fixture tiny but ensure we emit at least one real constraint.
    // Add range check: a must be between 0 and 100
    signal intermediate;
    intermediate <== a * a;
    out <== intermediate;
    intermediate >= 0;
    intermediate <= 10000;
}

component main = TestCircuit();
