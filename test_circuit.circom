pragma circom 2.0.0;

template TestCircuit() {
    signal input a;
    signal output out;

    // Keep the fixture tiny but ensure we emit at least one real constraint.
    signal intermediate;
    intermediate <== a * a;
    out <== intermediate;
}

component main = TestCircuit();
