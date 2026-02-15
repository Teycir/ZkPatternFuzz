pragma circom 2.0.0;

template TestCircuit() {
    signal input a;
    signal output out;

    // Keep the fixture tiny and deterministic for integration tests.
    out <== a;
}

component main = TestCircuit();
