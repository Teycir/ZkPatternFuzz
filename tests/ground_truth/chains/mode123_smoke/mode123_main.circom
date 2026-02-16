pragma circom 2.0.0;

template Mode123Main() {
    signal input a;
    signal input b;
    signal output out;

    // Keep this fixture tiny but constrained.
    out <== a + b;
}

component main = Mode123Main();
