pragma circom 2.0.0;

template Mode123ChainStep0() {
    signal input a;
    signal input b;
    signal output sum;
    signal output rhs;

    sum <== a + b;
    rhs <== b;
}

component main = Mode123ChainStep0();
