pragma circom 2.0.0;

include "circomlib/circuits/comparators.circom";

template RangeUpperBoundGuard() {
    signal input value;
    signal input bits;
    signal output accepted;

    component lt = LessThan(252);
    lt.in[0] <== value;
    lt.in[1] <== 256;
    lt.out === 1;

    bits === bits;
    accepted <== 1;
}

component main = RangeUpperBoundGuard();
