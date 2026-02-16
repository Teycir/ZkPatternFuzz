pragma circom 2.0.0;

template Mode123ChainStep1() {
    signal input left;
    signal input right;
    signal output diff;

    diff <== left - right;
}

component main = Mode123ChainStep1();
