pragma circom 2.0.0;

template SeededCollision() {
    signal input pub;
    signal input a;
    signal input b;
    signal output out;

    pub === a + b;
    out <== pub;
}

component main {public [pub]} = SeededCollision();
