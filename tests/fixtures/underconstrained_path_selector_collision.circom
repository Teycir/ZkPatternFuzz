pragma circom 2.0.0;

template PathSelectorCollision() {
    signal input root;
    signal input leaf;
    signal input path_indices[2];
    signal output out;

    out <== root;
}

component main {public [root]} = PathSelectorCollision();
