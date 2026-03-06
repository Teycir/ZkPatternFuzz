pragma circom 2.0.0;

template ArraySeedPassthrough() {
    signal input root;
    signal input path_elements[2];
    signal input path_indices[2];
    signal output out;

    out <== root + path_elements[0] + path_elements[1] + path_indices[0] + path_indices[1];
}

component main {public [root]} = ArraySeedPassthrough();
