pragma circom 2.0.0;

template MerklePathLengthGuard() {
    signal input path_length;
    signal output accepted;

    path_length === 20;
    accepted <== 1;
}

component main = MerklePathLengthGuard();
