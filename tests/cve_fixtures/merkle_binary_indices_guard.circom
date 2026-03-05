pragma circom 2.0.0;

template MerkleBinaryIndicesGuard() {
    signal input pathIndices[20];
    signal output accepted;

    for (var i = 0; i < 20; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;
    }

    accepted <== 1;
}

component main = MerkleBinaryIndicesGuard();
