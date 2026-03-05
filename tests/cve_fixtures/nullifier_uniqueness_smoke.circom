pragma circom 2.0.0;

template NullifierUniquenessSmoke() {
    signal input secret_a;
    signal input secret_b;
    signal input secrets[100];
    signal output digest;

    signal acc[101];
    acc[0] <== secret_a + secret_b;

    for (var i = 0; i < 100; i++) {
        acc[i + 1] <== acc[i] + secrets[i];
    }

    digest <== acc[100];
}

component main = NullifierUniquenessSmoke();
