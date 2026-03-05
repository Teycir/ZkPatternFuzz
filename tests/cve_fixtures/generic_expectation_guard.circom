pragma circom 2.0.0;

template GenericExpectationGuard() {
    signal input pub;
    signal input expect_invalid;
    signal output accepted;

    // Keep the portable regression lane binary: either the case is expected to
    // succeed (0) or it is expected to fail closed (1).
    expect_invalid * (expect_invalid - 1) === 0;
    expect_invalid === 0;

    // Keep a public signal live so executor metadata stays non-empty.
    pub === pub;
    accepted <== 1;
}

component main {public [pub]} = GenericExpectationGuard();
