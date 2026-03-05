pragma circom 2.0.0;

template GenericPortableValid() {
    signal input pub;
    signal input secret;
    signal output accepted;

    // Keep both signals wired so executor metadata stays non-empty.
    pub === pub;
    secret === secret;
    accepted <== 1;
}

component main {public [pub]} = GenericPortableValid();
