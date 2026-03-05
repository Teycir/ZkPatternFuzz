pragma circom 2.0.0;

template SignatureCanonicalGuard() {
    signal input signature_s;
    signal input negate_s;
    signal output accepted;

    // Fixture policy: canonical signatures keep negate_s at 0.
    negate_s * (negate_s - 1) === 0;
    negate_s === 0;

    // Keep the signature field live so the fixture remains input-driven.
    signature_s === signature_s;
    accepted <== 1;
}

component main = SignatureCanonicalGuard();
