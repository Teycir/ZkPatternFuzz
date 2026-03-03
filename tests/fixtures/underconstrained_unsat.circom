pragma circom 2.0.0;

template UnderconstrainedUnsat() {
    signal input pub;
    signal input secret;

    // Keep the public input wired so underconstrained collision checks run.
    pub === pub;
    // Always unsatisfiable: no witness can satisfy this relation.
    secret === secret + 1;
}

component main {public [pub]} = UnderconstrainedUnsat();
