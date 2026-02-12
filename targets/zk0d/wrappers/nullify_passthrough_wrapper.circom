pragma circom 2.1.1;

// Wrapper around iden3's Nullify() that also exposes the inputs as outputs.
// This makes it easy to wire the same values into other circuits in Mode 3.
include "/media/elements/Repos/zk0d/cat3_privacy/circuits/circuits/lib/utils/nullify.circom";

template NullifyPassThrough() {
    signal input genesisID;
    signal input claimSubjectProfileNonce;
    signal input claimSchema;
    signal input verifierID;
    signal input nullifierSessionID;

    // Pass-through outputs (stable output indices for chain wiring)
    signal output genesisID_out;
    signal output claimSubjectProfileNonce_out;
    signal output claimSchema_out;
    signal output verifierID_out;
    signal output nullifierSessionID_out;

    signal output nullifier;

    genesisID_out <== genesisID;
    claimSubjectProfileNonce_out <== claimSubjectProfileNonce;
    claimSchema_out <== claimSchema;
    verifierID_out <== verifierID;
    nullifierSessionID_out <== nullifierSessionID;

    component n = Nullify();
    n.genesisID <== genesisID;
    n.claimSubjectProfileNonce <== claimSubjectProfileNonce;
    n.claimSchema <== claimSchema;
    n.verifierID <== verifierID;
    n.nullifierSessionID <== nullifierSessionID;

    nullifier <== n.nullifier;
}

component main { public [genesisID, claimSubjectProfileNonce, claimSchema, verifierID, nullifierSessionID] } = NullifyPassThrough();

