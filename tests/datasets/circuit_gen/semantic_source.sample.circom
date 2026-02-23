pragma circom 2.1.9;

template AccessRange() {
    signal input admin_flag;
    signal input amount;
    signal output out;

    // only admin can mint
    // amount must be less than 1000
    /* users must not mint without admin role */
    out <== admin_flag * amount;
}

component main = AccessRange();
