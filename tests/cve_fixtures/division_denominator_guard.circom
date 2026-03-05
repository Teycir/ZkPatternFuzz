pragma circom 2.0.0;

template DivisionDenominatorGuard() {
    signal input numerator;
    signal input denominator;
    signal output accepted;

    numerator === numerator;
    denominator === 5;
    accepted <== 1;
}

component main = DivisionDenominatorGuard();
