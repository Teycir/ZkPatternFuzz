pragma circom 2.0.0;

// Simple multiplier circuit for testing backend integration
template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    
    c <== a * b;
}

component main = Multiplier();
