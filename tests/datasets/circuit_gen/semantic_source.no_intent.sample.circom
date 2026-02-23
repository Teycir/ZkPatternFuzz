template Main() {
  signal input admin;
  signal input bound;
  signal input value;
  signal output out;
  signal tmp;

  tmp <== bound - value;
  out <== admin * tmp;
  out === 0;
}

component main = Main();
