%builtins output

func main{output_ptr: felt*}() {
    let a = 2;
    let b = 5;
    let res = (a * b) + a;
    assert [output_ptr] = res;
    let output_ptr = output_ptr + 1;
    return ();
}
