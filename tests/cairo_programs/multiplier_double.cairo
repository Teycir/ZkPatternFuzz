%builtins output

func main{output_ptr: felt*}() {
    let a = 6;
    let b = 7;
    let res = a * b;
    assert [output_ptr] = res;
    let output_ptr = output_ptr + 1;
    return ();
}
