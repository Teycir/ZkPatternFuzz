%builtins output

func main{output_ptr: felt*}() {
    let a = 8;
    let b = 8;
    let res = a * b;
    assert [output_ptr] = res;
    let output_ptr = output_ptr + 1;
    return ();
}
