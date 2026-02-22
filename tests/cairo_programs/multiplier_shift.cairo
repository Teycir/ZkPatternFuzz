%builtins output

func main{output_ptr: felt*}() {
    let a = 9;
    let b = 3;
    let mul = a * b;
    let res = mul + 1;
    assert [output_ptr] = res;
    let output_ptr = output_ptr + 1;
    return ();
}
