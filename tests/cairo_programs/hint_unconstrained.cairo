%builtins output

func main{output_ptr: felt*}() {
    alloc_locals;
    local hinted;
    %{ memory[ids.hinted] = 1337 %}
    assert [output_ptr] = hinted;
    let output_ptr = output_ptr + 1;
    return ();
}
