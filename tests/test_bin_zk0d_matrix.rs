mod zk0d_matrix_under_test {
    #![allow(dead_code)]
    include!("../src/bin/zk0d_matrix.rs");

    mod tests {
        include!("support/zk0d_matrix_tests_body.rs");
    }
}
