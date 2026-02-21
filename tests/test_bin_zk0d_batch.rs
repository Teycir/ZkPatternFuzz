mod zk0d_batch_under_test {
    #![allow(dead_code)]
    include!("../src/bin/zk0d_batch.rs");

    mod tests {
        include!("support/zk0d_batch_tests_body.rs");
    }
}
