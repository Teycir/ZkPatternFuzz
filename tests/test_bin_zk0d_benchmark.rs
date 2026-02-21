mod zk0d_benchmark_under_test {
    #![allow(dead_code)]
    include!("../src/bin/zk0d_benchmark.rs");

    mod tests {
        include!("support/zk0d_benchmark_tests_body.rs");
    }
}
