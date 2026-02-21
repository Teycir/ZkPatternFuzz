mod isolation_hardening_under_test {
    #![allow(dead_code)]
    include!("../src/executor/isolation_hardening.rs");

    mod tests {
        include!("support/executor_isolation_hardening_tests_body.rs");
    }
}
