mod executor {
    pub use zk_fuzzer::executor::*;
}

mod fuzzer {
    pub mod oracles {
        pub use zk_fuzzer::fuzzer::oracles::*;
    }
}

mod config {
    pub mod parser {
        pub use zk_fuzzer::config::parser::*;
    }
}

mod cve_under_test {
    #![allow(dead_code)]
    include!("../src/cve/mod.rs");

    mod tests {
        include!("support/cve_mod_tests_body.rs");
    }
}
