mod toolchain_bootstrap_under_test {
    #![allow(dead_code)]
    include!("../src/toolchain_bootstrap.rs");

    #[test]
    fn normalize_sha256_accepts_prefixed_and_plain() {
        let raw = "7ffca1fa4a9a4b432075d353311c44bb6ffcf42def5ae41353ac7b15c81ef49c";
        let prefixed = format!("sha256:{raw}");
        assert_eq!(normalize_sha256_hex(raw).expect("plain"), raw);
        assert_eq!(normalize_sha256_hex(&prefixed).expect("prefixed"), raw);
    }

    #[test]
    fn verify_ptau_magic_rejects_non_ptau_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bad = dir.path().join("bad.ptau");
        fs::write(&bad, b"nope0000").expect("write bad");
        let err = verify_ptau_magic(&bad).expect_err("should reject bad header");
        assert!(format!("{err:#}").contains("Invalid ptau header"));
    }
}
