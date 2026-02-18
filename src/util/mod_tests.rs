    use super::write_file_atomic;

    #[test]
    fn test_write_file_atomic_replaces_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("atomic.txt");

        write_file_atomic(&path, b"first").expect("first write");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "first");

        write_file_atomic(&path, b"second").expect("second write");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second");
    }
