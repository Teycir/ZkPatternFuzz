    use super::*;

    #[test]
    fn test_node_capabilities_default() {
        let caps = NodeCapabilities::default();
        assert!(caps.worker_count > 0);
        assert!(caps.memory_bytes > 0);
    }

    #[test]
    fn test_serializable_corpus_entry() {
        let entry = SerializableCorpusEntry {
            inputs: vec!["0x01".to_string(), "0x02".to_string()],
            coverage_hash: 12345,
            discovered_new_coverage: true,
            energy: 50,
        };

        let corpus_entry = entry.to_corpus_entry();
        assert!(corpus_entry.is_some());
    }
