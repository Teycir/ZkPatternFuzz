use super::*;

#[test]
fn test_fuzzer_node_creation() {
    let node = FuzzerNode::new("test-node", NodeRole::Worker);
    assert_eq!(node.node_id(), "test-node");
    assert_eq!(node.role(), NodeRole::Worker);
}

#[test]
fn test_network_config_default() {
    let config = NetworkConfig::default();
    assert_eq!(config.port, 9527);
    assert!(config.max_message_size > 0);
}
