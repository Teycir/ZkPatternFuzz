
use super::*;

#[test]
fn test_coordinator_creation() {
    let config = DistributedConfig::default();
    let coordinator = DistributedCoordinator::new(config);
    assert_eq!(coordinator.worker_count().expect("worker count failed"), 0);
}

#[test]
fn test_work_unit_creation() {
    let work = WorkUnit::new(1, "underconstrained", 1000);
    assert_eq!(work.id, 1);
    assert_eq!(work.iterations, 1000);
}

#[test]
fn test_worker_registration() {
    let config = DistributedConfig::default();
    let coordinator = DistributedCoordinator::new(config);

    let msg = DistributedMessage::Register {
        node_id: "test-worker".to_string(),
        role: super::super::network::NodeRole::Worker,
        capabilities: NodeCapabilities::default(),
    };

    coordinator
        .handle_message(msg)
        .expect("message handling failed");
    assert_eq!(coordinator.worker_count().expect("worker count failed"), 1);
}
