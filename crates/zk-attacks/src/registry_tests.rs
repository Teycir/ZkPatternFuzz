use super::*;

#[test]
fn test_registry_defaults() {
    let registry = AttackRegistry::new();
    assert!(!registry.is_empty());
    assert!(registry.get("underconstrained").is_some());
}
