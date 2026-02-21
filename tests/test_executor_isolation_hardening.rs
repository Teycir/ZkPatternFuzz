#[allow(dead_code, unused_imports)]
#[path = "../src/executor/isolation_hardening.rs"]
mod isolation_hardening_under_test;

use isolation_hardening_under_test::*;
use std::time::Duration;

#[test]
fn config_defaults_are_sane() {
    let config = IsolationHardeningConfig::default();
    assert_eq!(config.max_memory_bytes, 4 * 1024 * 1024 * 1024);
    assert_eq!(config.max_consecutive_crashes, 5);
    assert!(config.enable_crash_recovery);
}

#[test]
fn telemetry_records_crash_events() {
    let telemetry = IsolationTelemetry::new(10);

    telemetry.record(IsolationEvent {
        timestamp: 0,
        event_type: IsolationEventType::Crash,
        circuit_id: "test".to_string(),
        error: Some("test error".to_string()),
        context: None,
    });

    let stats = telemetry.stats();
    assert_eq!(stats.total_crashes, 1);
    assert_eq!(stats.total_timeouts, 0);

    let events = telemetry.recent_events(10);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, IsolationEventType::Crash);
}

#[test]
fn crash_recovery_state_tracks_and_blacklists() {
    let state = CrashRecoveryState::new();

    assert_eq!(state.record_crash("circuit1"), 1);
    assert_eq!(state.record_crash("circuit1"), 2);
    assert_eq!(state.record_crash("circuit1"), 3);

    state.reset_crashes("circuit1");
    assert_eq!(state.record_crash("circuit1"), 1);

    assert!(!state.is_blacklisted("circuit1"));
    state.blacklist("circuit1");
    assert!(state.is_blacklisted("circuit1"));
}

#[test]
fn watchdog_times_out_after_deadline() {
    let watchdog = Watchdog::new(100);
    assert!(!watchdog.is_timed_out());

    watchdog.ping();
    assert!(!watchdog.is_timed_out());

    std::thread::sleep(Duration::from_millis(150));
    assert!(watchdog.is_timed_out());
}

#[test]
fn resource_limits_detect_memory_exceeded() {
    let config = IsolationHardeningConfig {
        max_memory_bytes: 1024 * 1024,
        max_cpu_time_ms: 1000,
        ..Default::default()
    };
    let monitor = ResourceMonitor::new(config);

    let usage = ResourceUsage {
        memory_bytes: 2 * 1024 * 1024,
        cpu_time_ms: 500,
        pid: 0,
        is_alive: true,
    };

    assert_eq!(
        monitor.check_limits(&usage),
        Some(IsolationEventType::MemoryExceeded)
    );
}
