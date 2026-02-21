    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = IsolationHardeningConfig::default();
        assert_eq!(config.max_memory_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(config.max_consecutive_crashes, 5);
        assert!(config.enable_crash_recovery);
    }

    #[test]
    fn test_telemetry() {
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
    fn test_crash_recovery_state() {
        let state = CrashRecoveryState::new();

        // Record crashes
        assert_eq!(state.record_crash("circuit1"), 1);
        assert_eq!(state.record_crash("circuit1"), 2);
        assert_eq!(state.record_crash("circuit1"), 3);

        // Reset
        state.reset_crashes("circuit1");
        assert_eq!(state.record_crash("circuit1"), 1);

        // Blacklist
        assert!(!state.is_blacklisted("circuit1"));
        state.blacklist("circuit1");
        assert!(state.is_blacklisted("circuit1"));
    }

    #[test]
    fn test_watchdog() {
        let watchdog = Watchdog::new(100); // 100ms timeout

        assert!(!watchdog.is_timed_out());

        watchdog.ping();
        assert!(!watchdog.is_timed_out());

        std::thread::sleep(Duration::from_millis(150));
        assert!(watchdog.is_timed_out());
    }

    #[test]
    fn test_resource_limits() {
        let config = IsolationHardeningConfig {
            max_memory_bytes: 1024 * 1024, // 1MB
            max_cpu_time_ms: 1000,          // 1 second
            ..Default::default()
        };
        let monitor = ResourceMonitor::new(config);

        let usage = ResourceUsage {
            memory_bytes: 2 * 1024 * 1024, // 2MB - exceeds limit
            cpu_time_ms: 500,
            pid: 0,
            is_alive: true,
        };

        assert_eq!(
            monitor.check_limits(&usage),
            Some(IsolationEventType::MemoryExceeded)
        );
    }
