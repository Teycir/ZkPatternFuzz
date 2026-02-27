use std::time::Duration;
use zk_fuzzer_core::power_schedule::{PowerSchedule, PowerScheduler, TestCaseMetrics};

#[test]
fn power_schedule_none_uses_base_energy() {
    let scheduler = PowerScheduler::new(PowerSchedule::None);
    let metrics = TestCaseMetrics::default();
    assert_eq!(scheduler.calculate_energy(&metrics), 100);
}

#[test]
fn power_schedule_explore_prioritizes_rare_paths() {
    let mut scheduler = PowerScheduler::new(PowerSchedule::Explore);
    scheduler.update_globals(Duration::from_micros(100), 1000);

    let rare = TestCaseMetrics {
        path_frequency: 10,
        ..Default::default()
    };
    let common = TestCaseMetrics {
        path_frequency: 500,
        ..Default::default()
    };

    assert!(scheduler.calculate_energy(&rare) > scheduler.calculate_energy(&common));
}

#[test]
fn power_schedule_exploit_prioritizes_findings() {
    let scheduler = PowerScheduler::new(PowerSchedule::Exploit);

    let with_findings = TestCaseMetrics {
        findings_count: 5,
        ..Default::default()
    };
    let without_findings = TestCaseMetrics::default();

    assert!(scheduler.calculate_energy(&with_findings) > scheduler.calculate_energy(&without_findings));
}

#[test]
fn power_schedule_coe_deprioritizes_overused_cases() {
    let scheduler = PowerScheduler::new(PowerSchedule::Coe);

    let fresh = TestCaseMetrics {
        selection_count: 5,
        ..Default::default()
    };
    let overused = TestCaseMetrics {
        selection_count: 100,
        ..Default::default()
    };

    assert!(scheduler.calculate_energy(&fresh) > scheduler.calculate_energy(&overused));
}

#[test]
fn power_schedule_energy_is_clamped() {
    let scheduler = PowerScheduler::new(PowerSchedule::Explore);
    let extreme = TestCaseMetrics {
        path_frequency: 0,
        ..Default::default()
    };

    // Current max_energy in scheduler is 1600.
    assert!(scheduler.calculate_energy(&extreme) <= 1600);
}
