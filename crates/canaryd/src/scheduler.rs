//! Fixed-cadence monitor scheduling helpers (spec §11).

use std::time::Duration;

/// Canary probes are anchored to process startup, rather than to completion
/// of the preceding probe.  This prevents slow targets from drifting their
/// periodic schedule.
pub const PROBE_PERIOD: Duration = Duration::from_secs(60);
pub const MAX_JITTER_SECONDS: u64 = 5;
pub const MAX_CONCURRENT_PROBES: usize = 8;

/// Offset for schedule number `n` after the immediate startup probe.  The
/// caller supplies a uniform integer jitter in the inclusive V0 range 0..=5.
pub fn scheduled_offset(n: u64, jitter_seconds: u64) -> Duration {
    assert!(
        jitter_seconds <= MAX_JITTER_SECONDS,
        "jitter is a V0 fixed range"
    );
    PROBE_PERIOD
        .checked_mul(n as u32)
        .unwrap_or(Duration::MAX)
        .saturating_add(Duration::from_secs(jitter_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_is_anchored_and_not_completion_relative() {
        assert_eq!(scheduled_offset(1, 0), Duration::from_secs(60));
        assert_eq!(scheduled_offset(2, 5), Duration::from_secs(125));
        assert_eq!(scheduled_offset(3, 0), Duration::from_secs(180));
    }

    #[test]
    #[should_panic(expected = "V0 fixed range")]
    fn rejects_out_of_range_jitter() {
        let _ = scheduled_offset(1, 6);
    }
}
