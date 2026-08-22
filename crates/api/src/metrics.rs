//! Minimal Prometheus-format metrics exporter (no external dependencies).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Process-wide metrics registry rendered as Prometheus text format.
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub request_errors_total: AtomicU64,
    pub active_sessions: AtomicU64,
    pub executed_sessions_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
}

impl Metrics {
    pub fn global() -> &'static Metrics {
        static METRICS: OnceLock<Metrics> = OnceLock::new();
        METRICS.get_or_init(|| Metrics {
            requests_total: AtomicU64::new(0),
            request_errors_total: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            executed_sessions_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
        })
    }

    pub fn render(&self) -> String {
        let req = self.requests_total.load(Ordering::Relaxed);
        let err = self.request_errors_total.load(Ordering::Relaxed);
        let active = self.active_sessions.load(Ordering::Relaxed);
        let executed = self.executed_sessions_total.load(Ordering::Relaxed);
        let limited = self.rate_limited_total.load(Ordering::Relaxed);

        format!(
            "# HELP osmiridium_requests_total Total HTTP requests.\n\
             # TYPE osmiridium_requests_total counter\n\
             osmiridium_requests_total {}\n\
             # HELP osmiridium_request_errors_total HTTP 4xx/5xx responses.\n\
             # TYPE osmiridium_request_errors_total counter\n\
             osmiridium_request_errors_total {}\n\
             # HELP osmiridium_active_sessions Currently active sessions.\n\
             # TYPE osmiridium_active_sessions gauge\n\
             osmiridium_active_sessions {}\n\
             # HELP osmiridium_executed_sessions_total Sessions executed.\n\
             # TYPE osmiridium_executed_sessions_total counter\n\
             osmiridium_executed_sessions_total {}\n\
             # HELP osmiridium_rate_limited_total Requests rejected by rate limit.\n\
             # TYPE osmiridium_rate_limited_total counter\n\
             osmiridium_rate_limited_total {}\n",
            req, err, active, executed, limited
        )
    }
}
