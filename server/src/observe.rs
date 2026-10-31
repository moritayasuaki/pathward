//! Bounded, nonblocking producer logging and fixed-cardinality metrics.
use std::{
    io::{self, Write},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct Observability {
    log: Mutex<Option<SyncSender<String>>>,
    pub(crate) serving: AtomicBool,
    pub(crate) accepted: AtomicU64,
    pub(crate) overloaded: AtomicU64,
    active: AtomicU64,
    requests: AtomicU64,
    responses: [AtomicU64; 6],
    io_errors: AtomicU64,
    bytes: AtomicU64,
    tls_errors: AtomicU64,
    reloads: AtomicU64,
    reload_errors: AtomicU64,
    acme_attempts: AtomicU64,
    acme_successes: AtomicU64,
    acme_errors: AtomicU64,
    log_dropped: AtomicU64,
}
impl Observability {
    /// A stalled collector cannot block serving or shutdown. The detached writer
    /// and its at most 256 pending records are best effort at process exit.
    pub fn enable_stderr(&self) -> io::Result<()> {
        let mut log = self.log.lock().map_err(|_| io::Error::other("log lock"))?;
        if log.is_some() {
            return Ok(());
        }
        let (send, receive) = mpsc::sync_channel::<String>(256);
        thread::Builder::new()
            .name("pathward-log".into())
            .spawn(move || {
                for line in receive {
                    // Do not hold stderr's lock while waiting for another record.
                    if writeln!(io::stderr().lock(), "{line}").is_err() {
                        break;
                    }
                }
            })?;
        *log = Some(send);
        Ok(())
    }
    pub fn listening(&self, port: u16, monitor_port: Option<u16>, tls: bool) {
        self.emit(format!(
            "\"event\":\"listening\",\"port\":{port},\"monitor_port\":{},\"tls\":{tls}",
            monitor_port.unwrap_or(0)
        ));
    }
    fn emit(&self, fields: String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs())
            .unwrap_or(0);
        let line = format!("{{\"time\":{now},{fields}}}");
        if let Ok(log) = self.log.lock()
            && let Some(log) = log.as_ref()
            && log.try_send(line).is_err()
        {
            self.log_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn event(&self, event: &'static str, generation: u64, value: u64) {
        // All callers use compile-time event names, never user-controlled strings.
        self.emit(format!(
            "\"event\":\"{event}\",\"generation\":{generation},\"value\":{value}"
        ));
    }
    pub(crate) fn request(
        &self,
        generation: u64,
        elapsed: Duration,
        result: &io::Result<(u16, u64)>,
    ) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let (status, bytes) = match result {
            Ok((s, b)) => {
                let (s, b) = (*s, *b);
                self.responses[(s / 100) as usize].fetch_add(1, Ordering::Relaxed);
                self.bytes.fetch_add(b, Ordering::Relaxed);
                (s, b)
            }
            Err(_) => {
                self.io_errors.fetch_add(1, Ordering::Relaxed);
                (0, 0)
            }
        };
        self.emit(format!("\"event\":\"request\",\"generation\":{generation},\"status\":{status},\"body_bytes\":{bytes},\"duration_us\":{}", elapsed.as_micros()));
    }
    pub(crate) fn reload(&self, ok: bool, generation: u64) {
        if ok {
            self.reloads.fetch_add(1, Ordering::Relaxed);
        } else {
            self.reload_errors.fetch_add(1, Ordering::Relaxed);
        }
        self.event(
            if ok {
                "reload_committed"
            } else {
                "reload_rejected"
            },
            generation,
            0,
        );
    }
    pub(crate) fn tls_failed(&self) {
        self.tls_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn acme(&self, result: Option<bool>, retry: u64) {
        let event = match result {
            None => {
                self.acme_attempts.fetch_add(1, Ordering::Relaxed);
                "acme_order_started"
            }
            Some(true) => {
                self.acme_successes.fetch_add(1, Ordering::Relaxed);
                "acme_activated"
            }
            Some(false) => {
                self.acme_errors.fetch_add(1, Ordering::Relaxed);
                "acme_failed"
            }
        };
        self.event(event, 0, retry);
    }
    pub(crate) fn connection(&self) -> Active<'_> {
        self.active.fetch_add(1, Ordering::Relaxed);
        Active(self)
    }
    pub(crate) fn metrics(
        &self,
        generation: u64,
        ready: bool,
        draining: bool,
        tls: bool,
        cert: Option<(u64, u64)>,
    ) -> String {
        let mut out = String::new();
        for (name, kind, value) in [
            (
                "connections_total",
                "counter",
                self.accepted.load(Ordering::Relaxed),
            ),
            (
                "connections_active",
                "gauge",
                self.active.load(Ordering::Relaxed),
            ),
            (
                "connections_overloaded_total",
                "counter",
                self.overloaded.load(Ordering::Relaxed),
            ),
            (
                "requests_total",
                "counter",
                self.requests.load(Ordering::Relaxed),
            ),
            (
                "request_io_errors_total",
                "counter",
                self.io_errors.load(Ordering::Relaxed),
            ),
            (
                "body_bytes_total",
                "counter",
                self.bytes.load(Ordering::Relaxed),
            ),
            (
                "tls_handshake_errors_total",
                "counter",
                self.tls_errors.load(Ordering::Relaxed),
            ),
            (
                "reloads_total",
                "counter",
                self.reloads.load(Ordering::Relaxed),
            ),
            (
                "reload_errors_total",
                "counter",
                self.reload_errors.load(Ordering::Relaxed),
            ),
            (
                "acme_orders_total",
                "counter",
                self.acme_attempts.load(Ordering::Relaxed),
            ),
            (
                "acme_activations_total",
                "counter",
                self.acme_successes.load(Ordering::Relaxed),
            ),
            (
                "acme_errors_total",
                "counter",
                self.acme_errors.load(Ordering::Relaxed),
            ),
            (
                "log_dropped_total",
                "counter",
                self.log_dropped.load(Ordering::Relaxed),
            ),
            ("config_generation", "gauge", generation),
            ("ready", "gauge", u64::from(ready)),
            ("draining", "gauge", u64::from(draining)),
            ("tls_enabled", "gauge", u64::from(tls)),
            ("certificate_present", "gauge", u64::from(cert.is_some())),
            (
                "certificate_not_before_seconds",
                "gauge",
                cert.map(|c| c.0).unwrap_or(0),
            ),
            (
                "certificate_not_after_seconds",
                "gauge",
                cert.map(|c| c.1).unwrap_or(0),
            ),
        ] {
            out.push_str(&format!(
                "# TYPE pathward_{name} {kind}\npathward_{name} {value}\n"
            ));
        }
        out.push_str("# TYPE pathward_responses_total counter\n");
        for class in 1..=5 {
            out.push_str(&format!(
                "pathward_responses_total{{class=\"{class}xx\"}} {}\n",
                self.responses[class].load(Ordering::Relaxed)
            ));
        }
        out
    }
}
pub(crate) struct Active<'a>(&'a Observability);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_log_queue_drops_without_blocking_and_has_only_fixed_fields() {
        let obs = Observability::default();
        let (tx, rx) = mpsc::sync_channel(1);
        *obs.log.lock().unwrap() = Some(tx);
        obs.request(7, Duration::from_micros(12), &Ok((404, 0)));
        obs.event("reload_rejected", 7, 0);
        assert_eq!(obs.log_dropped.load(Ordering::Relaxed), 1);
        let line = rx.recv().unwrap();
        assert!(line.contains("\"status\":404"));
        assert!(!line.contains("host") && !line.contains("path"));
        assert!(
            obs.metrics(7, true, false, false, None)
                .contains("pathward_config_generation 7\n")
        );
    }
}
