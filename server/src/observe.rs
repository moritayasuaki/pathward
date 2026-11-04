//! Bounded, nonblocking producer logging and fixed-cardinality metrics.
use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Default)]
pub struct Observability {
    shared_nat: bool,
    log: Mutex<Option<SyncSender<String>>>,
    pub(crate) serving: AtomicBool,
    pub(crate) accepted: AtomicU64,
    pub(crate) overloaded: AtomicU64,
    pub(crate) quic_migrations: AtomicU64,
    pub(crate) early_static: AtomicU64,
    pub(crate) early_rejected: AtomicU64,
    admission_rejected: AtomicU64,
    admission_reasons: [AtomicU64; 7],
    active: AtomicU64,
    requests: AtomicU64,
    responses: [AtomicU64; 6],
    io_errors: AtomicU64,
    io_reasons: [AtomicU64; 7],
    bytes: AtomicU64,
    tls_errors: AtomicU64,
    h2_idle_timeout: AtomicU64,
    h2_idle_eof: AtomicU64,
    h2_retired_streams: AtomicU64,
    reloads: AtomicU64,
    reload_errors: AtomicU64,
    acme_attempts: AtomicU64,
    acme_successes: AtomicU64,
    acme_errors: AtomicU64,
    log_dropped: AtomicU64,
}
const IO_REASONS: [&str; 7] = [
    "timed_out",
    "connection_reset",
    "connection_aborted",
    "broken_pipe",
    "not_connected",
    "unexpected_eof",
    "other",
];
fn io_reason(error: &io::Error) -> usize {
    match error.kind() {
        io::ErrorKind::TimedOut => 0,
        io::ErrorKind::ConnectionReset => 1,
        io::ErrorKind::ConnectionAborted => 2,
        io::ErrorKind::BrokenPipe => 3,
        io::ErrorKind::NotConnected => 4,
        io::ErrorKind::UnexpectedEof => 5,
        _ => 6,
    }
}
pub(crate) enum DeliveryPhase {
    Head,
    Body,
    Finish,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum TransportStage {
    Admission,
    Input,
    Responder,
    Output,
    Connection,
}
#[derive(Debug)]
struct StageError {
    stage: TransportStage,
    error: io::Error,
    connection: Option<(u64, u64)>,
}
impl std::fmt::Display for StageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transport stage failure")
    }
}
impl std::error::Error for StageError {}
pub(crate) fn stage_error(error: io::Error, stage: TransportStage) -> io::Error {
    if error.get_ref().is_some_and(|e| e.is::<StageError>()) {
        return error;
    }
    io::Error::new(
        error.kind(),
        StageError {
            stage,
            error,
            connection: None,
        },
    )
}
pub(crate) fn connection_error(error: io::Error, active: u64, seen: u64) -> io::Error {
    io::Error::new(
        error.kind(),
        StageError {
            stage: TransportStage::Connection,
            error,
            connection: Some((active, seen)),
        },
    )
}
pub(crate) struct DeliveryProgress {
    pub phase: DeliveryPhase,
    pub status: u16,
    pub head_bytes: usize,
    pub body_bytes: u64,
}
impl Observability {
    pub(crate) fn for_capacity(shared_nat: bool) -> Self {
        Self {
            shared_nat,
            ..Self::default()
        }
    }
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
        self.record_request(generation, elapsed, result, None);
    }
    pub(crate) fn delivery_request(
        &self,
        generation: u64,
        elapsed: Duration,
        result: &io::Result<(u16, u64)>,
        progress: DeliveryProgress,
    ) {
        self.record_request(generation, elapsed, result, Some(progress));
    }
    fn record_request(
        &self,
        generation: u64,
        elapsed: Duration,
        result: &io::Result<(u16, u64)>,
        progress: Option<DeliveryProgress>,
    ) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let mut detail = String::new();
        let (status, bytes) = match result {
            Ok((s, b)) => {
                let (s, b) = (*s, *b);
                self.responses[(s / 100) as usize].fetch_add(1, Ordering::Relaxed);
                self.bytes.fetch_add(b, Ordering::Relaxed);
                (s, b)
            }
            Err(error) => {
                self.io_errors.fetch_add(1, Ordering::Relaxed);
                let reason = io_reason(error);
                self.io_reasons[reason].fetch_add(1, Ordering::Relaxed);
                // Never format the error: its message can contain request data.
                detail = format!(",\"io_error\":\"{}\"", IO_REASONS[reason]);
                let cause = if let Some(stage) =
                    error.get_ref().and_then(|e| e.downcast_ref::<StageError>())
                {
                    let label = match stage.stage {
                        TransportStage::Admission => "admission",
                        TransportStage::Input => "input",
                        TransportStage::Responder => "responder",
                        TransportStage::Output => "output",
                        TransportStage::Connection => "connection",
                    };
                    detail.push_str(&format!(",\"transport_phase\":\"{label}\""));
                    if let Some((active, seen)) = stage.connection {
                        detail.push_str(&format!(
                            ",\"active_streams\":{active},\"seen_streams\":{seen}"
                        ));
                    }
                    &stage.error
                } else {
                    error
                };
                if let Some(h2) = cause
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<crate::multiplex::H2Failure>())
                {
                    // Fixed fields only: no request/response bytes, URLs,
                    // credentials or remote GOAWAY debug text are formatted.
                    let reason = h2.reason.map_or_else(|| "null".into(), |n| n.to_string());
                    detail.push_str(&format!(",\"h2_reason\":{reason},\"h2_remote\":{},\"h2_reset\":{},\"h2_goaway\":{},\"h2_library\":{}", h2.remote, h2.reset, h2.goaway, h2.library));
                    if let Some(limit) = h2.limit {
                        detail.push_str(&format!(",\"h2_limit\":\"{limit}\""));
                    }
                }
                if let Some(p) = progress {
                    let phase = match p.phase {
                        DeliveryPhase::Head => "head",
                        DeliveryPhase::Body => "body",
                        DeliveryPhase::Finish => "finish",
                    };
                    detail.push_str(&format!(",\"delivery_phase\":\"{phase}\",\"delivery_status\":{},\"head_bytes_written\":{},\"body_bytes_written\":{}", p.status, p.head_bytes, p.body_bytes));
                }
                (0, 0)
            }
        };
        self.emit(format!("\"event\":\"request\",\"generation\":{generation},\"status\":{status},\"body_bytes\":{bytes},\"duration_us\":{}{detail}", elapsed.as_micros()));
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
    pub(crate) fn tls_handshake_failed(&self, elapsed: Duration, error: &io::Error) {
        self.tls_failed();
        let detail = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<crate::tls::HandshakeFailure>());
        let phase = detail.map_or("socket", |d| d.phase.label());
        let bytes = detail.map_or(0, |d| d.read_bytes);
        self.emit(format!("\"event\":\"tls_handshake_failed\",\"phase\":\"{phase}\",\"reason\":\"{}\",\"read_bytes\":{bytes},\"duration_us\":{}", IO_REASONS[io_reason(error)], elapsed.as_micros()));
    }
    pub(crate) fn admission_rejected(&self, reason: crate::admission::Rejection) {
        self.admission_rejected.fetch_add(1, Ordering::Relaxed);
        self.admission_reasons[reason as usize].fetch_add(1, Ordering::Relaxed);
        self.emit(format!(
            "\"event\":\"admission_rejected\",\"reason\":\"{}\"",
            reason.label()
        ));
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
    pub(crate) fn connection(self: &Arc<Self>) -> Active {
        self.active.fetch_add(1, Ordering::Relaxed);
        Active(self.clone())
    }
    pub(crate) fn h2_retired_stream(&self, generation: u64, admitted: u64) {
        self.h2_retired_streams.fetch_add(1, Ordering::Relaxed);
        self.event("h2_retired_stream", generation, admitted);
    }
    pub(crate) fn h2_idle_closed(&self, timed_out: bool) {
        if timed_out {
            &self.h2_idle_timeout
        } else {
            &self.h2_idle_eof
        }
        .fetch_add(1, Ordering::Relaxed);
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
                "h2_retired_streams_total",
                "counter",
                self.h2_retired_streams.load(Ordering::Relaxed),
            ),
            (
                "h2_idle_preface_timeout_total",
                "counter",
                self.h2_idle_timeout.load(Ordering::Relaxed),
            ),
            (
                "h2_idle_preface_eof_total",
                "counter",
                self.h2_idle_eof.load(Ordering::Relaxed),
            ),
            (
                "quic_path_changes_total",
                "counter",
                self.quic_migrations.load(Ordering::Relaxed),
            ),
            (
                "early_static_total",
                "counter",
                self.early_static.load(Ordering::Relaxed),
            ),
            (
                "early_rejected_total",
                "counter",
                self.early_rejected.load(Ordering::Relaxed),
            ),
            (
                "admission_global_limit",
                "gauge",
                pathward::release::capacity_global(self.shared_nat),
            ),
            (
                "admission_peer_limit",
                "gauge",
                pathward::release::capacity_peer(self.shared_nat),
            ),
            (
                "admission_queue_limit",
                "gauge",
                pathward::release::capacity_queue(self.shared_nat),
            ),
            (
                "admission_global_rate",
                "gauge",
                pathward::release::capacity_rate(self.shared_nat, false),
            ),
            (
                "admission_peer_rate",
                "gauge",
                pathward::release::capacity_rate(self.shared_nat, true),
            ),
            (
                "admission_global_burst",
                "gauge",
                pathward::release::capacity_burst(self.shared_nat, false),
            ),
            (
                "admission_peer_burst",
                "gauge",
                pathward::release::capacity_burst(self.shared_nat, true),
            ),
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
                "admission_rejected_total",
                "counter",
                self.admission_rejected.load(Ordering::Relaxed),
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
        out.push_str("# TYPE pathward_admission_rejections_total counter\n");
        for reason in crate::admission::Rejection::ALL {
            out.push_str(&format!(
                "pathward_admission_rejections_total{{reason=\"{}\"}} {}\n",
                reason.label(),
                self.admission_reasons[reason as usize].load(Ordering::Relaxed)
            ));
        }
        out.push_str("# TYPE pathward_request_io_failures_total counter\n");
        for (index, reason) in IO_REASONS.iter().enumerate() {
            out.push_str(&format!(
                "pathward_request_io_failures_total{{reason=\"{reason}\"}} {}\n",
                self.io_reasons[index].load(Ordering::Relaxed)
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
pub(crate) struct Active(Arc<Observability>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn io_failures_retain_failure_totals_and_never_format_error_messages() {
        let obs = Observability::default();
        let (tx, rx) = mpsc::sync_channel(8);
        *obs.log.lock().unwrap() = Some(tx);
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::InvalidData,
        ] {
            obs.delivery_request(
                7,
                Duration::from_micros(12),
                &Err(io::Error::new(kind, "secret request /path?token=private")),
                DeliveryProgress {
                    phase: DeliveryPhase::Body,
                    status: 200,
                    head_bytes: 100,
                    body_bytes: 16384,
                },
            );
            let line = rx.recv().unwrap();
            assert!(line.contains("\"status\":0,\"body_bytes\":0"));
            assert!(line.contains("\"delivery_phase\":\"body\""));
            assert!(line.contains("\"body_bytes_written\":16384"));
            assert!(!line.contains("secret") && !line.contains("token") && !line.contains("path"));
        }
        let metrics = obs.metrics(7, true, false, false, None);
        assert!(metrics.contains("pathward_request_io_errors_total 7\n"));
        assert!(metrics.contains("pathward_body_bytes_total 0\n"));
        for reason in IO_REASONS {
            assert!(metrics.contains(&format!(
                "pathward_request_io_failures_total{{reason=\"{reason}\"}} 1\n"
            )));
        }
    }
    #[test]
    fn transport_diagnostics_keep_only_fixed_fields_and_preserve_error_kind() {
        let obs = Observability::default();
        let (tx, rx) = mpsc::sync_channel(2);
        *obs.log.lock().unwrap() = Some(tx);
        let secret = stage_error(
            io::Error::new(io::ErrorKind::TimedOut, "secret /?token=private"),
            TransportStage::Output,
        );
        obs.request(7, Duration::ZERO, &Err(secret));
        let line = rx.recv().unwrap();
        assert!(line.contains("\"transport_phase\":\"output\""));
        assert!(line.contains("\"io_error\":\"timed_out\""));
        assert!(!line.contains("secret") && !line.contains("token"));
        let protocol = io::Error::new(
            io::ErrorKind::InvalidData,
            crate::multiplex::H2Failure {
                reason: Some(11),
                remote: false,
                reset: false,
                goaway: true,
                library: true,
                limit: Some("pending_resets"),
            },
        );
        obs.request(
            7,
            Duration::ZERO,
            &Err(stage_error(protocol, TransportStage::Connection)),
        );
        let line = rx.recv().unwrap();
        assert!(line.contains("\"h2_reason\":11,\"h2_remote\":false,\"h2_reset\":false,\"h2_goaway\":true,\"h2_library\":true"));
        assert!(line.contains("\"transport_phase\":\"connection\""));
    }
    #[test]
    fn admission_reasons_are_fixed_and_do_not_log_peer_or_request_data() {
        let obs = Observability::default();
        let (tx, rx) = mpsc::sync_channel(7);
        *obs.log.lock().unwrap() = Some(tx);
        for reason in crate::admission::Rejection::ALL {
            obs.admission_rejected(reason);
            let line = rx.recv().unwrap();
            assert!(line.contains(&format!("\"reason\":\"{}\"", reason.label())));
            assert!(!line.contains("peer_ip") && !line.contains("host") && !line.contains("path"));
        }
        let metrics = obs.metrics(1, true, false, false, None);
        assert!(metrics.contains("pathward_admission_rejected_total 7\n"));
        for reason in crate::admission::Rejection::ALL {
            assert!(metrics.contains(&format!(
                "pathward_admission_rejections_total{{reason=\"{}\"}} 1\n",
                reason.label()
            )));
        }
    }
    #[test]
    fn handshake_diagnostics_never_format_peer_errors() {
        let obs = Observability::default();
        let (tx, rx) = mpsc::sync_channel(2);
        *obs.log.lock().unwrap() = Some(tx);
        let untrusted = io::Error::other("private host /path?token=secret");
        obs.tls_handshake_failed(Duration::from_millis(5), &untrusted);
        let line = rx.recv().unwrap();
        assert!(line.contains("\"phase\":\"socket\",\"reason\":\"other\",\"read_bytes\":0"));
        assert!(!line.contains("secret") && !line.contains("private"));
        let bounded = io::Error::new(
            io::ErrorKind::TimedOut,
            crate::tls::HandshakeFailure {
                phase: crate::tls::HandshakePhase::Negotiation,
                read_bytes: 1234,
            },
        );
        obs.tls_handshake_failed(Duration::from_secs(5), &bounded);
        assert!(
            rx.recv()
                .unwrap()
                .contains("\"phase\":\"negotiation\",\"reason\":\"timed_out\",\"read_bytes\":1234")
        );
        assert_eq!(obs.tls_errors.load(Ordering::Relaxed), 2);
    }
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
