//! Local rehearsal diagnostics: never subscribe to headers, frames or span fields.
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing_core::{Event, Level, Metadata, Subscriber, field, span};

fn category(message: &str) -> Option<&'static str> {
    if message.starts_with("recv_reset; remotely-reset pending-accept streams reached limit") {
        Some("pending_resets")
    } else if message.starts_with("locally-reset streams reached limit")
        || message.starts_with("reset_on_recv_stream_err; locally-reset streams reached limit")
    {
        Some("internal_resets")
    } else {
        None
    }
}
struct Message(Option<&'static str>);
impl field::Visit for Message {
    fn record_debug(&mut self, field: &field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            // The formatted message is never retained or emitted. Only the
            // fixed allowlist result survives this call.
            self.0 = category(&format!("{value:?}"));
        }
    }
}
struct Limits(AtomicUsize);
impl Subscriber for Limits {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() == Level::WARN
            && matches!(
                metadata.target(),
                "h2::proto::streams::recv" | "h2::proto::streams::streams"
            )
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut message = Message(None);
        event.record(&mut message);
        if let Some(reason) = message.0
            && self.0.fetch_add(1, Ordering::Relaxed) < 16
        {
            eprintln!("{{\"event\":\"h2_test_limit\",\"reason\":\"{reason}\"}}");
        }
    }
}
pub fn install() {
    tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(Limits(
        AtomicUsize::new(0),
    )))
    .expect("isolated driver owns its diagnostic subscriber");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_fixed_categories_survive() {
        install();
        assert_eq!(
            category("recv_reset; remotely-reset pending-accept streams reached limit (32)"),
            Some("pending_resets")
        );
        assert_eq!(
            category("locally-reset streams reached limit (8)"),
            Some("internal_resets")
        );
        assert_eq!(
            category("reset_on_recv_stream_err; locally-reset streams reached limit (8)"),
            Some("internal_resets")
        );
        assert_eq!(
            category("https://private.example/?secret=must-not-log"),
            None
        );
    }
}
