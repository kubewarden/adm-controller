//! Bridges ferricel guest log events (`cel_log` host import) to the Kubewarden
//! `policy_log` tracing target.
//!
//! The ferricel wasm module calls `env::cel_log(ptr, len)` for every guest log
//! statement. ferricel-core deserializes the raw JSON payload into a structured
//! [`ferricel_types::LogEvent`] and dispatches it to the `slog::Logger` held in
//! [`HostState`](ferricel_core::runtime). The logger built here receives those
//! records and re-emits them as host-side `tracing` events under
//! `target: "policy_log"` — exactly the same target and field layout used by
//! the waPC `tracing/log` host callback (`policy_tracing.rs`).
//!
//! `policy_id` is attached at construction time and included in every event,
//! matching how `callback.rs` carries it for other runtimes.

use std::sync::Arc;

use slog::{Drain, KV, Key, OwnedKVList, Record, Serializer};
use tracing::Level;

// ─── Drain ────────────────────────────────────────────────────────────────────

/// An `slog::Drain` that forwards log records to the `policy_log` tracing target.
///
/// Constructed once per evaluation via [`policy_logger`] and injected into the
/// ferricel [`EnginePre::rehydrate`](ferricel_core::EnginePre::rehydrate) call
/// in [`StackPre::rehydrate`](crate::runtimes::ferricel::StackPre::rehydrate).
pub(crate) struct PolicyLogDrain {
    policy_id: Arc<str>,
}

impl Drain for PolicyLogDrain {
    // Never fails; internal errors are swallowed rather than panicking.
    type Ok = ();
    type Err = slog::Never;

    fn log(&self, record: &Record<'_>, values: &OwnedKVList) -> Result<(), slog::Never> {
        // Collect all structured KV pairs (file, line, column, extra, …) into a
        // JSON map.  Errors during serialization are silently ignored — a drain
        // must never panic.
        let data: serde_json::Value = {
            let mut serializer = JsonMapSerializer::default();
            // KV on the record itself (e.g. custom key-values added by the log site).
            let _ = record.kv().serialize(record, &mut serializer);
            // KV accumulated on the logger (e.g. "file", "line", "column", "extra"
            // fields added by ferricel-core when it builds the child logger).
            let _ = values.serialize(record, &mut serializer);
            serde_json::Value::Object(serializer.map)
        };

        let message = record.msg().to_string();
        let policy_id = self.policy_id.as_ref();

        // Emit under the same "policy_log" target used by the waPC path.
        match record.level() {
            slog::Level::Critical | slog::Level::Error => {
                tracing::event!(
                    target: "policy_log",
                    Level::ERROR,
                    policy_id,
                    data = %data,
                    "{message}",
                );
            }
            slog::Level::Warning => {
                tracing::event!(
                    target: "policy_log",
                    Level::WARN,
                    policy_id,
                    data = %data,
                    "{message}",
                );
            }
            slog::Level::Info => {
                tracing::event!(
                    target: "policy_log",
                    Level::INFO,
                    policy_id,
                    data = %data,
                    "{message}",
                );
            }
            slog::Level::Debug => {
                tracing::event!(
                    target: "policy_log",
                    Level::DEBUG,
                    policy_id,
                    data = %data,
                    "{message}",
                );
            }
            slog::Level::Trace => {
                tracing::event!(
                    target: "policy_log",
                    Level::TRACE,
                    policy_id,
                    data = %data,
                    "{message}",
                );
            }
        }

        Ok(())
    }
}

/// Build a `slog::Logger` that routes guest log events to `policy_log` tracing
/// events carrying the given `policy_id`.
///
/// Called from [`StackPre::rehydrate`](crate::runtimes::ferricel::StackPre::rehydrate)
/// so the logger is created fresh per evaluation with the correct `policy_id`.
pub(crate) fn policy_logger(policy_id: impl Into<Arc<str>>) -> slog::Logger {
    let drain = PolicyLogDrain {
        policy_id: policy_id.into(),
    };
    slog::Logger::root(drain.fuse(), slog::o!())
}

// ─── Serializer ──────────────────────────────────────────────────────────────

/// Collects slog key-value pairs into a `serde_json::Map`.
///
/// ferricel-core emits the `extra` field as a pre-serialized JSON string (e.g.
/// `"{\"key\":\"val\"}"`) rather than a nested object. This serializer detects
/// string values that are valid JSON objects or arrays and re-parses them inline
/// so that `data` stays flat rather than containing a doubly-encoded string.
#[derive(Default)]
struct JsonMapSerializer {
    map: serde_json::Map<String, serde_json::Value>,
}

impl Serializer for JsonMapSerializer {
    fn emit_str(&mut self, key: Key, val: &str) -> slog::Result {
        // Try to parse as JSON first; if it succeeds use the parsed value so
        // that nested objects/arrays surface as proper JSON rather than strings.
        let value = serde_json::from_str::<serde_json::Value>(val)
            .unwrap_or_else(|_| serde_json::Value::String(val.to_owned()));
        self.map.insert(key.to_owned(), value);
        Ok(())
    }

    fn emit_usize(&mut self, key: Key, val: usize) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_u64(&mut self, key: Key, val: u64) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_u32(&mut self, key: Key, val: u32) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_isize(&mut self, key: Key, val: isize) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_i64(&mut self, key: Key, val: i64) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_i32(&mut self, key: Key, val: i32) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_bool(&mut self, key: Key, val: bool) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_f64(&mut self, key: Key, val: f64) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::json!(val));
        Ok(())
    }

    fn emit_arguments(&mut self, key: Key, val: &std::fmt::Arguments<'_>) -> slog::Result {
        let s = val.to_string();
        // Same re-parse attempt as emit_str.
        let value =
            serde_json::from_str::<serde_json::Value>(&s).unwrap_or(serde_json::Value::String(s));
        self.map.insert(key.to_owned(), value);
        Ok(())
    }

    fn emit_none(&mut self, key: Key) -> slog::Result {
        self.map.insert(key.to_owned(), serde_json::Value::Null);
        Ok(())
    }
}
