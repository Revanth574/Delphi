// SPDX-License-Identifier: MIT

//! Payload size caps for the D-Bus trust boundary (services-sweep SVC-6).
//!
//! Every `#[zbus::interface]` method is reachable by any session-bus caller.
//! Without bounds, a hostile caller can hand a method an arbitrarily large
//! string / JSON blob, forcing unbounded allocation, parsing, or storage — a
//! denial-of-service amplification on top of the bus's own message limit.
//!
//! The caps are defined **once here** (auditable, uniform across the crate)
//! rather than magic-numbered per service, and are intentionally generous so
//! legitimate inputs are unaffected. Bump a constant here if pilot users hit a
//! ceiling — the change is one edit with crate-wide effect.

/// Maximum byte length for a general caller-supplied string / JSON parameter.
pub const MAX_STRING_BYTES: usize = 1 << 20; // 1 MiB

/// Maximum byte length for `knowledge.ingest_text`'s `text` payload, which is
/// legitimately larger than a typical parameter (it can be a whole document).
pub const MAX_INGEST_TEXT_BYTES: usize = 8 << 20; // 8 MiB

/// Maximum number of entries in a caller-supplied `HashMap<String, String>`
/// parameter (currently only `workspace.create_from_template`'s `params`).
/// Bounds both unbounded-allocation DoS and per-entry oversize via
/// [`ensure_map_within`] (SVC-6-R2-3).
pub const MAX_MAP_ENTRIES: usize = 256;

/// Reject a caller-supplied string that exceeds `max` bytes, *before* it is
/// parsed or stored. The error names only the field and the limit — never the
/// oversized content — so it leaks no caller data across the bus.
///
/// `field` MUST be a `&'static str` parameter name (e.g. `"spec_json"`).
pub(crate) fn ensure_within(
    value: &str,
    max: usize,
    field: &'static str,
) -> zbus::fdo::Result<()> {
    let len = value.len();
    if len > max {
        tracing::warn!(field, len, max, "D-Bus payload exceeds size cap");
        return Err(zbus::fdo::Error::InvalidArgs(format!(
            "{field} exceeds the {max}-byte limit"
        )));
    }
    Ok(())
}

/// Reject a caller-supplied `HashMap<String, String>` whose cardinality
/// exceeds `max_entries` or whose keys/values exceed `max_bytes` each
/// (SVC-6-R2-3). The leak-safe guarantees of [`ensure_within`] extend
/// transitively: only the field name and the limits are surfaced, never the
/// rejected key/value content.
pub(crate) fn ensure_map_within(
    map: &std::collections::HashMap<String, String>,
    max_entries: usize,
    max_bytes: usize,
    field: &'static str,
) -> zbus::fdo::Result<()> {
    if map.len() > max_entries {
        tracing::warn!(
            field,
            entries = map.len(),
            max_entries,
            "D-Bus map exceeds entry cap"
        );
        return Err(zbus::fdo::Error::InvalidArgs(format!(
            "{field} exceeds the {max_entries}-entry limit"
        )));
    }
    for (k, v) in map {
        ensure_within(k, max_bytes, field)?;
        ensure_within(v, max_bytes, field)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit_is_ok() {
        assert!(ensure_within("small", MAX_STRING_BYTES, "field").is_ok());
        // Exactly at the limit is allowed.
        let exact = "a".repeat(MAX_STRING_BYTES);
        assert!(ensure_within(&exact, MAX_STRING_BYTES, "field").is_ok());
    }

    #[test]
    fn over_limit_is_invalid_args_without_leaking_content() {
        let secret = format!("SECRET-{}", "a".repeat(MAX_STRING_BYTES));
        let err = ensure_within(&secret, MAX_STRING_BYTES, "spec_json").unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
        let msg = err.to_string();
        // The field name and limit are fine to surface; the content is not.
        assert!(msg.contains("spec_json"));
        assert!(!msg.contains("SECRET"));
    }
}
