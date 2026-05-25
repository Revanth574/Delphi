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
