// SPDX-License-Identifier: MIT

//! Transport-layer error sanitization for the D-Bus trust boundary.
//!
//! # Why this module exists (services-sweep SVC-4 / Task 3A.5 finding F7)
//!
//! Domain crates (`die-orchestrator`, `semantic-fs`, `die-inference`, …)
//! format errors with full operational detail — filesystem paths, SQLite
//! messages, query fragments. That detail is correct for local `tracing`
//! diagnostics, but every `#[zbus::interface]` method is reachable by any
//! session-bus caller, so the D-Bus boundary is a trust edge. Returning a
//! domain error verbatim (`Failed(e.to_string())`) re-opens the
//! filesystem-existence / path-disclosure oracle that Codex closed in Task
//! 3A.5 (finding F7) and re-flagged crate-wide as services-sweep finding
//! SVC-4.
//!
//! [`opaque`] is the single sanctioned domain-error → `zbus::fdo::Error`
//! translation site, mirroring `workspace.rs::map_workspace_error`: the full
//! error goes to `tracing::warn!` for the operator; only a fixed,
//! content-free message crosses the bus. Constructing
//! `zbus::fdo::Error::Failed` directly from a domain error's `to_string()`
//! is a policy violation — route it through [`opaque`].
//!
//! Note: lock-poison (`PoisonError`) and `serde_json` serialization errors
//! are left on their existing fixed-prefix messages — those carry no path /
//! PII / caller content and are not part of the SVC-4 leak surface.

use std::fmt::Display;

use die_orchestrator::OrchestratorError;

/// Translate a domain error into an opaque `zbus::fdo::Error::Failed`
/// carrying only the fixed, caller-supplied `context`. The full error is
/// logged locally via `tracing::warn!`; no part of `err` crosses the D-Bus
/// boundary, so paths / PII / internal state cannot reach a session-bus
/// caller.
///
/// `context` MUST be a `&'static str` describing the operation
/// (e.g. `"file search failed"`) and MUST NOT be interpolated with caller
/// input or domain detail.
pub(crate) fn opaque<E: Display>(context: &'static str, err: E) -> zbus::fdo::Error {
    tracing::warn!(context, error = %err, "service operation failed");
    zbus::fdo::Error::Failed(context.to_string())
}

/// Translate an [`OrchestratorError`] into a `zbus::fdo::Error` using the
/// SVC-9 typed-variant mapping (define once, use everywhere). The typed
/// variants carry only `&'static str` fields (subsystem / field / reason /
/// entity), so their messages are safe to surface; everything else — the
/// legacy `Planning` catch-all and the downstream-wrapped variants — is
/// sanitized through [`opaque`] so no path / PII / id leaks.
///
/// - `Validation { field, reason, .. }` → `InvalidArgs("validation failed: {field} ({reason})")`
/// - `NotFound { entity }` → `InvalidArgs("{entity} not found")` (no id leak)
/// - `Conflict { domain, reason }` → `Failed("{domain} state conflict ({reason})")`
/// - everything else → [`opaque`]`(context, err)`
pub(crate) fn map_orchestrator(
    context: &'static str,
    err: OrchestratorError,
) -> zbus::fdo::Error {
    match err {
        OrchestratorError::Validation { field, reason, .. } => {
            zbus::fdo::Error::InvalidArgs(format!("validation failed: {field} ({reason})"))
        }
        OrchestratorError::NotFound { entity } => {
            zbus::fdo::Error::InvalidArgs(format!("{entity} not found"))
        }
        OrchestratorError::Conflict { domain, reason } => {
            zbus::fdo::Error::Failed(format!("{domain} state conflict ({reason})"))
        }
        other => opaque(context, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semantic_fs::SemanticFsError;

    const SENTINEL: &str = "/home/secret-user/private/vault.db";

    #[test]
    fn opaque_returns_only_the_fixed_context() {
        let e = opaque("file search failed", "raw detail token /tmp/x: denied");
        assert_eq!(
            e.to_string(),
            "org.freedesktop.DBus.Error.Failed: file search failed"
        );
    }

    #[test]
    fn opaque_drops_path_bearing_domain_detail() {
        // A real semantic-fs error that embeds a filesystem path. Sanity-check
        // the raw error DOES contain the path first, so the assertion below
        // cannot pass for the wrong reason (Task 3A.6 R3 TDD-soundness).
        let err = SemanticFsError::FileIo {
            path: SENTINEL.to_string(),
            reason: "permission denied".to_string(),
        };
        assert!(err.to_string().contains(SENTINEL));

        let msg = opaque("file search failed", err).to_string();
        assert!(!msg.contains(SENTINEL), "leaked path: {msg}");
        assert!(!msg.contains("secret-user"), "leaked path fragment: {msg}");
    }

    #[test]
    fn map_orchestrator_maps_typed_variants_and_sanitizes_the_rest() {
        let v = map_orchestrator(
            "ctx",
            OrchestratorError::Validation {
                domain: "goal",
                field: "title",
                reason: "must not be empty",
            },
        );
        assert!(matches!(v, zbus::fdo::Error::InvalidArgs(_)));
        assert!(v.to_string().ends_with("validation failed: title (must not be empty)"));

        let nf = map_orchestrator("ctx", OrchestratorError::NotFound { entity: "goal" });
        assert!(matches!(nf, zbus::fdo::Error::InvalidArgs(_)));
        assert!(nf.to_string().ends_with("goal not found"));

        let c = map_orchestrator(
            "ctx",
            OrchestratorError::Conflict {
                domain: "goal",
                reason: "cycle",
            },
        );
        assert!(matches!(c, zbus::fdo::Error::Failed(_)));
        assert!(c.to_string().ends_with("goal state conflict (cycle)"));

        // The legacy catch-all is sanitized — a path must not leak.
        let p = map_orchestrator(
            "operation failed",
            OrchestratorError::Planning("/home/secret/db.sqlite: boom".to_string()),
        );
        assert!(matches!(p, zbus::fdo::Error::Failed(_)));
        assert!(!p.to_string().contains("secret"), "leaked: {p}");
        assert!(p.to_string().ends_with("operation failed"));
    }
}
