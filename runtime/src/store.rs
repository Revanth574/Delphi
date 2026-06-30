// SPDX-License-Identifier: MIT

//! The daemon's in-memory pending-action registry (Increment B1).
//!
//! THE HALF-(ii) SOURCE OF TRUTH. Each AI proposal is canonicalized into one
//! [`PendingAction`] and stored here under a `pending_id`. The human approves THAT
//! object's preview; the token is bound to THAT object's digest; and at `Present`
//! the daemon executes THIS STORED object — never anything re-supplied on the wire.
//! `Present` carries no action data, so there is nowhere to inject a different
//! action B (see `proto/runtime_wire.proto`).
//!
//! In-memory and per-daemon: empty on (re)start ⇒ every prior approval fails closed
//! (`docs/TRUST_MODEL.md` §4 failure modes — "the in-memory PendingAction registry
//! is empty ⇒ all pending approvals fail-closed").

use std::collections::HashMap;

use crate::action::PendingAction;

/// The lifecycle of a registered action. The transitions are the protocol's state
/// machine; a `Present` is only honored against a `Granted` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    /// Canonicalized + stored; consent not yet granted.
    Proposed,
    /// Human-approved, token minted + delivered to the AI; awaiting `Present`.
    Granted,
    /// One-shot consumed (executed) — terminal.
    Consumed,
}

/// One registered action: the canonical object (the source of truth) + its state.
pub struct PendingEntry {
    /// The canonical action — the ONLY thing the daemon previews / approves /
    /// digest-binds / executes for this `pending_id`.
    pub action: PendingAction,
    /// Where this action is in the consent → present → execute lifecycle.
    pub state: PendingState,
}

/// The daemon's pending registry. The single-threaded service loop owns it; it is
/// never shared with the children (who only ever see a `pending_id`, a preview, or a
/// token — never the canonical object).
#[derive(Default)]
pub struct PendingStore {
    next: u64,
    entries: HashMap<String, PendingEntry>,
}

impl PendingStore {
    /// A fresh, empty registry (the daemon holds one in memory).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next `pending_id`. Decided BEFORE canonicalization so the id is
    /// part of the canonical object's digest (the action and the registry key match).
    pub fn next_id(&mut self) -> String {
        let id = format!("act-{}", self.next);
        self.next += 1;
        id
    }

    /// Register a freshly-canonicalized action in the `Proposed` state. The key is
    /// the action's own `pending_id` (assigned via [`next_id`](Self::next_id)).
    pub fn insert(&mut self, action: PendingAction) {
        let id = action.pending_id.clone();
        self.entries.insert(id, PendingEntry { action, state: PendingState::Proposed });
    }

    /// Borrow a registered entry by id, if present.
    #[must_use]
    pub fn get(&self, pending_id: &str) -> Option<&PendingEntry> {
        self.entries.get(pending_id)
    }

    /// Mutably borrow a registered entry by id, if present (for state transitions).
    pub fn get_mut(&mut self, pending_id: &str) -> Option<&mut PendingEntry> {
        self.entries.get_mut(pending_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{BindMode, NetPolicy, PendingAction, RequiredTier};
    use std::path::PathBuf;
    use std::time::Duration;

    fn action(id: &str) -> PendingAction {
        PendingAction {
            pending_id: id.into(),
            preview_version: 1,
            executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
            executable_digest: [0xAB; 32],
            argv: vec!["t".into()],
            cwd: PathBuf::from("/"),
            env_delta: vec![],
            fs_binds: vec![(PathBuf::from("/x"), BindMode::ReadOnly)],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    #[test]
    fn ids_are_unique_and_entries_round_trip() {
        let mut s = PendingStore::new();
        let id0 = s.next_id();
        let id1 = s.next_id();
        assert_ne!(id0, id1);
        s.insert(action(&id0));
        assert_eq!(s.get(&id0).unwrap().state, PendingState::Proposed);
        s.get_mut(&id0).unwrap().state = PendingState::Granted;
        assert_eq!(s.get(&id0).unwrap().state, PendingState::Granted);
        assert!(s.get("act-999").is_none(), "unknown id absent (fail-closed)");
    }
}
