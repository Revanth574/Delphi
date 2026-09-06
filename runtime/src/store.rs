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
    /// MONOTONIC instant at which the token for this action was minted (D0A-R25-01's
    /// sibling, D0A-R25-04). `None` until the action reaches `Granted`.
    ///
    /// The token's own TTL is checked against `SystemTime` because the issue time is bound
    /// into the token's MAC and must survive as an absolute value. But a security LIFETIME
    /// measured on an adjustable clock can be extended by adjusting it: setting the wall
    /// clock back makes `now - issued_at` shrink, and a token stays live for as long as the
    /// clock keeps moving backwards. `Instant` cannot be set, so the elapsed check that
    /// actually gates execution reads this instead.
    pub granted_at: Option<std::time::Instant>,
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
        self.entries.insert(id, PendingEntry { action, state: PendingState::Proposed, granted_at: None });
    }

    /// Move an entry to `Granted`, stamping the monotonic consent instant in the same step.
    ///
    /// Returns `false` if no entry has that id.
    ///
    /// The two fields are set TOGETHER and only here (D0A-R25-04). Setting `state` by hand
    /// leaves `granted_at` unset, which `present_and_execute` treats as fail-closed — so a
    /// split update produces an action that can never execute, and six integration fixtures
    /// did exactly that the moment the field was added. Making the transition a single
    /// operation removes the drift rather than relying on every future caller to set both.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use delphi_runtime::store::{PendingStore, PendingState};
    /// # fn f(store: &mut PendingStore, id: &str) {
    /// assert!(store.grant(id));
    /// assert_eq!(store.get(id).unwrap().state, PendingState::Granted);
    /// assert!(store.get(id).unwrap().granted_at.is_some());
    /// # }
    /// ```
    pub fn grant(&mut self, pending_id: &str) -> bool {
        match self.entries.get_mut(pending_id) {
            Some(e) => {
                e.state = PendingState::Granted;
                e.granted_at = Some(std::time::Instant::now());
                true
            }
            None => false,
        }
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
