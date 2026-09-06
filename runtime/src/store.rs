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

/// Has the consent window elapsed? A PURE function of the two readings and the TTL.
///
/// **D0A-R27 self-correction.** The clock change (R26-03) shipped with a test that reads the
/// real clock, and a reviewer's mutation — swapping production `CLOCK_BOOTTIME` for
/// `CLOCK_MONOTONIC` — **still passed it**. On a machine that has never suspended the two are
/// identical, so that test discriminates NEITHER suspend behaviour NOR clock identity. The
/// disclosure written beside it ("checks identity, not suspend behaviour") therefore CLAIMED
/// MORE THAN THE TEST DID, which is worse than no disclosure: it stops the question being
/// asked.
///
/// Separating the decision from the reading is what makes expiry testable at all — the edges
/// (exactly at TTL, one past, a clock that went backwards) are reachable with injected values
/// and unreachable through a real clock.
///
/// # Examples
///
/// ```
/// use delphi_runtime::store::consent_window_elapsed;
/// assert!(!consent_window_elapsed(100, 130, 30), "exactly at the TTL is still live");
/// assert!(consent_window_elapsed(100, 131, 30), "one second past is expired");
/// ```
#[must_use]
pub fn consent_window_elapsed(granted_at: u64, now: u64, ttl_secs: u64) -> bool {
    // `saturating_sub` makes a backwards reading (which CLOCK_BOOTTIME forbids, but a corrupt
    // or mocked value could produce) read as ZERO elapsed rather than as a huge unsigned
    // wrap — fail-closed would be the opposite, so it is stated: a backwards clock cannot
    // EXPIRE a token early, and cannot extend one either, because the boot clock cannot be set.
    now.saturating_sub(granted_at) > ttl_secs
}

/// `CLOCK_BOOTTIME` in whole seconds — monotonic AND suspend-inclusive (D0A-R26-03).
///
/// `None` if the clock cannot be read, which every caller treats as fail-closed. See
/// [`PendingEntry::granted_at_boot_secs`] for why this clock and not `Instant`.
#[must_use]
pub fn boot_secs() -> Option<u64> {
    // SAFETY: `clock_gettime` writes through a pointer to a `timespec` this frame owns and
    // fully initialises; the return value is checked before the value is read. CLOCK_BOOTTIME
    // has existed since Linux 2.6.39.
    unsafe {
        let mut ts: nix::libc::timespec = std::mem::zeroed();
        if nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut ts) != 0 {
            return None;
        }
        u64::try_from(ts.tv_sec).ok()
    }
}

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
    /// `CLOCK_BOOTTIME` seconds at which the token for this action was minted (D0A-R25-04,
    /// corrected by D0A-R26-03). `None` until the action reaches `Granted`.
    ///
    /// The token's own TTL is checked against `SystemTime` because the issue time is bound
    /// into the token's MAC and must survive as an absolute value. But a security LIFETIME
    /// measured on an adjustable clock can be extended by adjusting it: setting the wall clock
    /// back makes `now - issued_at` shrink, and a token stays live for as long as the clock
    /// keeps moving backwards.
    ///
    /// **Why not `Instant` — which is what R25-04 used.** Rust's `Instant` is `CLOCK_MONOTONIC`
    /// on Linux (measured: a 51.048 ms `elapsed()` against a 0.051 s `CLOCK_MONOTONIC` delta),
    /// and `CLOCK_MONOTONIC` **does not advance while the machine is suspended**. So a laptop
    /// closed for an hour between consent and `Present` returns with its consent window barely
    /// moved — the token outlives its TTL in wall-clock reality by exactly the suspend
    /// duration, which is the scenario an unattended machine makes routine. `CLOCK_BOOTTIME`
    /// is the same monotonic guarantee INCLUDING suspend, so it is the one a consent window
    /// must be measured on.
    pub granted_at_boot_secs: Option<u64>,
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
        self.entries.insert(id, PendingEntry { action, state: PendingState::Proposed, granted_at_boot_secs: None });
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
    /// assert!(store.get(id).unwrap().granted_at_boot_secs.is_some());
    /// # }
    /// ```
    pub fn grant(&mut self, pending_id: &str) -> bool {
        match self.entries.get_mut(pending_id) {
            Some(e) => {
                e.state = PendingState::Granted;
                e.granted_at_boot_secs = boot_secs();
                // A clock that cannot be read is fail-closed, not fail-open: leaving this
                // `None` makes `present_and_execute` refuse the action (D0A-R26-03).
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
            required_tier: RequiredTier::Confirm,
            script: None,
        }
    }

    /// D0A-R27 — the consent-window decision, at every edge, with NO clock involved.
    ///
    /// This is the coverage the clock test could not provide. A reviewer's mutation replaced
    /// production `CLOCK_BOOTTIME` with `CLOCK_MONOTONIC` and the clock test still passed, so
    /// expiry had no discriminating test at all. These edges are unreachable through a real
    /// clock and are the whole of the decision.
    #[test]
    fn the_consent_window_decision_is_exact_at_its_edges() {
        const TTL: u64 = 30;
        assert!(!consent_window_elapsed(1_000, 1_000, TTL), "same instant is live");
        assert!(!consent_window_elapsed(1_000, 1_029, TTL), "one before the TTL is live");
        assert!(!consent_window_elapsed(1_000, 1_030, TTL), "EXACTLY at the TTL is live");
        assert!(consent_window_elapsed(1_000, 1_031, TTL), "one past the TTL is expired");
        assert!(consent_window_elapsed(1_000, u64::MAX, TTL), "far future is expired");
        // A backwards reading reads as zero elapsed, not as an unsigned wrap to ~u64::MAX.
        assert!(
            !consent_window_elapsed(1_000, 900, TTL),
            "a backwards reading must not wrap into 'expired' — it reads as zero elapsed"
        );
    }

    /// D0A-R26-03 / D0A-R27 — `boot_secs` agrees with a direct `CLOCK_BOOTTIME` read.
    ///
    /// **THIS TEST DISCRIMINATES NOTHING ON A MACHINE THAT HAS NEVER SUSPENDED, AND SAYS SO
    /// OUT LOUD.** `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` differ by exactly the accumulated
    /// suspend time; where that is zero, production could read either and this test passes
    /// — which a reviewer demonstrated by mutation. The previous version of this comment
    /// claimed it "checks clock IDENTITY"; it does not, here.
    ///
    /// It is kept because it costs nothing and becomes a real discriminator on a lane that has
    /// suspended. It prints the measured delta so a reader can see whether this run had any
    /// discriminating power at all, rather than inferring it from green.
    #[test]
    fn boot_secs_agrees_with_a_direct_boottime_read_and_reports_its_own_discriminating_power() {
        let read = |clk| unsafe {
            let mut ts: nix::libc::timespec = std::mem::zeroed();
            assert_eq!(nix::libc::clock_gettime(clk, &mut ts), 0, "clock must be readable");
            ts.tv_sec as i64
        };
        let boot = read(nix::libc::CLOCK_BOOTTIME);
        let mono = read(nix::libc::CLOCK_MONOTONIC);
        let ours = boot_secs().expect("boot_secs must read the clock") as i64;
        assert!(
            (ours - boot).abs() <= 1,
            "boot_secs ({ours}) disagrees with CLOCK_BOOTTIME ({boot}) beyond the sampling gap"
        );
        let delta = boot - mono;
        eprintln!(
            "DISCRIMINATION: BOOTTIME - MONOTONIC = {delta}s.              {}",
            if delta > 1 {
                "This lane HAS suspended — the assertion above distinguishes the two clocks."
            } else {
                "This lane has NOT suspended — the two clocks are identical here, so this test                  CANNOT distinguish them and a green proves nothing about clock selection.                  Expiry coverage comes from the_consent_window_decision_is_exact_at_its_edges."
            }
        );
        assert!(boot_secs().expect("second read") as i64 >= ours, "the boot clock went backwards");
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
