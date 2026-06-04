// SPDX-License-Identifier: MIT

//! Caller-identity + permission-tier authorization at the D-Bus boundary
//! (services-sweep SVC-2).
//!
//! # The problem
//!
//! Every `#[zbus::interface]` method in this crate executes regardless of the
//! caller or the action's sensitivity. [`fortress::permissions::PermissionChecker`]
//! exists but is wired into nothing, and its `module` argument is a
//! *self-reported* string — there is no authenticated caller identity. SVC-2
//! makes authorization a structural property of the boundary.
//!
//! # The layered model
//!
//! Two orthogonal layers, kept deliberately distinct (the SVC-1-R1-1-01
//! clarification: a recognized caller can be [`AuthOutcome::Authorized`] at the
//! *identity* layer yet still need [`AuthOutcome::ConfirmationRequired`] at the
//! *tier* layer):
//!
//! 1. **Tier gating** ([`authorize`]). Every method is classified
//!    ([`METHOD_POLICY`], Codex's verbatim table) into a [`PermissionTier`].
//!    Read-only → `Autonomous` (proceed); mutating → `Confirm`; destructive /
//!    reversal / `forget_*` → `Biometric`. An *unmapped* method is denied by
//!    default (fail-closed). The tier comes from the unchanged
//!    `PermissionChecker`, fed SVC-2's classification as rules.
//!
//! 2. **Caller identity** ([`CallerIdentity`], [`AuthPolicy`]). The standard
//!    session bus is **not** a security boundary (a stated SVC-2 invariant, not
//!    a silent assumption). So:
//!    - **Dev** ([`BusTrust::DevLogAndAllow`]): an unrecognized caller to a
//!      gated method is logged-and-allowed with a loud warning. Recognition is
//!      best-effort (the shell's unique name is recorded when it registers).
//!    - **Deployed** ([`BusTrust::DeployedDeny`]): an unrecognized caller is
//!      denied; recognition is structural (authenticated socket peer / dedicated
//!      bus).
//!
//! # The SVC-1-R1-1-01 closure — same-caller binding
//!
//! SVC-1 closed token *forgery* (the HMAC `ConfirmationToken`) but not
//! *consent*: a caller can obtain a token and echo it back in a second call
//! with no human ever seeing the preview. SVC-2 closes that with
//! [`authorize_cloud_send`]: a cloud-send confirmation is **bound to the unique
//! bus name of the caller that requested it** ([`CloudSendConfirmations`]). A
//! completion from a *different* unique name is rejected. This works on the
//! ordinary dev session bus — caller A and caller B have different bus-assigned
//! unique names — which is exactly why the closure test runs in dev. Unlike
//! general methods, a binding violation is a hard **deny in both** dev and
//! deployment (cloud-send is the stricter category). Deployed mode additionally
//! requires the completer to be the authenticated shell.
//!
//! # Stage boundaries (this module is the SVC-2 *foundation*)
//!
//! This module is the pure, bus-free policy core: the typed outcomes, the tier
//! catalogue, and the synchronous decision functions over an *already-resolved*
//! [`CallerIdentity`]. Resolving that identity from the live message (the
//! `#[zbus(header)]` sender + a `fdo::DBusProxy` credential round-trip) and the
//! `NameOwnerChanged`-invalidated identity cache is the async Stage-1b resolver;
//! threading the guard into every method is Stage 2; the live cloud-send seam +
//! its RED closure test is Stage 3.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use fortress::permissions::{PermissionChecker, PermissionRule, PermissionTier};
use tracing::warn;

/// How long a cloud-send confirmation remains completable (SVC-2 Q9 cache:
/// TTL is defense-in-depth *on top of* same-caller binding, not the primary
/// control). Short by design — the user approves within seconds.
pub const CLOUD_SEND_TTL: Duration = Duration::from_secs(120);

/// The bus-trust posture (SVC-2 Layer 2). Drives unrecognized-caller handling,
/// the `Biometric` dev-degradation, and the deployed cloud-send shell check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusTrust {
    /// v0.4 dev on the standard session bus (NOT a security boundary):
    /// unrecognized callers are logged-and-allowed; `Biometric` degrades to the
    /// strongest available confirmation (no biometric hardware in dev).
    DevLogAndAllow,
    /// Deployed on a dedicated/authenticated bus: unrecognized callers are
    /// denied; `Biometric`/`Hardware` are real gates.
    DeployedDeny,
}

/// The authenticated identity of a D-Bus caller, resolved at the boundary from
/// the message's unique sender name (Stage 1b populates `uid`/`pid` via
/// `fdo::DBusProxy::get_connection_credentials`).
///
/// The `unique_name` is assigned by the bus daemon and cannot be spoofed by a
/// peer, which is what makes same-caller binding sound even on the dev session
/// bus. `uid`/`pid` are only structurally meaningful under the deployed
/// authenticated-socket model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    /// The bus-assigned unique name, e.g. `:1.42`.
    pub unique_name: String,
    /// Resolved caller uid (deployed-meaningful), if known.
    pub uid: Option<u32>,
    /// Resolved caller pid (deployed-meaningful), if known.
    pub pid: Option<u32>,
}

impl CallerIdentity {
    /// Construct from a unique bus name with creds unresolved (the common
    /// dev-path identity; Stage 1b fills creds when policy needs them).
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::CallerIdentity;
    ///
    /// let caller = CallerIdentity::from_unique_name(":1.42");
    /// assert_eq!(caller.unique_name, ":1.42");
    /// assert!(caller.uid.is_none());
    /// ```
    #[must_use]
    pub fn from_unique_name(unique_name: impl Into<String>) -> Self {
        Self {
            unique_name: unique_name.into(),
            uid: None,
            pid: None,
        }
    }
}

/// The confirmation strength the shell must satisfy for a tiered action.
///
/// Decision A: in dev, `Biometric`/`Hardware` *degrade* to the strongest
/// available confirmation ([`ConfirmationStrength::TypeToConfirm`]) rather than
/// a hard hardware gate, so the Biometric-tier tests are runnable without
/// biometric hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationStrength {
    /// An explicit user "OK" (the `Confirm` tier).
    Confirm,
    /// Dev-degraded `Biometric`/`Hardware`: the strongest confirmation
    /// available without dedicated hardware (e.g. type-to-confirm).
    TypeToConfirm,
    /// A real biometric gate (deployed `Biometric` tier).
    Biometric,
    /// A real hardware gate (deployed `Hardware` tier).
    Hardware,
}

impl ConfirmationStrength {
    /// Map a required `tier` + bus posture to the confirmation strength.
    /// `Autonomous` returns `None` — no confirmation, the caller is authorized
    /// outright.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{BusTrust, ConfirmationStrength};
    /// use fortress::permissions::PermissionTier;
    ///
    /// // Biometric degrades to type-to-confirm in dev (Decision A)…
    /// assert_eq!(
    ///     ConfirmationStrength::for_tier(PermissionTier::Biometric, BusTrust::DevLogAndAllow),
    ///     Some(ConfirmationStrength::TypeToConfirm),
    /// );
    /// // …but is a real gate when deployed.
    /// assert_eq!(
    ///     ConfirmationStrength::for_tier(PermissionTier::Biometric, BusTrust::DeployedDeny),
    ///     Some(ConfirmationStrength::Biometric),
    /// );
    /// // Autonomous needs no confirmation.
    /// assert_eq!(
    ///     ConfirmationStrength::for_tier(PermissionTier::Autonomous, BusTrust::DevLogAndAllow),
    ///     None,
    /// );
    /// ```
    #[must_use]
    pub fn for_tier(tier: PermissionTier, bus: BusTrust) -> Option<Self> {
        match tier {
            PermissionTier::Autonomous => None,
            PermissionTier::Confirm => Some(Self::Confirm),
            PermissionTier::Biometric => Some(match bus {
                BusTrust::DevLogAndAllow => Self::TypeToConfirm,
                BusTrust::DeployedDeny => Self::Biometric,
            }),
            PermissionTier::Hardware => Some(match bus {
                BusTrust::DevLogAndAllow => Self::TypeToConfirm,
                BusTrust::DeployedDeny => Self::Hardware,
            }),
        }
    }
}

/// The typed outcome of an authorization check. Names align with the SVC-9
/// typed-result contract. Identity rejection ([`AuthOutcome::AuthorizationDenied`])
/// and tier confirmation ([`AuthOutcome::ConfirmationRequired`]) are
/// **distinct** — the former is "you may not attempt this", the latter is "you
/// may attempt it, but a human must confirm first (in the shell)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Proceed immediately — `Autonomous` tier and (where required) a recognized
    /// caller.
    Authorized,
    /// Authorized to *attempt*, but the tier requires user confirmation of the
    /// given `strength` before the shell completes the action. NOT a denial.
    ConfirmationRequired {
        /// The required tier (drives the shell's confirmation UI).
        tier: PermissionTier,
        /// The confirmation strength (dev-degraded per [`ConfirmationStrength`]).
        strength: ConfirmationStrength,
    },
    /// The caller may not attempt the action: an unmapped method (fail-closed),
    /// an unrecognized caller under a deny policy, or a cloud-send completion
    /// that fails same-caller binding (the SVC-1-R1-1-01 closure). The reason is
    /// a leak-safe `&'static str` (never caller data — SVC-4 discipline).
    AuthorizationDenied {
        /// A fixed, non-sensitive explanation.
        reason: &'static str,
    },
}

/// Codex's verbatim Q1 tier classification: every inbound D-Bus method →
/// `(action string, tier)`. The action string is the canonical
/// `interface.method` identifier. This is the **explicit known set**: a method
/// absent here is denied by default ([`MethodPolicy::tier_of`] returns `None`).
///
/// Signals are not inbound callable methods and carry no auth gate, so they are
/// absent here by construction.
///
/// `inference.query` is `Autonomous` for the *local* path; the cloud send is the
/// separate `inference.cloud_send` `Confirm` subaction (shell-bound via
/// [`authorize_cloud_send`], then SVC-1 ZKQP egress).
/// `inference.grant_cloud_egress_consent` is the real `Confirm`-tier method the
/// shell calls to grant session destination consent (SVC-2 Piece 2); it mutates
/// the egress-consent state, so it carries a tier like any other mutation.
pub const METHOD_POLICY: &[(&str, PermissionTier)] = &[
    // ── Inference ──
    ("inference.query", PermissionTier::Autonomous),
    ("inference.cloud_send", PermissionTier::Confirm),
    ("inference.grant_cloud_egress_consent", PermissionTier::Confirm),
    ("inference.status", PermissionTier::Autonomous),
    // ── File search ──
    ("file_search.search", PermissionTier::Autonomous),
    // ── Mode ──
    ("mode.get_mode", PermissionTier::Autonomous),
    ("mode.set_mode", PermissionTier::Confirm),
    ("mode.list_modes", PermissionTier::Autonomous),
    // ── Timeline ──
    ("timeline.get_recent", PermissionTier::Autonomous),
    ("timeline.undo", PermissionTier::Biometric),
    ("timeline.count", PermissionTier::Autonomous),
    // ── Learning ──
    ("learning.get_suggestions", PermissionTier::Autonomous),
    ("learning.accept_suggestion", PermissionTier::Confirm),
    ("learning.dismiss_suggestion", PermissionTier::Confirm),
    ("learning.suggestion_count", PermissionTier::Autonomous),
    // ── Conversation ──
    ("conversation.start_conversation", PermissionTier::Confirm),
    ("conversation.add_message", PermissionTier::Confirm),
    ("conversation.recent_messages", PermissionTier::Autonomous),
    ("conversation.search", PermissionTier::Autonomous),
    ("conversation.list_conversations", PermissionTier::Autonomous),
    ("conversation.forget_today", PermissionTier::Biometric),
    ("conversation.forget_topic", PermissionTier::Biometric),
    ("conversation.forget_older_than", PermissionTier::Biometric),
    ("conversation.count", PermissionTier::Autonomous),
    // ── Goals ──
    ("goals.create_goal", PermissionTier::Confirm),
    ("goals.update_goal", PermissionTier::Confirm),
    ("goals.update_progress", PermissionTier::Confirm),
    ("goals.get_goal", PermissionTier::Autonomous),
    ("goals.list_active", PermissionTier::Autonomous),
    ("goals.list_children", PermissionTier::Autonomous),
    ("goals.find_stale", PermissionTier::Autonomous),
    ("goals.find_approaching_deadline", PermissionTier::Autonomous),
    ("goals.get_timeline", PermissionTier::Autonomous),
    ("goals.count", PermissionTier::Autonomous),
    // ── Environment ──
    ("environment.get_state", PermissionTier::Autonomous),
    ("environment.get_battery", PermissionTier::Autonomous),
    ("environment.get_thermal", PermissionTier::Autonomous),
    ("environment.get_memory", PermissionTier::Autonomous),
    ("environment.get_time_context", PermissionTier::Autonomous),
    ("environment.get_location", PermissionTier::Autonomous),
    ("environment.set_location_label", PermissionTier::Confirm),
    ("environment.remove_location_label", PermissionTier::Confirm),
    // ── Health ──
    ("health.check_all", PermissionTier::Autonomous),
    ("health.check_quick", PermissionTier::Autonomous),
    ("health.get_disk_health", PermissionTier::Autonomous),
    ("health.get_project_risk", PermissionTier::Autonomous),
    ("health.get_security_risk", PermissionTier::Autonomous),
    ("health.add_watched_repo", PermissionTier::Confirm),
    ("health.remove_watched_repo", PermissionTier::Confirm),
    ("health.add_expected_network_destination", PermissionTier::Confirm),
    // ── Knowledge ──
    ("knowledge.ingest_file", PermissionTier::Confirm),
    ("knowledge.ingest_text", PermissionTier::Confirm),
    ("knowledge.search", PermissionTier::Autonomous),
    ("knowledge.related_to", PermissionTier::Autonomous),
    ("knowledge.find_path", PermissionTier::Autonomous),
    ("knowledge.list_sources", PermissionTier::Autonomous),
    ("knowledge.detect_contradictions", PermissionTier::Autonomous),
    ("knowledge.forget_source", PermissionTier::Biometric),
    // ── Workspace ──
    ("workspace.preview", PermissionTier::Autonomous),
    ("workspace.create", PermissionTier::Confirm),
    ("workspace.create_from_template", PermissionTier::Confirm),
    ("workspace.list_templates", PermissionTier::Autonomous),
    ("workspace.undo", PermissionTier::Biometric),
];

/// The SVC-2 method→tier policy, expressed through the **unchanged**
/// [`PermissionChecker`] (wire-don't-rebuild): [`METHOD_POLICY`] is loaded as
/// `PermissionRule`s, so the tier decision routes through fortress's sanctioned
/// engine. A separate known-action set provides fail-closed denial for unmapped
/// methods (which the checker would otherwise default to `Confirm`).
pub struct MethodPolicy {
    checker: PermissionChecker,
    known: HashSet<&'static str>,
}

impl MethodPolicy {
    /// Build the policy from [`METHOD_POLICY`]. The same const populates both the
    /// checker rules and the known set, so they cannot drift.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::MethodPolicy;
    /// use fortress::permissions::PermissionTier;
    ///
    /// let policy = MethodPolicy::from_table();
    /// assert_eq!(policy.tier_of("timeline.undo"), Some(PermissionTier::Biometric));
    /// assert_eq!(policy.tier_of("not.a.method"), None); // fail-closed
    /// ```
    #[must_use]
    pub fn from_table() -> Self {
        let rules = METHOD_POLICY
            .iter()
            .map(|(action, tier)| PermissionRule {
                action: (*action).to_string(),
                tier: *tier,
            })
            .collect();
        let known = METHOD_POLICY.iter().map(|(action, _)| *action).collect();
        Self {
            checker: PermissionChecker::new(rules),
            known,
        }
    }

    /// The required tier for `action`, or `None` if the method is unmapped
    /// (fail-closed). Known actions route through the `PermissionChecker`.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::MethodPolicy;
    /// use fortress::permissions::PermissionTier;
    ///
    /// let policy = MethodPolicy::from_table();
    /// assert_eq!(policy.tier_of("file_search.search"), Some(PermissionTier::Autonomous));
    /// assert_eq!(policy.tier_of("mode.set_mode"), Some(PermissionTier::Confirm));
    /// ```
    #[must_use]
    pub fn tier_of(&self, action: &str) -> Option<PermissionTier> {
        if !self.known.contains(action) {
            return None;
        }
        // target/module are not part of the SVC-2 tier decision (identity is
        // carried separately as CallerIdentity, never the self-reported module).
        Some(self.checker.check(action, "", "svc2").actual_tier)
    }
}

/// The Layer-2 caller-identity policy: the bus posture plus the unique name
/// recorded as the shell. The standard session bus is explicitly NOT the
/// security boundary — dev recognition is best-effort, deployed is structural.
#[derive(Debug, Clone)]
pub struct AuthPolicy {
    bus: BusTrust,
    /// The unique bus name recorded as the shell (best-effort in dev, e.g. via
    /// `org.delphi.Shell` ownership; structural in deployed). `None` until the
    /// shell registers.
    shell_unique_name: Option<String>,
}

impl AuthPolicy {
    /// The v0.4 dev policy (log-and-allow on the standard session bus).
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{AuthPolicy, BusTrust};
    ///
    /// assert_eq!(AuthPolicy::dev().bus(), BusTrust::DevLogAndAllow);
    /// ```
    #[must_use]
    pub fn dev() -> Self {
        Self {
            bus: BusTrust::DevLogAndAllow,
            shell_unique_name: None,
        }
    }

    /// The deployed policy (deny unrecognized callers).
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{AuthPolicy, BusTrust};
    ///
    /// assert_eq!(AuthPolicy::deployed().bus(), BusTrust::DeployedDeny);
    /// ```
    #[must_use]
    pub fn deployed() -> Self {
        Self {
            bus: BusTrust::DeployedDeny,
            shell_unique_name: None,
        }
    }

    /// The current bus posture.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{AuthPolicy, BusTrust};
    ///
    /// assert_eq!(AuthPolicy::dev().bus(), BusTrust::DevLogAndAllow);
    /// ```
    #[must_use]
    pub fn bus(&self) -> BusTrust {
        self.bus
    }

    /// Record the shell's unique bus name (called when the shell registers).
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{AuthPolicy, CallerIdentity};
    ///
    /// let mut policy = AuthPolicy::deployed();
    /// policy.record_shell(":1.1");
    /// assert!(policy.is_recognized_shell(&CallerIdentity::from_unique_name(":1.1")));
    /// ```
    pub fn record_shell(&mut self, unique_name: impl Into<String>) {
        self.shell_unique_name = Some(unique_name.into());
    }

    /// Whether `caller` is the recognized shell. With no shell recorded, no
    /// caller is recognized.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{AuthPolicy, CallerIdentity};
    ///
    /// let mut policy = AuthPolicy::deployed();
    /// policy.record_shell(":1.1");
    /// assert!(policy.is_recognized_shell(&CallerIdentity::from_unique_name(":1.1")));
    /// assert!(!policy.is_recognized_shell(&CallerIdentity::from_unique_name(":1.2")));
    /// ```
    #[must_use]
    pub fn is_recognized_shell(&self, caller: &CallerIdentity) -> bool {
        self.shell_unique_name.as_deref() == Some(caller.unique_name.as_str())
    }
}

/// Authorize a (resolved) caller to invoke `action` — the SVC-2 tier+identity
/// decision (Layer 1 + Layer 2), synchronous over an already-resolved identity.
///
/// Order: fail-closed on unmapped → identity gate (deny unrecognized when
/// deployed; warn-and-allow in dev) → tier gate. The tier gate never *denies*;
/// it returns [`AuthOutcome::ConfirmationRequired`] for tier > `Autonomous`.
///
/// # Examples
///
/// ```
/// use delphi_services::auth::{authorize, AuthOutcome, AuthPolicy, CallerIdentity, MethodPolicy};
///
/// let methods = MethodPolicy::from_table();
/// let caller = CallerIdentity::from_unique_name(":1.5");
///
/// // A read-only method proceeds.
/// assert_eq!(
///     authorize("file_search.search", &caller, &AuthPolicy::dev(), &methods),
///     AuthOutcome::Authorized,
/// );
/// // An unmapped method is denied by default.
/// assert!(matches!(
///     authorize("bogus.method", &caller, &AuthPolicy::dev(), &methods),
///     AuthOutcome::AuthorizationDenied { .. },
/// ));
/// ```
#[must_use]
pub fn authorize(
    action: &str,
    caller: &CallerIdentity,
    policy: &AuthPolicy,
    methods: &MethodPolicy,
) -> AuthOutcome {
    // 1. Tier lookup — unmapped methods are denied by default (fail-closed).
    let Some(tier) = methods.tier_of(action) else {
        return AuthOutcome::AuthorizationDenied {
            reason: "unmapped method — denied by default",
        };
    };

    // 2. Identity gate. The session bus is not the security boundary: deny
    //    unrecognized callers only under the deployed policy; in dev, log loudly
    //    and allow (so dev is usable while the trust model stays a stated,
    //    checkable invariant rather than a silent assumption).
    if !policy.is_recognized_shell(caller) {
        match policy.bus() {
            BusTrust::DeployedDeny => {
                return AuthOutcome::AuthorizationDenied {
                    reason: "unrecognized caller on authenticated bus",
                };
            }
            BusTrust::DevLogAndAllow => warn!(
                caller = %caller.unique_name,
                action,
                "SVC-2 dev: unrecognized caller to a gated method — logged-and-allowed \
                 (the session bus is not the security boundary)"
            ),
        }
    }

    // 3. Tier gate (orthogonal to identity — the SVC-1-R1-1-01 clarification).
    match ConfirmationStrength::for_tier(tier, policy.bus()) {
        None => AuthOutcome::Authorized,
        Some(strength) => AuthOutcome::ConfirmationRequired { tier, strength },
    }
}

/// A cloud-send confirmation issued to a specific caller, bound by unique bus
/// name (SVC-1-R1-1-01 same-caller binding) with a TTL for defense-in-depth.
#[derive(Debug, Clone)]
struct IssuedConfirmation {
    caller_unique_name: String,
    issued_at: Instant,
}

/// Registry of pending cloud-send confirmations, each bound to the unique bus
/// name of the caller that requested it. The closure mechanism for
/// SVC-1-R1-1-01: a completion from a different unique name is rejected, which
/// is observable on any bus (distinct unique names) and therefore testable in
/// dev.
#[derive(Debug, Default)]
pub struct CloudSendConfirmations {
    /// operation fingerprint → who it was issued to + when.
    issued: HashMap<String, IssuedConfirmation>,
}

impl CloudSendConfirmations {
    /// Record that `caller` has been issued a cloud-send confirmation for the
    /// operation identified by `fingerprint` (e.g. a hash of the sanitized
    /// prompt / model / max_tokens). A later issue for the same fingerprint
    /// supersedes the earlier one.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::{CallerIdentity, CloudSendConfirmations};
    ///
    /// let mut reg = CloudSendConfirmations::default();
    /// reg.issue("fp-1", &CallerIdentity::from_unique_name(":1.10"));
    /// ```
    pub fn issue(&mut self, fingerprint: impl Into<String>, caller: &CallerIdentity) {
        self.issued.insert(
            fingerprint.into(),
            IssuedConfirmation {
                caller_unique_name: caller.unique_name.clone(),
                issued_at: Instant::now(),
            },
        );
    }

    /// Whether `caller` holds a fresh confirmation for `fingerprint` at `now`.
    /// `now` is injected so the TTL boundary is deterministically testable.
    #[must_use]
    fn is_bound_fresh(&self, fingerprint: &str, caller: &CallerIdentity, now: Instant) -> bool {
        match self.issued.get(fingerprint) {
            Some(c) => {
                c.caller_unique_name == caller.unique_name
                    && now.saturating_duration_since(c.issued_at) <= CLOUD_SEND_TTL
            }
            None => false,
        }
    }
}

/// Authorize completion of a cloud send — the SVC-1-R1-1-01 closure, distinct
/// from the `Confirm` tier (the Clarification). It checks **same-caller
/// binding** (the completer is the unique name the confirmation was issued to),
/// enforced as a hard deny in **both** dev and deployment (cloud-send is the
/// stricter category). Under the deployed policy it additionally requires the
/// completer to be the authenticated shell.
///
/// `now` is injected for deterministic TTL testing (live callers pass
/// `Instant::now()`).
///
/// # Examples
///
/// ```
/// use std::time::Instant;
/// use delphi_services::auth::{
///     authorize_cloud_send, AuthOutcome, AuthPolicy, CallerIdentity, CloudSendConfirmations,
/// };
///
/// let mut reg = CloudSendConfirmations::default();
/// let a = CallerIdentity::from_unique_name(":1.10");
/// let b = CallerIdentity::from_unique_name(":1.11");
/// reg.issue("fp-1", &a);
///
/// // Same caller completes → authorized.
/// assert_eq!(
///     authorize_cloud_send(&a, "fp-1", Instant::now(), &reg, &AuthPolicy::dev()),
///     AuthOutcome::Authorized,
/// );
/// // A different caller echoing A's confirmation → denied (the closure).
/// assert!(matches!(
///     authorize_cloud_send(&b, "fp-1", Instant::now(), &reg, &AuthPolicy::dev()),
///     AuthOutcome::AuthorizationDenied { .. },
/// ));
/// ```
#[must_use]
pub fn authorize_cloud_send(
    caller: &CallerIdentity,
    fingerprint: &str,
    now: Instant,
    confirmations: &CloudSendConfirmations,
    policy: &AuthPolicy,
) -> AuthOutcome {
    // (1) Same-caller binding — the closure. Enforced in dev AND deployed.
    if !confirmations.is_bound_fresh(fingerprint, caller, now) {
        return AuthOutcome::AuthorizationDenied {
            reason: "cloud-send confirmation not bound to this caller (or expired)",
        };
    }

    // (2) Deployed hardening: the completer must also be the authenticated
    //     shell. Decision 1 — degrade-to-DENY (must NOT fail open): deployed
    //     shell verification relies on the caller's resolved credentials (the
    //     authenticated peer). If the resolver degraded to unique-name-only
    //     because the credential fetch failed (`uid` is `None`), deployment
    //     cannot verify the caller is the shell, so it must DENY — never
    //     "couldn't verify, so allow". In dev this whole branch is skipped; the
    //     same-caller binding in (1) carries cloud-send regardless.
    if matches!(policy.bus(), BusTrust::DeployedDeny) {
        if caller.uid.is_none() {
            return AuthOutcome::AuthorizationDenied {
                reason: "deployed cloud-send: caller credentials unavailable, cannot verify shell",
            };
        }
        if !policy.is_recognized_shell(caller) {
            return AuthOutcome::AuthorizationDenied {
                reason: "cloud-send requires the authenticated shell (deployed policy)",
            };
        }
    }

    AuthOutcome::Authorized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(name: &str) -> CallerIdentity {
        CallerIdentity::from_unique_name(name)
    }

    /// A caller whose credentials were resolved (the deployed authenticated-peer
    /// case). Decision 1: the deployed cloud-send shell check requires creds.
    fn caller_with_creds(name: &str, uid: u32) -> CallerIdentity {
        CallerIdentity {
            unique_name: name.to_string(),
            uid: Some(uid),
            pid: Some(4242),
        }
    }

    // ── Tier table fidelity (Codex's verbatim Q1 classification) ──

    #[test]
    fn tier_table_matches_codex_classification() {
        let p = MethodPolicy::from_table();
        // Read-only → Autonomous.
        assert_eq!(p.tier_of("file_search.search"), Some(PermissionTier::Autonomous));
        assert_eq!(p.tier_of("knowledge.search"), Some(PermissionTier::Autonomous));
        assert_eq!(p.tier_of("workspace.preview"), Some(PermissionTier::Autonomous));
        // Mutating → Confirm.
        assert_eq!(p.tier_of("mode.set_mode"), Some(PermissionTier::Confirm));
        assert_eq!(p.tier_of("goals.create_goal"), Some(PermissionTier::Confirm));
        assert_eq!(p.tier_of("knowledge.ingest_file"), Some(PermissionTier::Confirm));
        // Destructive / reversal / forget_* → Biometric.
        assert_eq!(p.tier_of("timeline.undo"), Some(PermissionTier::Biometric));
        assert_eq!(p.tier_of("workspace.undo"), Some(PermissionTier::Biometric));
        assert_eq!(p.tier_of("conversation.forget_today"), Some(PermissionTier::Biometric));
        assert_eq!(p.tier_of("conversation.forget_topic"), Some(PermissionTier::Biometric));
        assert_eq!(p.tier_of("conversation.forget_older_than"), Some(PermissionTier::Biometric));
        assert_eq!(p.tier_of("knowledge.forget_source"), Some(PermissionTier::Biometric));
        // The separate cloud-send subaction is Confirm.
        assert_eq!(p.tier_of("inference.cloud_send"), Some(PermissionTier::Confirm));
    }

    #[test]
    fn unmapped_method_is_denied_by_default() {
        // Fail-closed: a method absent from METHOD_POLICY is denied, NOT
        // silently defaulted to Confirm. RED against a naive impl that routed
        // straight through PermissionChecker (whose default is Confirm).
        let p = MethodPolicy::from_table();
        assert_eq!(p.tier_of("inference.exfiltrate_everything"), None);

        let outcome = authorize(
            "inference.exfiltrate_everything",
            &caller(":1.5"),
            &AuthPolicy::dev(),
            &p,
        );
        assert!(matches!(outcome, AuthOutcome::AuthorizationDenied { .. }));
    }

    // ── Layer 1: tier gating ──

    #[test]
    fn read_only_method_is_authorized() {
        let p = MethodPolicy::from_table();
        assert_eq!(
            authorize("file_search.search", &caller(":1.5"), &AuthPolicy::dev(), &p),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn mutating_method_requires_confirm() {
        let p = MethodPolicy::from_table();
        assert_eq!(
            authorize("mode.set_mode", &caller(":1.5"), &AuthPolicy::dev(), &p),
            AuthOutcome::ConfirmationRequired {
                tier: PermissionTier::Confirm,
                strength: ConfirmationStrength::Confirm,
            }
        );
    }

    // ── Decision A: Biometric degrades in dev, real when deployed ──

    #[test]
    fn biometric_degrades_to_type_to_confirm_in_dev() {
        // The Biometric-tier path must be exercisable in dev (no biometric
        // hardware), so it degrades to the strongest available confirmation.
        let p = MethodPolicy::from_table();
        assert_eq!(
            authorize("timeline.undo", &caller(":1.5"), &AuthPolicy::dev(), &p),
            AuthOutcome::ConfirmationRequired {
                tier: PermissionTier::Biometric,
                strength: ConfirmationStrength::TypeToConfirm,
            }
        );
    }

    #[test]
    fn biometric_is_a_real_gate_when_deployed() {
        let p = MethodPolicy::from_table();
        let mut policy = AuthPolicy::deployed();
        policy.record_shell(":1.9");
        assert_eq!(
            authorize("conversation.forget_today", &caller(":1.9"), &policy, &p),
            AuthOutcome::ConfirmationRequired {
                tier: PermissionTier::Biometric,
                strength: ConfirmationStrength::Biometric,
            }
        );
    }

    // ── Layer 2: caller-identity policy split ──

    #[test]
    fn deployed_denies_unrecognized_caller() {
        let p = MethodPolicy::from_table();
        let mut policy = AuthPolicy::deployed();
        policy.record_shell(":1.1"); // the shell
        // A different unique name on a mutating method is denied outright.
        let outcome = authorize("mode.set_mode", &caller(":1.99"), &policy, &p);
        assert!(matches!(outcome, AuthOutcome::AuthorizationDenied { .. }));
    }

    #[test]
    fn dev_logs_and_allows_unrecognized_caller() {
        // In dev, an unrecognized caller is NOT denied — the tier decision still
        // applies (here: Autonomous → Authorized).
        let p = MethodPolicy::from_table();
        let policy = AuthPolicy::dev(); // no shell recorded → nobody "recognized"
        assert_eq!(
            authorize("file_search.search", &caller(":1.77"), &policy, &p),
            AuthOutcome::Authorized
        );
    }

    // ── SVC-1-R1-1-01 closure: same-caller binding (unit level) ──

    #[test]
    fn cloud_send_same_caller_is_authorized() {
        let mut reg = CloudSendConfirmations::default();
        let a = caller(":1.10");
        reg.issue("fp-abc", &a);
        assert_eq!(
            authorize_cloud_send(&a, "fp-abc", Instant::now(), &reg, &AuthPolicy::dev()),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn cloud_send_different_caller_is_denied_even_in_dev() {
        // THE CLOSURE, in miniature: caller B echoes a confirmation issued to A.
        // Denied in DEV (cloud-send is deny-in-both, unlike general methods).
        // RED against a no-binding implementation (which would authorize B).
        let mut reg = CloudSendConfirmations::default();
        let a = caller(":1.10");
        let b = caller(":1.11"); // different unique name — the second caller
        reg.issue("fp-abc", &a);

        let outcome = authorize_cloud_send(&b, "fp-abc", Instant::now(), &reg, &AuthPolicy::dev());
        assert!(
            matches!(outcome, AuthOutcome::AuthorizationDenied { .. }),
            "a cloud-send echo from a different caller must be denied (SVC-1-R1-1-01)"
        );
    }

    #[test]
    fn cloud_send_without_a_prior_request_is_denied() {
        let reg = CloudSendConfirmations::default();
        let outcome =
            authorize_cloud_send(&caller(":1.10"), "fp-none", Instant::now(), &reg, &AuthPolicy::dev());
        assert!(matches!(outcome, AuthOutcome::AuthorizationDenied { .. }));
    }

    #[test]
    fn cloud_send_expired_confirmation_is_denied() {
        // TTL is defense-in-depth on top of same-caller binding.
        let mut reg = CloudSendConfirmations::default();
        let a = caller(":1.10");
        reg.issue("fp-abc", &a);
        let later = Instant::now() + CLOUD_SEND_TTL + Duration::from_secs(1);
        assert!(matches!(
            authorize_cloud_send(&a, "fp-abc", later, &reg, &AuthPolicy::dev()),
            AuthOutcome::AuthorizationDenied { .. }
        ));
    }

    #[test]
    fn cloud_send_deployed_requires_authenticated_shell() {
        // Same caller (passes binding) but NOT the recognized shell → denied
        // under the deployed policy (the additional hardening layer).
        let mut reg = CloudSendConfirmations::default();
        // Has creds (passes the credential gate) but is NOT the recorded shell,
        // so it is denied specifically on the shell-mismatch (not on missing
        // creds — that is a separate test below).
        let nonshell = caller_with_creds(":1.50", 1000);
        reg.issue("fp-abc", &nonshell);
        let mut policy = AuthPolicy::deployed();
        policy.record_shell(":1.1"); // the real shell is someone else

        let outcome = authorize_cloud_send(&nonshell, "fp-abc", Instant::now(), &reg, &policy);
        assert!(matches!(outcome, AuthOutcome::AuthorizationDenied { .. }));
    }

    #[test]
    fn cloud_send_deployed_shell_same_caller_with_creds_is_authorized() {
        let mut reg = CloudSendConfirmations::default();
        let shell = caller_with_creds(":1.1", 1000); // resolved creds (authenticated peer)
        reg.issue("fp-abc", &shell);
        let mut policy = AuthPolicy::deployed();
        policy.record_shell(":1.1");
        assert_eq!(
            authorize_cloud_send(&shell, "fp-abc", Instant::now(), &reg, &policy),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn cloud_send_deployed_denies_when_creds_unavailable() {
        // Decision 1 — degrade-to-DENY. A deployed caller whose credentials could
        // not be resolved (resolver degraded to unique-name-only, uid=None)
        // cannot be verified as the authenticated shell, so cloud-send is denied
        // EVEN THOUGH it matches the recorded shell unique name and is
        // same-caller bound. RED against pre-Decision-1 code, which returned
        // Authorized on the unique-name match alone.
        let mut reg = CloudSendConfirmations::default();
        let degraded = caller(":1.1"); // same unique name as the shell, but uid=None
        reg.issue("fp-abc", &degraded);
        let mut policy = AuthPolicy::deployed();
        policy.record_shell(":1.1");
        assert!(
            matches!(
                authorize_cloud_send(&degraded, "fp-abc", Instant::now(), &reg, &policy),
                AuthOutcome::AuthorizationDenied { .. }
            ),
            "deployed cloud-send must deny when caller credentials are unavailable"
        );
    }

    // ── ConfirmationStrength mapping (Decision A, exhaustive) ──

    #[test]
    fn confirmation_strength_mapping_is_exhaustive() {
        use BusTrust::{DeployedDeny, DevLogAndAllow};
        use PermissionTier::{Autonomous, Biometric, Confirm, Hardware};
        assert_eq!(ConfirmationStrength::for_tier(Autonomous, DevLogAndAllow), None);
        assert_eq!(ConfirmationStrength::for_tier(Autonomous, DeployedDeny), None);
        assert_eq!(
            ConfirmationStrength::for_tier(Confirm, DevLogAndAllow),
            Some(ConfirmationStrength::Confirm)
        );
        assert_eq!(
            ConfirmationStrength::for_tier(Biometric, DevLogAndAllow),
            Some(ConfirmationStrength::TypeToConfirm)
        );
        assert_eq!(
            ConfirmationStrength::for_tier(Biometric, DeployedDeny),
            Some(ConfirmationStrength::Biometric)
        );
        assert_eq!(
            ConfirmationStrength::for_tier(Hardware, DevLogAndAllow),
            Some(ConfirmationStrength::TypeToConfirm)
        );
        assert_eq!(
            ConfirmationStrength::for_tier(Hardware, DeployedDeny),
            Some(ConfirmationStrength::Hardware)
        );
    }
}
