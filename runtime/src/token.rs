// SPDX-License-Identifier: MIT

//! The daemon-minted, action-digest-bound approval capability (Increment 1c).
//!
//! This is the capability the AI **cannot fabricate**: the only path to a token
//! that [`verify`]s is a genuine human-consent event (1c's PAM + logind gate)
//! driving the root daemon to [`mint`] one. (`docs/TRUST_MODEL.md` §4, step 4 —
//! "mint the HMAC capability bound to the digest + TTL".)
//!
//! # Pattern, not reuse
//!
//! It mirrors the proven cloud-egress token
//! ([die-inference `token.rs`](../../../die/inference/src/token.rs) —
//! HMAC-SHA256, ephemeral key, short TTL, opaque with no `Debug`/`Clone`), but it
//! binds the **action digest** rather than the cloud `(prompt, model, max_tokens)`
//! tuple, and it is minted by the **root daemon** whose [`MintingKey`] is held in
//! root-only memory (the 1a anchor's "minting key, out of user reach"), not by the
//! cloud gateway. Forgery resistance is the HMAC; the key never leaves the daemon.
//!
//! # Binding is the whole point
//!
//! [`verify`] re-derives the MAC over the digest the AI presents **at execute**,
//! so a token minted for action A fails verification against action B — a stolen
//! or replayed token cannot be re-pointed at a different action. Within the TTL,
//! valid only for the exact action it was minted for.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// How long a minted token remains valid. Short by design (the human approves in
/// seconds); a stale token forces a fresh consent rather than a long-lived bearer.
pub const TOKEN_TTL_SECS: u64 = 30;

/// The daemon's ephemeral HMAC minting key (32 bytes).
///
/// Held only in the root daemon's memory and never serialized. No `Debug`/`Clone`
/// so it cannot be logged or casually copied. In production the daemon fills it
/// from a CSPRNG at startup; tests use a fixed key.
pub struct MintingKey([u8; 32]);

impl MintingKey {
    /// Wrap 32 raw key bytes (the daemon's CSPRNG output, or a fixed test key).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// An opaque, action-digest-bound approval capability.
///
/// No `Debug`/`Clone`: a live token is a short-lived bearer credential for one
/// exact action, so it must not be logged or duplicated. The only minting path is
/// [`mint`]; the only validation path is [`verify`]; [`ApprovalToken::from_wire`]
/// yields an untrusted candidate that fails verification unless it carries a
/// genuine daemon-issued MAC over the presented digest.
pub struct ApprovalToken {
    issued_at_unix: u64,
    mac_hex: String,
}

impl ApprovalToken {
    /// Serialize to the opaque wire form `{issued_at}:{mac_hex}` (the AI echoes it
    /// back unchanged at execute).
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.issued_at_unix, self.mac_hex)
    }

    /// Parse a wire string into an **untrusted** candidate, or `None` if
    /// malformed. Parsing grants no trust — only [`verify`] (which holds the key)
    /// accepts it.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        let (ts, mac) = s.split_once(':')?;
        let issued_at_unix: u64 = ts.parse().ok()?;
        if mac.len() != 64 || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self { issued_at_unix, mac_hex: mac.to_ascii_lowercase() })
    }
}

/// Build the keyed HMAC over the bound `(action_digest, issued_at)`.
fn build_mac(key: &[u8; 32], action_digest: &[u8; 32], issued_at_unix: u64) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(action_digest);
    mac.update(&issued_at_unix.to_le_bytes());
    mac
}

/// Whether a token issued at `issued_at_unix` is within the TTL at `now` (rejects
/// future-dated tokens — clock skew / forgery — and anything past the TTL).
fn within_ttl(issued_at_unix: u64, now: u64) -> bool {
    now >= issued_at_unix && now - issued_at_unix <= TOKEN_TTL_SECS
}

/// Mint a token binding `action_digest`, issued at `now`.
///
/// The daemon calls this **only** after the human-consent gate (PAM + logind)
/// passes for this exact action.
///
/// # Examples
///
/// ```
/// use delphi_runtime::token::{mint, verify, MintingKey};
///
/// let key = MintingKey::from_bytes([7u8; 32]);
/// let digest = [9u8; 32];
/// let t = mint(&key, &digest, 1_000);
/// assert!(verify(&key, &t, &digest, 1_010)); // same action, within TTL
/// ```
#[must_use]
pub fn mint(key: &MintingKey, action_digest: &[u8; 32], now: u64) -> ApprovalToken {
    let mac = build_mac(&key.0, action_digest, now).finalize().into_bytes();
    ApprovalToken { issued_at_unix: now, mac_hex: hex_encode(&mac) }
}

/// Verify `token` was minted by this key for **this exact** `action_digest` and
/// is within the TTL at `now`. Constant-time MAC comparison.
///
/// Returns `false` for a token minted for a different action, an expired or
/// future-dated token, a wrong key, or a forged/malformed MAC.
#[must_use]
pub fn verify(
    key: &MintingKey,
    token: &ApprovalToken,
    action_digest: &[u8; 32],
    now: u64,
) -> bool {
    if !within_ttl(token.issued_at_unix, now) {
        return false;
    }
    let Some(provided) = hex_decode(&token.mac_hex) else {
        return false;
    };
    // Re-derive over the digest the caller presents NOW: a token minted for a
    // different action cannot pass here.
    build_mac(&key.0, action_digest, token.issued_at_unix)
        .verify_slice(&provided)
        .is_ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];
    const DIGEST_A: [u8; 32] = [0xAA; 32];
    const DIGEST_B: [u8; 32] = [0xBB; 32];

    #[test]
    fn mint_then_verify_same_action_within_ttl() {
        let key = MintingKey::from_bytes(KEY);
        let t = mint(&key, &DIGEST_A, 1_000);
        assert!(verify(&key, &t, &DIGEST_A, 1_000)); // same second
        assert!(verify(&key, &t, &DIGEST_A, 1_000 + TOKEN_TTL_SECS)); // at TTL edge
    }

    /// THE BINDING / REPLAY RED-PROOF (durable positive control): a token minted
    /// for action A is REJECTED when presented for action B. If the token were
    /// not bound to the digest, this would pass (replay) — so this assertion
    /// failing would mean the binding was lost.
    #[test]
    fn token_for_one_action_is_rejected_for_another() {
        let key = MintingKey::from_bytes(KEY);
        let t = mint(&key, &DIGEST_A, 1_000);
        assert!(
            !verify(&key, &t, &DIGEST_B, 1_000),
            "a token minted for action A must NOT verify for action B (replay/substitution denied)"
        );
    }

    #[test]
    fn expired_or_future_token_rejected() {
        let key = MintingKey::from_bytes(KEY);
        let t = mint(&key, &DIGEST_A, 1_000);
        assert!(!verify(&key, &t, &DIGEST_A, 1_000 + TOKEN_TTL_SECS + 1)); // past TTL
        assert!(!verify(&key, &t, &DIGEST_A, 999)); // future-dated
    }

    #[test]
    fn wrong_key_cannot_verify() {
        let minted = mint(&MintingKey::from_bytes(KEY), &DIGEST_A, 1_000);
        let attacker_key = MintingKey::from_bytes([8u8; 32]);
        assert!(!verify(&attacker_key, &minted, &DIGEST_A, 1_000));
    }

    #[test]
    fn forged_or_malformed_wire_rejected() {
        let key = MintingKey::from_bytes(KEY);
        // A fabricated MAC of the right shape (64 hex) but wrong value.
        let forged = ApprovalToken::from_wire(&format!("1000:{}", "ab".repeat(32))).unwrap();
        assert!(!verify(&key, &forged, &DIGEST_A, 1_000));
        // Malformed wires don't even parse.
        assert!(ApprovalToken::from_wire("no-colon").is_none());
        assert!(ApprovalToken::from_wire("1000:tooshort").is_none());
    }

    #[test]
    fn wire_round_trips() {
        let key = MintingKey::from_bytes(KEY);
        let t = mint(&key, &DIGEST_A, 1_000);
        let parsed = ApprovalToken::from_wire(&t.to_wire()).expect("valid wire parses");
        assert!(verify(&key, &parsed, &DIGEST_A, 1_005));
    }
}
