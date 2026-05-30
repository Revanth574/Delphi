// SPDX-License-Identifier: MIT

//! Cloud-egress confirmation token (services-sweep SVC-1-R1-1).
//!
//! # Why this exists
//!
//! SVC-1's *sanitization* gate is structural: nothing reaches the cloud
//! without ZKQP. But the *confirmation* gate — the high-privacy-score pause
//! that asks the user before sending — was guarded only by a caller-set
//! `bool` (`cloud_confirmed`). Any caller could set it `true` on the first
//! request and skip the pause (Codex SVC-1-R1-1, P2: ZKQP still ran, so no PII
//! leaked, but the user-consent contract was bypassable).
//!
//! The fix applies the capability pattern to consent: a [`ConfirmationToken`]
//! is an opaque, HMAC-bound proof that the gateway itself issued a
//! confirmation request for *this exact* `(sanitized prompt, model,
//! max_tokens)` tuple, recently. A caller cannot fabricate a token that passes
//! verification, because the HMAC key is an ephemeral secret held only by the
//! gateway. The only way to obtain a verifiable token is to first receive a
//! `ConfirmationRequired` outcome from the gateway.
//!
//! # Wire vs in-process
//!
//! In-process the token is opaque (no `Debug`/`Clone`, no trusted public
//! constructor). On the wire (WebSocket / D-Bus) it travels as an opaque
//! string via [`ConfirmationToken::to_wire`] / [`ConfirmationToken::from_wire`].
//! Forgery resistance does NOT depend on the wire encoding being secret — it
//! depends on the HMAC, which only the issuing gateway can compute or check.
//! `from_wire` produces an *untrusted candidate*; only the gateway's verify
//! step (which holds the key) grants trust.
//!
//! # Binding, not one-time-use
//!
//! Verification re-derives the HMAC over the freshly re-sanitized prompt, so a
//! token is valid only for the exact sanitized text it was issued for, only
//! until it expires. Combined with deterministic sanitization (proven by
//! `fortress::zkqp::sanitizer::tests::sanitize_is_deterministic`), an edited
//! prompt or an expired token fails verification and forces a fresh
//! confirmation.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::cloud::CloudModel;

type HmacSha256 = Hmac<Sha256>;

/// How long an issued token remains valid (SVC-1-R1-1). Short by design: the
/// user is expected to approve within seconds; a stale token forces a fresh
/// confirmation rather than allowing a long-lived bearer credential.
pub(crate) const TOKEN_TTL_SECS: u64 = 30;

/// An opaque, HMAC-bound proof that the cloud-egress gateway issued a
/// confirmation request for a specific `(sanitized prompt, model, max_tokens)`
/// — see the module docs.
///
/// No `Debug`/`Clone`: a live token is a short-lived bearer credential for one
/// exact prompt, so it must not be logged or casually duplicated. The only
/// trusted minting path is `CloudEgressGateway::issue_token`; the only
/// validation path is `CloudEgressGateway::verify_token`. [`from_wire`] yields
/// an untrusted candidate that fails verification unless it carries a genuine
/// gateway-issued MAC.
///
/// [`from_wire`]: ConfirmationToken::from_wire
pub struct ConfirmationToken {
    issued_at_unix: u64,
    mac_hex: String,
}

impl ConfirmationToken {
    /// Construct from raw parts. `pub(crate)`: the gateway uses it to mint a
    /// freshly-MAC'd token, and [`from_wire`](Self::from_wire) uses it to wrap
    /// an untrusted parsed candidate. Not public — external code cannot
    /// assemble a token at all, trusted or otherwise.
    pub(crate) fn from_parts(issued_at_unix: u64, mac_hex: String) -> Self {
        Self {
            issued_at_unix,
            mac_hex,
        }
    }

    /// Issue time (unix seconds). `pub(crate)` for the gateway's expiry check.
    pub(crate) fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    /// The HMAC hex. `pub(crate)` for the gateway's constant-time verify.
    pub(crate) fn mac_hex(&self) -> &str {
        &self.mac_hex
    }

    /// Serialize to the opaque wire form `{issued_at}:{mac_hex}` for
    /// transmission to the shell. The shell treats it as an opaque blob and
    /// echoes it back on the confirmed retry.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.issued_at_unix, self.mac_hex)
    }

    /// Parse a wire string back into an **untrusted** token candidate, or
    /// `None` if malformed. Parsing grants no trust — the candidate is
    /// meaningless until `CloudEgressGateway::verify_token` (which holds the
    /// HMAC key) accepts it.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        let (ts, mac) = s.split_once(':')?;
        let issued_at_unix: u64 = ts.parse().ok()?;
        // The MAC must be non-empty even-length hex (SHA-256 -> 64 hex chars).
        if mac.len() != 64 || !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self::from_parts(issued_at_unix, mac.to_ascii_lowercase()))
    }
}

/// Build the keyed, field-fed HMAC for the bound tuple, ready to `finalize`
/// (issue) or `verify_slice` (verify). The variable-length sanitized text is
/// length-prefixed so no concatenation ambiguity exists between fields.
pub(crate) fn build_mac(
    key: &[u8; 32],
    sanitized_prompt: &str,
    model: CloudModel,
    max_tokens: u32,
    issued_at_unix: u64,
) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&(sanitized_prompt.len() as u64).to_le_bytes());
    mac.update(sanitized_prompt.as_bytes());
    mac.update(model.api_model_id().as_bytes());
    mac.update(&max_tokens.to_le_bytes());
    mac.update(&issued_at_unix.to_le_bytes());
    mac
}

/// Current unix time in seconds (0 on the impossible pre-epoch error).
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a token issued at `issued_at_unix` is still within the TTL at
/// `now`. Rejects future-dated tokens (clock skew / forgery) and anything
/// older than [`TOKEN_TTL_SECS`].
pub(crate) fn within_ttl(issued_at_unix: u64, now: u64) -> bool {
    now >= issued_at_unix && now - issued_at_unix <= TOKEN_TTL_SECS
}

/// Lowercase hex-encode bytes (for the wire MAC).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode an even-length hex string to bytes, or `None` if malformed.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
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

    #[test]
    fn wire_round_trips() {
        let t = ConfirmationToken::from_parts(1_700_000_000, "ab".repeat(32));
        let wire = t.to_wire();
        let parsed = ConfirmationToken::from_wire(&wire).expect("valid wire parses");
        assert_eq!(parsed.issued_at_unix(), 1_700_000_000);
        assert_eq!(parsed.mac_hex(), &"ab".repeat(32));
    }

    #[test]
    fn from_wire_rejects_malformed() {
        assert!(ConfirmationToken::from_wire("no-colon").is_none());
        assert!(ConfirmationToken::from_wire("notanumber:abcd").is_none());
        // Wrong MAC length (not 64 hex chars).
        assert!(ConfirmationToken::from_wire("123:abcd").is_none());
        // Non-hex MAC.
        assert!(ConfirmationToken::from_wire(&format!("123:{}", "zz".repeat(32))).is_none());
    }

    #[test]
    fn within_ttl_boundaries() {
        assert!(within_ttl(100, 100)); // same second
        assert!(within_ttl(100, 100 + TOKEN_TTL_SECS)); // exactly at TTL
        assert!(!within_ttl(100, 100 + TOKEN_TTL_SECS + 1)); // just past
        assert!(!within_ttl(100, 99)); // future-dated -> rejected
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "000fa5ff");
        assert_eq!(hex_decode(&hex).unwrap(), bytes);
        assert!(hex_decode("abc").is_none()); // odd length
    }

    #[test]
    fn build_mac_is_deterministic_and_key_bound() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        let m1 = build_mac(&key_a, "hi", CloudModel::ClaudeSonnet, 64, 100)
            .finalize()
            .into_bytes();
        let m2 = build_mac(&key_a, "hi", CloudModel::ClaudeSonnet, 64, 100)
            .finalize()
            .into_bytes();
        let m_other_key = build_mac(&key_b, "hi", CloudModel::ClaudeSonnet, 64, 100)
            .finalize()
            .into_bytes();
        let m_other_prompt = build_mac(&key_a, "bye", CloudModel::ClaudeSonnet, 64, 100)
            .finalize()
            .into_bytes();
        assert_eq!(m1, m2, "same inputs -> same MAC");
        assert_ne!(m1, m_other_key, "different key -> different MAC");
        assert_ne!(m1, m_other_prompt, "different prompt -> different MAC");
    }
}
