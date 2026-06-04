// SPDX-License-Identifier: MIT

//! SVC-1-R1-1-01 **live closure** — the real-bus integration test that
//! discharges the cross-caller cloud-send token-echo vulnerability.
//!
//! This is deliberately NOT a bus-free unit test. The Stage-1 unit tests and
//! the Piece-1 service-layer tests (`inference::tests::cloud_send_*`) already
//! prove the binding *function* in isolation. They do NOT prove the gate is
//! ARMED on the live D-Bus entry path — that the method, dispatched over a real
//! bus with real daemon-assigned unique names, rejects a different caller
//! echoing another's confirmation token. Proving *that* is the whole point of
//! R1-1-01, and it requires the real path end-to-end:
//!
//! 1. `InferenceService` is served on a real session bus via the object server.
//! 2. Caller **A** (its own connection → its own daemon-assigned unique name)
//!    sends a high-privacy-score cloud query. The ZKQP gateway pauses and mints
//!    a confirmation token, bound to A by the Piece-1 wiring. Nothing is sent.
//! 3. Caller **B** (a DIFFERENT connection → a DIFFERENT unique name) echoes
//!    A's token. The same-caller binding must reject the completion with
//!    `AccessDenied` BEFORE the gateway send.
//!
//! **RED against pre-SVC-2:** before Piece-1's `enforce_cloud_send` gate, B's
//! echo verifies A's HMAC token against the same sanitized prompt, is approved,
//! and reaches `CloudClient::complete` (the send) — surfacing as a cloud/Failed
//! error, NOT `AccessDenied`. The `AccessDenied` assertion below therefore
//! FAILS against the pre-Piece-1 code (demonstrated by reverting the gate),
//! which is what proves this test actually catches the bypass rather than
//! passing for the wrong reason.
//!
//! Requires a D-Bus session bus (WSL2 provides one; CI runs under
//! `dbus-run-session`). With no bus reachable the test skips with a notice —
//! an integration test cannot run without its integration substrate, and the
//! absence of a bus is not a failure of the code under test.

use std::sync::{Arc, Mutex};

use tokio::sync::RwLock;

use delphi_services::auth::{AuthPolicy, CloudSendConfirmations};
use delphi_services::auth_guard::AuthGuard;
use delphi_services::caller_resolver::CallerResolver;
use delphi_services::inference::{InferenceService, PATH};
use die_inference::router::Router;
use fortress::audit::AuditLog;

const IFACE: &str = "org.delphi.Inference";

/// A high-PII prompt that drives the ZKQP score over the confirmation
/// threshold (five distinct email addresses), so the cloud path pauses and
/// mints a token rather than sending. Mirrors the deterministic trigger used by
/// `die_inference`'s own router tests.
const HIGH_PII_PROMPT: &str = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com to all";

/// Build an `InferenceService` whose router has a (fake) cloud key configured —
/// enough for the ZKQP gateway to take the cloud path and pause on the high
/// score; the fake key is never exercised on the green path because the pause
/// (caller A) and the binding rejection (caller B) both return before any send.
/// A dev guard so the general `inference.query` tier gate admits both callers —
/// the test isolates the same-caller cloud-send binding, not the tier gate.
fn build_service() -> InferenceService {
    let mut router = Router::new();
    router.set_cloud_api_key("sk-test".to_string());
    // SVC-2 Piece 2: grant session destination consent up front. This test
    // isolates the SVC-1-R1-1-01 same-caller binding, which is INDEPENDENT of
    // the (new) destination-consent egress gate — without this grant, caller A's
    // query would now be refused at egress (DestinationConsentRequired) before
    // ever minting a token to bind. Granting it lets A reach the privacy pause
    // and proves the binding still denies caller B unchanged after Piece 2.
    router.grant_destination_consent();
    InferenceService::new(
        Arc::new(RwLock::new(router)),
        Arc::new(AuthGuard::new(
            AuthPolicy::dev(),
            Arc::new(Mutex::new(AuditLog::in_memory())),
        )),
        Arc::new(CallerResolver::new()),
        Arc::new(Mutex::new(CloudSendConfirmations::default())),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cloud_confirmation_token_echo_from_non_caller_is_rejected_live() {
    // ── Substrate: a real session bus hosting the served interface ──
    let Ok(server) = zbus::Connection::session().await else {
        eprintln!(
            "SKIP cloud_confirmation_token_echo_from_non_caller_is_rejected_live: \
             no D-Bus session bus reachable (run under dbus-run-session in CI)"
        );
        return;
    };
    server
        .object_server()
        .at(PATH, build_service())
        .await
        .expect("serve InferenceService on the session bus");
    let dest = server
        .unique_name()
        .expect("server connection has a unique name")
        .to_string();

    // ── Caller A: its own connection → its own daemon-assigned unique name ──
    let client_a = zbus::Connection::session()
        .await
        .expect("caller A session connection");
    let reply_a = client_a
        .call_method(
            Some(dest.as_str()),
            PATH,
            Some(IFACE),
            "Query",
            &(HIGH_PII_PROMPT, 50u32, false, ""),
        )
        .await
        .expect("caller A Query call dispatched");
    let json_a: String = reply_a
        .body()
        .deserialize()
        .expect("caller A reply is a JSON string");
    let value_a: serde_json::Value =
        serde_json::from_str(&json_a).expect("caller A reply parses as JSON");
    assert_eq!(
        value_a["status"], "confirmation_required",
        "caller A's high-PII cloud query must pause for confirmation (mint a token); got: {json_a}"
    );
    let token = value_a["token"]
        .as_str()
        .expect("the confirmation response carries a token")
        .to_string();
    assert!(!token.is_empty(), "the minted confirmation token must be non-empty");

    // ── Caller B: a DIFFERENT connection → a DIFFERENT unique name ──
    let client_b = zbus::Connection::session()
        .await
        .expect("caller B session connection");
    assert_ne!(
        client_a.unique_name(),
        client_b.unique_name(),
        "callers A and B must hold distinct daemon-assigned unique names for this to test R1-1-01"
    );

    // B echoes A's token. The same-caller binding must reject the completion
    // BEFORE the gateway send.
    let result_b = client_b
        .call_method(
            Some(dest.as_str()),
            PATH,
            Some(IFACE),
            "Query",
            &(HIGH_PII_PROMPT, 50u32, false, token.as_str()),
        )
        .await;

    // If B's call SUCCEEDED, the cross-caller echo completed a cloud send — the
    // exact R1-1-01 bypass. That is a breach, not a pass.
    let err_b = result_b.expect_err(
        "R1-1-01 BREACH: caller B completed caller A's cloud send by echoing A's \
         confirmation token — the same-caller binding did not reject the cross-caller echo",
    );

    // It must be denied by the binding (AccessDenied), NOT by some downstream
    // error. A non-AccessDenied error means B reached past the gate to the send
    // — which is exactly the pre-Piece-1 (un-armed) behavior this test must fail
    // against. This assertion is the RED-against-pre-SVC-2 lever.
    let err_str = err_b.to_string();
    assert!(
        err_str.contains("AccessDenied"),
        "caller B's cross-caller token echo must be rejected by the same-caller binding with \
         AccessDenied (the R1-1-01 closure), proving the send never happened. A different error \
         means B reached the gateway send — the un-armed pre-SVC-2 behavior. Got: {err_b}"
    );
}
