// SPDX-License-Identifier: MIT

//! **A DELIBERATELY UNCOOPERATIVE AI** — completes the protocol, then refuses to exit.
//!
//! # Why this fixture exists (D0A-R28-02, assembly coverage — D0A-R30 decision A)
//!
//! The AI is untrusted by construction (`docs/TRUST_MODEL.md` §2). `delphi-runtimed` used to
//! `waitpid` on it unconditionally, so an AI that took its terminal response and simply did not
//! exit held the ROOT daemon forever — "B1 services one action and exits" was a property that
//! depended on the AI's cooperation.
//!
//! **`delphi-minimal-ai` cooperates**: it returns from `main` after its terminal response. So
//! every existing test drives the daemon down the path where `reap_within` succeeds inside the
//! grace period, and the `SIGKILL` branch that the whole fix consists of **is never taken**.
//! That is why the policy sat compiled, linked and unexercised for three rounds.
//!
//! This binary is that path's fixture, and nothing else: it speaks the identical protocol
//! through the identical helpers, then **sleeps past the daemon's grace period**. Any
//! difference in the daemon's behaviour between this and `delphi-minimal-ai` is attributable to
//! the one thing that differs — whether the AI exits.
//!
//! **Feature-gated (`insecure-test-seams`) and never built in production**, like the surface
//! shell. An AI that ignores termination is a test instrument, not a shipped component.
//!
//! Env: as `delphi-minimal-ai`, plus `DELPHI_STUBBORN_AI_SLEEP_SECS` (default 3600) — the
//! duration is unbounded-in-practice on purpose. A fixture that outlives the grace by a second
//! would let a slow machine turn a real regression into a pass.

use std::os::unix::net::UnixStream;

use delphi_runtime::service::{ai_round_trip, present_msg, propose_msg};
use delphi_runtime::wire::{pb, read_frame};

fn ro(p: &str) -> pb::Bind {
    pb::Bind { path: p.into(), mode: pb::BindMode::BindReadOnly as i32 }
}
fn rw(p: &str) -> pb::Bind {
    pb::Bind { path: p.into(), mode: pb::BindMode::BindReadWrite as i32 }
}

fn main() {
    let sock = std::env::var(delphi_runtime::scaffold_env::APPROVE_SOCK)
        .expect(delphi_runtime::scaffold_env::APPROVE_SOCK);
    let exe = std::env::var(delphi_runtime::scaffold_env::AI_EXE)
        .expect(delphi_runtime::scaffold_env::AI_EXE);
    let arg = std::env::var(delphi_runtime::scaffold_env::AI_ARG).unwrap_or_default();
    let bind_rw = std::env::var(delphi_runtime::scaffold_env::AI_BIND_RW).unwrap_or_else(|_| "/tmp".into());

    let mut stream = UnixStream::connect(&sock).expect("connect approve.sock");

    let propose = pb::Propose {
        argv: vec!["tool".into(), arg],
        cwd: "/".into(),
        env_delta: vec![],
        fs_binds: vec![ro("/usr"), ro("/bin"), ro("/lib"), ro("/lib64"), rw(&bind_rw)],
        exe_path: exe,
        net_policy: pb::NetPolicy::NetNone as i32,
        timeout_secs: 30,
        required_tier: pb::RequiredTier::TierConfirm as i32,
    };

    // Propose → Pending.
    let pending = ai_round_trip(&mut stream, &propose_msg(propose)).expect("propose round-trip");
    let pending_id = match pending.msg {
        Some(pb::daemon_to_ai::Msg::Pending(p)) => p.pending_id,
        other => panic!("expected Pending, got {other:?}"),
    };
    eprintln!("[stubborn-ai] pending_id = {pending_id}");

    // Granted arrives after the human consents (no AI message in between).
    let granted: pb::DaemonToAi = read_frame(&mut stream).expect("read Granted");
    let token = match granted.msg {
        Some(pb::daemon_to_ai::Msg::Granted(g)) => g.token,
        other => panic!("expected Granted, got {other:?}"),
    };
    eprintln!("[stubborn-ai] received token");

    // Present the token for the SAME pending_id (no action data on the wire).
    let done = ai_round_trip(&mut stream, &present_msg(&pending_id, &token)).expect("present round-trip");
    eprintln!("[stubborn-ai] terminal: {:?}", done.msg);

    // THE POINT OF THIS BINARY. The terminal response has been ACKNOWLEDGED — the daemon has
    // done everything the protocol asks of it — and this process now refuses to exit. Printed
    // before sleeping so the test can distinguish "reached the stubborn state" from "died
    // early", which would make the daemon's clean exit meaningless.
    eprintln!("[stubborn-ai] STUBBORN: terminal response acknowledged, NOT exiting");
    let secs: u64 = std::env::var("DELPHI_STUBBORN_AI_SLEEP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);
    std::thread::sleep(std::time::Duration::from_secs(secs));
    eprintln!("[stubborn-ai] slept {secs}s without being killed — the daemon did NOT bound its wait");
}
