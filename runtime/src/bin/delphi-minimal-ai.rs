// SPDX-License-Identifier: MIT

//! B1 minimal AI — the thinnest thing that drives the REAL general-socket wire.
//! NOT Brain (B2): no reasoning, it proposes one fixed action from the env. Because
//! it speaks the real protobuf protocol, B2 swaps the AI's *logic* without changing
//! the wire.
//!
//! Sequence over `approve.sock` (path from `DELPHI_APPROVE_SOCK`):
//!   Propose → receive Pending{id} → receive Granted{id, token} → Present{id, token}
//!   → receive Completed/Denied.
//!
//! Env: `DELPHI_AI_EXE` (the executable to propose), `DELPHI_AI_ARG` (argv[1] — the
//! marker the action writes), `DELPHI_AI_BIND_RW` (the writable bind for the output).

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
        required_tier: pb::RequiredTier::TierBiometric as i32,
    };

    // Propose → Pending.
    let pending = ai_round_trip(&mut stream, &propose_msg(propose)).expect("propose round-trip");
    let pending_id = match pending.msg {
        Some(pb::daemon_to_ai::Msg::Pending(p)) => p.pending_id,
        other => panic!("expected Pending, got {other:?}"),
    };
    eprintln!("[minimal-ai] pending_id = {pending_id}");

    // Granted arrives after the human consents (no AI message in between).
    let granted: pb::DaemonToAi = read_frame(&mut stream).expect("read Granted");
    let token = match granted.msg {
        Some(pb::daemon_to_ai::Msg::Granted(g)) => g.token,
        other => panic!("expected Granted, got {other:?}"),
    };
    eprintln!("[minimal-ai] received token");

    // Present the token for the SAME pending_id (no action data on the wire).
    let done = ai_round_trip(&mut stream, &present_msg(&pending_id, &token)).expect("present round-trip");
    eprintln!("[minimal-ai] terminal: {:?}", done.msg);
}
