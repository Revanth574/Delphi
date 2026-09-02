// SPDX-License-Identifier: MIT
//
// D0A-R9-11 — the daemon must refuse to serve a system account.
//
// WHAT MAKES THIS DISCRIMINATING, rather than a test of a conditional. Asserting only
// "`--session root` fails" proves nothing: it fails pre-guard too, at the root-only
// anchor. So each leg asserts WHICH failure it got, and the two legs are mirror images:
//
//   * root            -> refused as a system account, and NOT at the anchor
//   * the real user   -> reaches the anchor, and is NOT refused as a system account
//
// The second leg is the positive control (`docs/DEFECT_CLASSES.md` class 35): without it,
// "root is refused" cannot be told apart from "everything is refused".
//
// Both run unprivileged by design — the guard sits before the anchor precisely so its
// refusal is reachable without root.

use std::process::{Command, Output};

fn run_daemon(session: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_delphi-runtimed"))
        .args(["--session", session])
        .output()
        .expect("spawning delphi-runtimed")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// Properties, not a literal message (standard 5): a reworded refusal must still pass,
/// and a refusal that stopped naming what it refused must still fail.
fn is_system_account_refusal(text: &str, name: &str, uid: &str) -> bool {
    let t = text.to_lowercase();
    t.contains("system account") && t.contains(name) && t.contains(uid)
}

/// Pre-guard, THIS is where `--session root` died as an unprivileged caller — the
/// root-owned runtime directory. Its presence means user resolution was passed.
///
/// **D0A-R23-12 — the `|| t.contains("permission denied")` alternative is REMOVED.** It was
/// generic enough that ANY permission error satisfied it, so the positive control could pass
/// for a reason unconnected to the guard. The daemon's actual anchor failure is
/// `establishing the root-owned runtime directory`; "permission denied" appears only in the
/// `Caused by:` chain beneath it, which is precisely the part another failure could forge.
///
/// **RESIDUAL, recorded rather than closed:** this is still a LATER-STAGE oracle — it infers
/// "the guard passed" from "a subsequent stage was reached", so a new stage inserted between
/// the guard and the anchor would invalidate it without any test going red. That is the same
/// shape as a positive control asserting `build failed`. Closing it properly needs the daemon
/// to emit a structured guard-passed witness; until then the narrowing above at least stops
/// an UNRELATED error from satisfying it.
fn reached_the_anchor(text: &str) -> bool {
    text.to_lowercase().contains("root-owned runtime directory")
}

#[test]
fn root_session_is_refused_as_a_system_account_before_the_anchor() {
    let out = run_daemon("root");
    let err = stderr_of(&out);
    assert!(!out.status.success(), "daemon must not serve `root`; stderr: {err}");
    assert!(
        is_system_account_refusal(&err, "root", "0"),
        "D0A-R9-11: refusal must name the account and its uid; got: {err}"
    );
    // The RED leg. Pre-guard the daemon proceeded past user resolution and failed HERE
    // instead, so this assertion is the one that fails against the unguarded binary.
    assert!(
        !reached_the_anchor(&err),
        "D0A-R9-11: refusal must precede the anchor — reaching it means the guard did \
         not fire and the failure is incidental; got: {err}"
    );
}

#[test]
fn a_regular_login_user_is_not_refused_as_a_system_account() {
    let uid = Command::new("id").arg("-u").output().expect("id -u");
    let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
    if uid == "0" {
        eprintln!("SKIP a_regular_login_user_is_not_refused_as_a_system_account: running as root");
        return;
    }
    let name = Command::new("id").arg("-un").output().expect("id -un");
    let name = String::from_utf8_lossy(&name.stdout).trim().to_string();

    let out = run_daemon(&name);
    let err = stderr_of(&out);
    // POSITIVE CONTROL: this user must pass the guard. It still fails afterwards (the
    // anchor needs root) — that is the point: the guard is not what stopped it.
    assert!(
        !is_system_account_refusal(&err, &name, &uid),
        "guard must not refuse a regular login user (uid {uid}); got: {err}"
    );
    assert!(
        reached_the_anchor(&err),
        "positive control is vacuous unless this user actually got PAST the guard to the \
         anchor; got: {err}"
    );
}
