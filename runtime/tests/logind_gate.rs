// SPDX-License-Identifier: MIT

//! logind gate — forge-resistance + live query (Increment 1c, R3-02).
//!
//! The gate's verdict must come from **logind** (authoritative), not a same-uid-
//! assertable signal. The RED-proof is the same one-variable discipline as the PAM
//! routing test: the SAME forge intent ("make the gate pass for a session I don't
//! legitimately control as active-local"), with the gate's **trust source** as the
//! only variable — logind vs a same-uid-writable signal — and the outcome flips.
//!
//! Scope (carried to the 1d review): the **decision** (`active && !remote`) is
//! unit-proven (`logind.rs`); forge-resistance is proven here; the **live query**
//! path is exercised where a real session exists (gated). Provisioning a logind
//! session for a *daemon-spawned shell* (via `pam_open_session`) is a documented
//! **deploy requirement** — not faked. logind-gate-resistance = `(gate trusts
//! logind, RED-proven vs same-uid-signal) + (logind authoritative, deploy-real)`,
//! provisioning deferred.

use std::fs;
use std::path::PathBuf;

use delphi_runtime::logind::{session_passes_gate, LogindVerdict, SessionVerdict};

/// A verdict sourced from a same-uid-writable FILE — the deliberately-weakened,
/// forgeable trust source for the RED-proof.
struct FileAssertedVerdict {
    path: PathBuf,
}

impl SessionVerdict for FileAssertedVerdict {
    fn is_active(&self) -> bool {
        fs::read_to_string(&self.path).is_ok_and(|s| s.contains("active"))
    }
    fn is_remote(&self) -> bool {
        fs::read_to_string(&self.path).is_ok_and(|s| s.contains("remote"))
    }
    fn is_seated(&self) -> bool {
        fs::read_to_string(&self.path).is_ok_and(|s| s.contains("seated"))
    }
}

/// CORRECT: the gate trusts LOGIND. A same-uid process cannot make logind report a
/// session it does not control as active-and-local — so a forged/unknown session
/// cannot pass.
#[test]
fn logind_trust_denies_same_uid_forge() {
    let fake = format!("delphi-no-such-session-{}", std::process::id());
    let passed = LogindVerdict::query(&fake).is_some_and(|v| session_passes_gate(&v));
    assert!(
        !passed,
        "logind-trust: a session logind does not know cannot pass the gate — a same-uid \
         process cannot inject an active-local verdict into logind"
    );
}

/// RED-proof (durable positive control): the gate trusts a same-uid-assertable
/// signal; the same-uid attacker forges it. SAME forge intent as above, trust
/// source flipped from logind to a same-uid-writable file → outcome flips to PASS.
#[test]
fn red_proof_same_uid_signal_trust_lets_forge_succeed() {
    let path = PathBuf::from(format!("/tmp/delphi-forge-session-{}", std::process::id()));
    let _ = fs::remove_file(&path);
    // The same-uid attacker forges the FULL verdict (active + local + seated) by writing
    // the signal it can reach — the B2a seat axis is forgeable too when the source is a
    // same-uid file, which is precisely why the source must be logind.
    fs::write(&path, "active seated").expect("same-uid write to the forgeable signal");
    let passed = session_passes_gate(&FileAssertedVerdict { path: path.clone() });
    let _ = fs::remove_file(&path);
    assert!(
        passed,
        "RED-proof: trusting a same-uid-writable signal lets the attacker forge \
         active-local-seated → the gate passes. This is exactly why the gate must query \
         logind, not a same-uid signal."
    );
}

/// Gated-live GATE-NEGATIVE (B2a R3-02 tightening, biting on WSL2): a **real**
/// active + local but **seatless** session — the kind WSL2 has (`SEAT=-`) — passes the
/// pre-B2a `active && !remote` gate yet MUST FAIL the tightened `active && !remote &&
/// seated` gate. The session is found via logind's own `/run/systemd/sessions` registry
/// and confirmed via the authoritative `sd_session_*` query (not faked). If no such
/// session exists here (a seated desktop), it documents — the seated **positive** runs
/// on the real seated lane.
#[test]
fn seatless_active_session_fails_the_seated_gate_live() {
    let Some((id, v)) = active_local_seatless_session() else {
        eprintln!(
            "DEFER gate-negative-live: no active+local+seatless session in logind's registry \
             here. On a seated desktop the seated POSITIVE is the case to prove (real lane)."
        );
        return;
    };
    // Precondition: this real session passes the PRE-B2a gate (active && !remote)…
    let old_gate = v.is_active() && !v.is_remote();
    let new_gate = session_passes_gate(&v);
    eprintln!(
        "gate-negative-live BIT: real logind session {id:?} — active={} remote={} seated={} \
         → OLD gate (active&&!remote)={old_gate}, tightened seated gate={new_gate}",
        v.is_active(),
        v.is_remote(),
        v.is_seated(),
    );
    assert!(old_gate, "precondition: a real active+local session passes the OLD gate");
    // …and MUST fail the tightened seated gate — the bite.
    assert!(
        !new_gate,
        "B2a R3-02: a real active+local but SEATLESS session must FAIL the seated gate \
         (it passed the pre-B2a active && !remote gate)"
    );
}

/// Scan logind's session registry (`/run/systemd/sessions/<id>`) for an active, local,
/// **seatless** session, confirmed via the authoritative `sd_session_*` query. The `.ref`
/// lock files and non-session entries are skipped.
fn active_local_seatless_session() -> Option<(String, LogindVerdict)> {
    for entry in fs::read_dir("/run/systemd/sessions").ok()?.flatten() {
        let name = entry.file_name();
        let id = name.to_string_lossy().into_owned();
        if id.ends_with(".ref") || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        if let Some(v) = LogindVerdict::query(&id)
            && v.is_active()
            && !v.is_remote()
            && !v.is_seated()
        {
            return Some((id, v));
        }
    }
    None
}

/// Gated-live: the direct `sd_session_*` query path works where a real logind
/// session exists; otherwise the deploy requirement is documented, not faked.
#[test]
fn live_logind_query_path_works_or_documents_deferral() {
    let pid = i32::try_from(std::process::id()).expect("pid fits i32");
    match LogindVerdict::for_pid(pid) {
        Some(v) => {
            // A real session: the LIVE sd_session_* query succeeded and yields a
            // usable verdict; the gate decision then composes deterministically.
            // (Active/local state here is environmental, so it is not asserted —
            // the point proven is that the live query path works.)
            let _ = session_passes_gate(&v);
        }
        None => {
            eprintln!(
                "DEFER live logind query: this process has no logind session (WSL2 sessions \
                 are ephemeral/seatless). DEPLOY REQUIREMENT: the daemon provisions a logind \
                 session for the spawned shell via pam_open_session/pam_systemd; the gate then \
                 queries it live via the same sd_session_* path proven here."
            );
        }
    }
}
