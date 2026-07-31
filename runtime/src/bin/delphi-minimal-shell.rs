// SPDX-License-Identifier: MIT

//! B1 minimal shell — the thinnest thing that drives the consent path over the
//! private channel. NOT the React-WRY shell (B2): no rendering, the human is
//! scripted (the password comes from the env, as in `be_human`). It proves the
//! private-channel protocol the real shell will speak.
//!
//! Sequence over the fork-passed channel (fd from `DELPHI_CHANNEL_FD`):
//!   1. receive the approval request (digest + preview) — the preview reaches the
//!      pinned shell;
//!   2. drive the live PAM conversation (read the prompt, write the password);
//!   3. send the mint-confirm (echo the digest) to signal approval.

use std::os::fd::RawFd;

use delphi_runtime::service::{recv_approval_request, send_mint_confirm};

fn main() {
    let chan: RawFd = std::env::var("DELPHI_CHANNEL_FD")
        .expect("DELPHI_CHANNEL_FD")
        .parse()
        .expect("DELPHI_CHANNEL_FD is a fd number");
    let password = std::env::var("DELPHI_PASSWORD").unwrap_or_default();

    // 0. READINESS (D0). The daemon's `launch()` blocks here until this datagram arrives:
    //    until it does, the shell is indistinguishable from one that exec'd and died. This
    //    minimal shell has nothing to initialise, so "up" is simply "reached main" — the real
    //    WRY host signals later, once its WebView has loaded (see runtime/shell-host).
    delphi_runtime::readiness::signal_ready(chan).expect("signal readiness");

    // 1. The approval request: digest + the arbiter's preview of the exact action.
    let (digest, preview) = recv_approval_request(chan).expect("recv approval request");
    eprintln!("[minimal-shell] approval preview over the private channel:\n{preview}");

    // 2. PAM conversation: read the daemon's prompt datagram, write the password
    //    datagram (the scripted human). pam_unix sends one PROMPT_ECHO_OFF.
    let mut buf = [0u8; 4096];
    // SAFETY: read one prompt datagram and write the password datagram on the
    // SEQPACKET channel fd (message boundaries preserved).
    unsafe {
        let _ = nix::libc::read(chan, buf.as_mut_ptr().cast(), buf.len());
        let _ = nix::libc::write(chan, password.as_ptr().cast(), password.len());
    }

    // 3. Mint-confirm: echo the digest of the action the human approved.
    send_mint_confirm(chan, &digest).expect("send mint confirm");
    eprintln!("[minimal-shell] approved + mint-confirm sent");
}
