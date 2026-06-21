// SPDX-License-Identifier: MIT

//! Daemon-owned PAM authentication, routed over the private channel (Increment 1c).
//!
//! The root daemon authenticates the human via a **live** `pam_authenticate`
//! against `/etc/shadow` (`docs/TRUST_MODEL.md` §4, R3-02 — "the auth party is the
//! root daemon via PAM"). The consent prompt/response travel **only** over the 1b
//! private `SOCK_SEQPACKET` channel via a custom [`ChannelConversation`]: no D-Bus,
//! no ambient agent, no tty.
//!
//! # What this proves, and what it composes with
//!
//! This module's contribution is the **routing**: the conversation is conducted
//! over the private channel, not a shared surface. It does NOT re-establish that
//! the channel is unreachable to a same-uid attacker — that is **1b's** proof
//! (`sibling_fd_theft`), *reused*. PAM-interposition-resistance is the two
//! composed: `(1c routing-over-private-channel) + (1b channel-is-private)`. The
//! interposition test proves the routing half and the RED-proof shows that routing
//! over a shared surface (the deliberately-weakened variant) lets a same-uid
//! attacker capture the prompt.
//!
//! Liveness is honest: `pam_authenticate` is real (a wrong secret fails); the
//! human-side response is *scripted* over the shell-end of the channel in tests —
//! the mechanism (live PAM + private-channel routing) is what is proven, not a
//! human in the loop.

use std::ffi::{CStr, CString};
use std::os::fd::RawFd;

use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};

use crate::RuntimeError;

/// Largest consent prompt/response datagram exchanged over the channel.
const MAX_MSG: usize = 4096;

/// A PAM [`ConversationHandler`] that sources every prompt's response from — and
/// writes every prompt to — a private channel fd (the daemon's end of the 1b
/// approval socketpair).
pub struct ChannelConversation {
    fd: RawFd,
}

impl ChannelConversation {
    /// Wrap the daemon's end of the private channel.
    #[must_use]
    pub fn new(channel_fd: RawFd) -> Self {
        Self { fd: channel_fd }
    }

    /// Send `prompt` as one SEQPACKET datagram and read the response datagram,
    /// trimming a trailing newline (the human side may send `secret\n`).
    fn exchange(&self, prompt: &CStr) -> Result<CString, ErrorCode> {
        let p = prompt.to_bytes();
        // SAFETY: write/read the borrowed channel fd; the buffer is stack-local and
        // sized by `n`. SEQPACKET preserves message boundaries (one prompt, one
        // response).
        let w = unsafe { nix::libc::write(self.fd, p.as_ptr().cast(), p.len()) };
        if w < 0 {
            return Err(ErrorCode::CONV_ERR);
        }
        let mut buf = [0u8; MAX_MSG];
        let n = unsafe { nix::libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return Err(ErrorCode::CONV_ERR);
        }
        let mut end = n as usize;
        while end > 0 && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
            end -= 1;
        }
        CString::new(&buf[..end]).map_err(|_| ErrorCode::CONV_ERR)
    }
}

impl ConversationHandler for ChannelConversation {
    fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        self.exchange(prompt)
    }

    fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        self.exchange(prompt)
    }

    // Informational messages carry no response; 1c routes only the prompt/response
    // exchange (pam_unix's password prompt) over the channel.
    fn text_info(&mut self, _msg: &CStr) {}
    fn error_msg(&mut self, _msg: &CStr) {}
}

/// Authenticate `user` via PAM `service`, driving the conversation over
/// `channel_fd` (the daemon's end of the private channel).
///
/// Live `pam_authenticate` + `pam_acct_mgmt`. Returns `Ok(())` only on a genuine
/// successful authentication; a wrong secret yields [`RuntimeError::Pam`].
///
/// # Errors
///
/// [`RuntimeError::Pam`] if `pam_start`, `pam_authenticate`, or `pam_acct_mgmt`
/// fails.
pub fn authenticate_over_channel(
    service: &str,
    user: &str,
    channel_fd: RawFd,
) -> Result<(), RuntimeError> {
    let conv = ChannelConversation::new(channel_fd);
    let mut ctx = Context::new(service, Some(user), conv)
        .map_err(|e| RuntimeError::Pam { op: "pam_start", detail: format!("{e:?}") })?;
    ctx.authenticate(Flag::NONE)
        .map_err(|e| RuntimeError::Pam { op: "pam_authenticate", detail: format!("{e:?}") })?;
    ctx.acct_mgmt(Flag::NONE)
        .map_err(|e| RuntimeError::Pam { op: "pam_acct_mgmt", detail: format!("{e:?}") })?;
    Ok(())
}
