// SPDX-License-Identifier: MIT

//! The AI↔daemon general-socket wire (Increment B1).
//!
//! protobuf (prost) message types + length-prefixed framing over the `approve.sock`
//! stream. The wire is the project's IPC law and is what B2's real Brain reuses
//! unchanged — the minimal AI exercises the REAL protocol so B2 swaps the AI's
//! *logic*, not the wire.
//!
//! The half-(ii) invariant is structural: [`pb::Present`] carries only a
//! `pending_id` + `token` — no action fields (see `proto/runtime_wire.proto`).

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use prost::Message;

use crate::RuntimeError;

/// The prost-generated types for protobuf package `delphi.runtime.wire`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/delphi.runtime.wire.rs"));
}

/// Frame body cap — a proposal is small; anything larger is a malformed/hostile
/// frame and is rejected before allocation.
pub const MAX_FRAME: usize = 64 * 1024;

/// Write `msg` as one `u32` (big-endian) length-prefixed protobuf frame.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] if the encoded body exceeds [`MAX_FRAME`] or the
/// underlying write fails.
pub fn write_frame<M: Message>(w: &mut impl Write, msg: &M) -> Result<(), RuntimeError> {
    let body = msg.encode_to_vec();
    if body.len() > MAX_FRAME {
        return Err(RuntimeError::Protocol(format!(
            "outbound frame {} bytes exceeds MAX_FRAME {MAX_FRAME}",
            body.len()
        )));
    }
    let len = u32::try_from(body.len()).expect("len <= MAX_FRAME fits u32");
    w.write_all(&len.to_be_bytes())
        .and_then(|()| w.write_all(&body))
        .and_then(|()| w.flush())
        .map_err(|e| RuntimeError::Protocol(format!("frame write: {e}")))
}

/// How long the root daemon will wait for ONE complete frame to arrive (D0A-R27-02).
///
/// An ABSOLUTE deadline across the whole frame, not a per-read timeout. A per-read timeout is
/// reset by every byte, so a peer trickling one byte per interval holds the daemon forever
/// while never technically stalling — which is why `set_read_timeout` alone is not the fix.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(30);

/// Arm a stream so [`read_frame`]'s deadline is reachable (D0A-R27-02).
///
/// Sets a short per-read timeout. That timeout alone is NOT the fix — it is reset by every
/// byte, so a trickling peer resets it forever — but without it a blocking `read` never
/// returns and the absolute deadline is unreachable code. Call it once, at accept.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if the timeout cannot be set.
///
/// # Examples
///
/// ```no_run
/// # use std::os::unix::net::UnixStream;
/// # fn f(s: &UnixStream) -> Result<(), delphi_runtime::RuntimeError> {
/// delphi_runtime::wire::arm_frame_liveness(s)?;
/// # Ok(()) }
/// ```
pub fn arm_frame_liveness(s: &std::os::unix::net::UnixStream) -> Result<(), RuntimeError> {
    s.set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| RuntimeError::Protocol(format!("set_read_timeout: {e}")))
}

/// Read one `u32`-length-prefixed protobuf frame into `M`, bounded in TIME as well as SIZE.
///
/// # Why the deadline exists (D0A-R27-02)
///
/// `MAX_FRAME` bounds how many bytes a frame may declare; **it bounds nothing about how long
/// they take to arrive.** Both reads here are on a blocking stream, and the daemon's only
/// other timeout covers `accept` — so an authorised requester could connect, send a single
/// prefix byte (or a valid prefix and a short body), and hold the connection. The ROOT daemon
/// then blocks **before canonicalization and before consent**, where neither the filesystem
/// read deadline nor the gate can help. The same shape applies to the wait for `Present`.
///
/// This was found in `wire.rs`, a file six consecutive review rounds never named.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] if the deadline elapses, the length prefix is missing, the
/// declared length exceeds [`MAX_FRAME`], the body is short, or the protobuf decode fails (EOF
/// on a clean channel close surfaces as a read error too — the caller treats it as the peer
/// hanging up).
pub fn read_frame<M: Message + Default>(r: &mut impl Read) -> Result<M, RuntimeError> {
    read_frame_by(r, Instant::now() + FRAME_DEADLINE)
}

/// [`read_frame`] against a caller-supplied absolute deadline (the seam tests use).
pub fn read_frame_by<M: Message + Default>(
    r: &mut impl Read,
    deadline: Instant,
) -> Result<M, RuntimeError> {
    let mut len_buf = [0u8; 4];
    read_exact_by(r, &mut len_buf, deadline, "frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(RuntimeError::Protocol(format!(
            "inbound frame {len} bytes exceeds MAX_FRAME {MAX_FRAME}"
        )));
    }
    let mut body = vec![0u8; len];
    read_exact_by(r, &mut body, deadline, "frame body")?;
    M::decode(&body[..]).map_err(|e| RuntimeError::Protocol(format!("protobuf decode: {e}")))
}

/// Fill `buf`, giving up at the ABSOLUTE `deadline` however much progress has been made.
///
/// **REQUIRES A READER THAT RETURNS.** The deadline is checked between reads, so a reader that
/// blocks forever inside one `read` call never reaches it. For a socket that means a
/// `set_read_timeout` must be in force — [`arm_frame_liveness`] does it, and the accept paths
/// call that. The socket timeout supplies LIVENESS (reads return); this deadline supplies the
/// BOUND (progress does not buy more time). Neither alone is sufficient.
///
/// The deadline is not extended by progress — that is the whole point. A peer feeding one byte
/// per second resets every per-read timeout ever set while still holding the daemon
/// indefinitely, so partial progress must not buy more time.
fn read_exact_by(
    r: &mut impl Read,
    buf: &mut [u8],
    deadline: Instant,
    what: &str,
) -> Result<(), RuntimeError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        if Instant::now() >= deadline {
            return Err(RuntimeError::Protocol(format!(
                "{what}: deadline elapsed with {filled} of {} bytes received — a peer that \
                 stalls or trickles cannot hold the root daemon before consent (D0A-R27-02)",
                buf.len()
            )));
        }
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(RuntimeError::Protocol(format!(
                    "{what}: peer closed with {filled} of {} bytes received",
                    buf.len()
                )))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // The socket's own read timeout fired; the ABSOLUTE deadline above decides
                // whether there is any time left, so this is a retry point and not a failure.
                continue;
            }
            Err(e) => return Err(RuntimeError::Protocol(format!("{what} read: {e}"))),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// D0A-R27-02 — a peer that sends part of a frame and stops cannot hold the daemon.
    ///
    /// One prefix byte, then silence, connection held open. Before the fix both `read_exact`
    /// calls blocked forever on the ROOT daemon, before canonicalization and before consent.
    #[test]
    fn a_stalled_peer_cannot_hold_the_daemon_past_the_frame_deadline() {
        let (mut daemon, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        arm_frame_liveness(&daemon).expect("arm");
        {
            let mut p = &peer;
            p.write_all(&[0u8]).expect("one prefix byte"); // 1 of the 4 needed
            p.flush().ok();
        }
        let started = Instant::now();
        let r: Result<pb::AiToDaemon, _> =
            read_frame_by(&mut daemon, Instant::now() + Duration::from_millis(400));
        match r {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("deadline elapsed"),
                "refused, but not by the deadline: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!("a 1-byte prefix decoded as a frame"),
        }
        assert!(started.elapsed() < Duration::from_secs(5), "the deadline did not bound the wait");
        drop(peer);
    }

    /// D0A-R27-02 — **the discriminating case**: a peer making CONTINUOUS PROGRESS is still
    /// bounded.
    ///
    /// This is the one a per-read timeout cannot catch, and the reason `set_read_timeout` alone
    /// is not the fix: every byte resets that timeout, so a peer trickling one byte per
    /// interval never stalls and holds the daemon forever. The deadline here is ABSOLUTE — it
    /// is not extended by progress — so the trickle is refused mid-frame.
    #[test]
    fn a_trickling_peer_cannot_extend_the_frame_deadline_by_making_progress() {
        let (mut daemon, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        arm_frame_liveness(&daemon).expect("arm");
        let writer = std::thread::spawn(move || {
            let mut p = &peer;
            // A large declared body, then one byte at a time, forever.
            let _ = p.write_all(&2048u32.to_be_bytes());
            for _ in 0..2048 {
                if p.write_all(&[0x41]).is_err() {
                    return;
                }
                let _ = p.flush();
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let started = Instant::now();
        let r: Result<pb::AiToDaemon, _> =
            read_frame_by(&mut daemon, Instant::now() + Duration::from_millis(400));
        let elapsed = started.elapsed();
        match r {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("deadline elapsed"),
                "refused, but not by the deadline — progress may still be buying time: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!("a trickled partial frame was accepted"),
        }
        assert!(
            elapsed < Duration::from_secs(5),
            "a peer making continuous progress held the daemon for {elapsed:?} — the deadline \
             is being extended by progress, which is exactly what a per-read timeout does"
        );
        drop(daemon);
        let _ = writer.join();
    }

    /// D0A-R27-02 — the positive control: a complete frame inside the deadline still works.
    ///
    /// Without it, a `read_frame` that refused everything would satisfy both tests above.
    #[test]
    fn a_complete_frame_within_the_deadline_is_still_accepted() {
        let (mut daemon, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        arm_frame_liveness(&daemon).expect("arm");
        let msg = pb::AiToDaemon {
            msg: Some(pb::ai_to_daemon::Msg::Present(pb::Present {
                pending_id: "act-1".into(),
                token: "1000:abcd".into(),
            })),
        };
        {
            let mut p = &peer;
            write_frame(&mut p, &msg).expect("write");
        }
        let got: pb::AiToDaemon =
            read_frame_by(&mut daemon, Instant::now() + Duration::from_secs(5))
                .expect("a complete frame must still be accepted");
        assert_eq!(got, msg, "round trip under the deadline");
        drop(peer);
    }

    /// A framed message round-trips through the length prefix + protobuf encode.
    #[test]
    fn frame_round_trips() {
        let msg = pb::AiToDaemon {
            msg: Some(pb::ai_to_daemon::Msg::Present(pb::Present {
                pending_id: "act-1".into(),
                token: "1000:abcd".into(),
            })),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).expect("write");
        let mut cur = Cursor::new(buf);
        let got: pb::AiToDaemon = read_frame(&mut cur).expect("read");
        match got.msg {
            Some(pb::ai_to_daemon::Msg::Present(p)) => {
                assert_eq!(p.pending_id, "act-1");
                assert_eq!(p.token, "1000:abcd");
            }
            other => panic!("expected Present, got {other:?}"),
        }
    }

    /// A length prefix beyond MAX_FRAME is rejected before allocating.
    #[test]
    fn oversized_length_prefix_rejected() {
        let mut framed = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        framed.push(0); // a stray body byte
        let mut cur = Cursor::new(framed);
        let err = read_frame::<pb::AiToDaemon>(&mut cur).expect_err("oversize must reject");
        assert!(matches!(err, RuntimeError::Protocol(_)));
    }
}
