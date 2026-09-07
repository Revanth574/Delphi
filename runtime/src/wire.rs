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

/// Read one `u32`-length-prefixed protobuf frame into `M`. **No deadline** — blocks until the
/// peer completes the frame.
///
/// # WHICH SIDE OF THE TRUST LINE ARE YOU ON? (D0A-R28-01)
///
/// **Use this when you are waiting on a COOPERATING peer**, where an unbounded wait is the
/// correct behaviour: a client waiting for `Granted` is waiting for **a human to authenticate**,
/// and there is no defensible number of seconds to cap that at.
///
/// **Use [`read_frame_untrusted`] when the peer is untrusted** — the daemon reading from the AI
/// socket. That is where a stall is an attack rather than a person thinking.
///
/// D0A-R27-02 put the deadline HERE, in the shared utility, which was wrong in a specific and
/// instructive way: a shared reader **cannot know which side of that line its caller is on**.
/// The result was that a daemon-side hardening became a 30-second cap on human consent —
/// breaking the legitimate path to close an attack path, which is the worse failure of the two.
/// The bound now lives at the call site that knows the peer is untrusted.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] if the length prefix is missing, the declared length exceeds
/// [`MAX_FRAME`], the body is short, or the protobuf decode fails.
pub fn read_frame<M: Message + Default>(r: &mut impl Read) -> Result<M, RuntimeError> {
    read_frame_by(r, client_deadline_policy())
}

/// The deadline policy `read_frame` applies to a COOPERATING peer: **none**.
///
/// A function rather than a literal `None` so a test can exercise the production wrapper's own
/// policy rather than a hand-built approximation of it (D0A-R29-04). See
/// `read_frame_applies_no_deadline_to_a_cooperating_peer`.
fn client_deadline_policy() -> Option<Instant> {
    None
}

/// Read one frame from an **UNTRUSTED** peer, bounded by [`FRAME_DEADLINE`] (D0A-R27-02).
///
/// `MAX_FRAME` bounds how many bytes a frame may declare; it bounds nothing about how long they
/// take to arrive. Without this, an authorised requester could connect, send a single prefix
/// byte, and hold the ROOT daemon **before canonicalization and before consent**, where neither
/// the filesystem read deadline nor the gate can help.
///
/// The deadline is ABSOLUTE across the whole frame. A per-read timeout is reset by every byte,
/// so a peer trickling one byte per interval never stalls and holds the daemon forever — which
/// is why [`arm_frame_liveness`] is necessary but not sufficient.
///
/// # Errors
///
/// As [`read_frame`], plus [`RuntimeError::Protocol`] when the deadline elapses.
pub fn read_frame_untrusted<M: Message + Default>(r: &mut impl Read) -> Result<M, RuntimeError> {
    read_frame_by(r, Some(Instant::now() + FRAME_DEADLINE))
}

/// [`read_frame`] against a caller-supplied absolute deadline (the seam tests use).
pub fn read_frame_by<M: Message + Default>(
    r: &mut impl Read,
    deadline: Option<Instant>,
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
    deadline: Option<Instant>,
    what: &str,
) -> Result<(), RuntimeError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        if deadline.is_some_and(|d| Instant::now() >= d) {
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
    // D0A-R28-03: CHECK AGAIN AFTER THE FILLING READ. The check at the loop head is not
    // enough — when the final read completes the buffer, the loop condition is false and the
    // function returned Ok having never re-examined the clock. So a frame whose last byte
    // arrived past the deadline was ACCEPTED, and the overrun was bounded only incidentally by
    // the socket's own read timeout. An absolute acceptance deadline has to be checked at
    // acceptance.
    if deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(RuntimeError::Protocol(format!(
            "{what}: the frame completed AFTER the deadline ({} bytes) — an absolute deadline \
             is checked at acceptance, not only before each read (D0A-R28-03)",
            buf.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// D0A-R28-03 — a frame whose FINAL byte arrives after the deadline is refused.
    ///
    /// The deadline was checked at the loop head only: when the last read completed the
    /// buffer, the loop condition went false and the function returned `Ok` without ever
    /// re-examining the clock. So a late frame was ACCEPTED, and the overrun was bounded only
    /// incidentally by the socket's read timeout — not by the absolute deadline that was
    /// claimed. An acceptance deadline has to be checked at acceptance.
    #[test]
    fn a_frame_whose_last_byte_arrives_after_the_deadline_is_refused() {
        let (mut daemon, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        arm_frame_liveness(&daemon).expect("arm");
        let msg = pb::AiToDaemon {
            msg: Some(pb::ai_to_daemon::Msg::Present(pb::Present {
                pending_id: "act-1".into(),
                token: "1000:abcd".into(),
            })),
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &msg).expect("encode");
        let writer = std::thread::spawn(move || {
            let mut p = &peer;
            // Everything but the last byte immediately, so the read loop is fed and the
            // deadline is not tripped at the loop head...
            let _ = p.write_all(&encoded[..encoded.len() - 1]);
            let _ = p.flush();
            // ...then the final byte, late.
            std::thread::sleep(Duration::from_millis(150));
            let _ = p.write_all(&encoded[encoded.len() - 1..]);
            let _ = p.flush();
            std::thread::sleep(Duration::from_millis(50));
        });
        let r: Result<pb::AiToDaemon, _> =
            read_frame_by(&mut daemon, Some(Instant::now() + Duration::from_millis(80)));
        match r {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("deadline"),
                "refused, but not by the deadline: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "a frame completed 150 ms into an 80 ms deadline was ACCEPTED — the deadline is \
                 checked before reads but not at acceptance (D0A-R28-03)"
            ),
        }
        let _ = writer.join();
    }

    /// D0A-R28-01 / **corrected at D0A-R29-04** — `read_frame` applies NO deadline to a
    /// cooperating peer.
    ///
    /// # The previous version of this test did not catch the regression it claimed to
    ///
    /// R28-01's regression was a **30-second** absolute bound in the shared reader, which
    /// capped *a human deciding whether to authenticate*. The test written to catch it used a
    /// **900 ms** delay — and 900 ms does not trip a 30-second deadline, so **it would have
    /// PASSED against the shipping defect.** Its weaken appeared to bite only because the
    /// weaken installed a 500 ms deadline, a value chosen so the 900 ms delay would trip it.
    /// The RED demonstrated a defect constructed to be demonstrable, not the one that shipped.
    /// Both the commit message and the baseline called it "the test that would have caught the
    /// regression". That was false.
    ///
    /// # Why this version is not just "sleep longer"
    ///
    /// **A test whose delay must exceed the production bound is a test that takes at least
    /// that long**, and the next person will reach for a fast one and reintroduce the same
    /// hole. So the assertion is on the POLICY rather than on a race against it:
    /// `client_deadline_policy()` is what the production `read_frame` passes, and asserting it
    /// is `None` catches ANY finite bound — 500 ms, 30 s, or an hour — where a timing test
    /// catches only bounds shorter than its own sleep.
    ///
    /// The behavioural half is kept as well, with a delay that exceeds the socket's 250 ms
    /// polling timeout, which is what a *liveness* mistake would trip.
    #[test]
    fn read_frame_applies_no_deadline_to_a_cooperating_peer() {
        // THE PROPERTY, checked against the production wrapper's own policy rather than a
        // reconstruction of it. Any finite deadline here is the R28-01 regression.
        assert!(
            client_deadline_policy().is_none(),
            "read_frame imposed a deadline on a COOPERATING peer. That wait is a human \
             deciding whether to authenticate, and there is no defensible number of seconds \
             to cap it at (D0A-R28-01). A timing test cannot catch this — the shipped bound \
             was 30s and no reasonable test sleeps that long (D0A-R29-04)."
        );

        // And the behavioural half: a delay past the socket's 250 ms polling timeout, which is
        // what a liveness error trips.
        let (mut client, peer) = std::os::unix::net::UnixStream::pair().expect("pair");
        arm_frame_liveness(&client).expect("arm");
        let msg = pb::DaemonToAi {
            msg: Some(pb::daemon_to_ai::Msg::Granted(pb::Granted {
                pending_id: "act-1".into(),
                token: "1000:abcd".into(),
            })),
        };
        let sender = msg.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(900));
            let mut p = &peer;
            write_frame(&mut p, &sender).expect("write Granted");
            std::thread::sleep(Duration::from_millis(50));
        });
        let got: pb::DaemonToAi =
            read_frame(&mut client).expect("a cooperating peer's frame must still arrive");
        assert_eq!(got, msg);
        let _ = writer.join();
    }

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
            read_frame_by(&mut daemon, Some(Instant::now() + Duration::from_millis(400)));
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
            read_frame_by(&mut daemon, Some(Instant::now() + Duration::from_millis(400)));
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
            read_frame_by(&mut daemon, Some(Instant::now() + Duration::from_secs(5)))
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
