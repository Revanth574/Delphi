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

/// Read one `u32`-length-prefixed protobuf frame into `M`.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] if the length prefix is missing, the declared length
/// exceeds [`MAX_FRAME`], the body is short, or the protobuf decode fails (EOF on a
/// clean channel close surfaces as a read error too — the caller treats it as the
/// peer hanging up).
pub fn read_frame<M: Message + Default>(r: &mut impl Read) -> Result<M, RuntimeError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(|e| RuntimeError::Protocol(format!("frame length read: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(RuntimeError::Protocol(format!(
            "inbound frame {len} bytes exceeds MAX_FRAME {MAX_FRAME}"
        )));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)
        .map_err(|e| RuntimeError::Protocol(format!("frame body read ({len} bytes): {e}")))?;
    M::decode(&body[..]).map_err(|e| RuntimeError::Protocol(format!("protobuf decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
