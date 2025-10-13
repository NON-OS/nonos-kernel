#![no_std]

extern crate alloc;

use alloc::{vec, vec::Vec};

use super::nonos_message::{IpcEnvelope, MessageType, SecurityLevel};

/// A stream descriptor for framed large-payload transport
#[derive(Debug, Clone)]
pub struct IpcStream {
    pub from: alloc::string::String,
    pub to: alloc::string::String,
    pub stream_id: u64,
    pub mtu: usize,       // bytes per frame (payload-only, not counting header)
    pub sec_level: SecurityLevel,
}

impl IpcStream {
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: alloc::string::String::from(from),
            to: alloc::string::String::from(to),
            stream_id: next_stream_id(),
            mtu: 4096 - 32, // conservative default frame payload size
            sec_level: SecurityLevel::None,
        }
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = core::cmp::max(256, core::cmp::min(mtu, 64 * 1024));
        self
    }

    pub fn with_security(mut self, level: SecurityLevel) -> Self {
        self.sec_level = level;
        self
    }
}

/// Send a payload via framed stream.
/// The tx function is responsible for policy/capability checks at the envelope layer.
pub fn send_stream_payload<F>(stream: &IpcStream, payload: &[u8], mut tx: F) -> Result<(), &'static str>
where
    F: FnMut(IpcEnvelope) -> Result<(), &'static str>,
{
    if payload.is_empty() {
        // send an empty data message to indicate EOF
        let env = IpcEnvelope {
            from: stream.from.clone(),
            to: stream.to.clone(),
            message_type: MessageType::Data,
            data: build_frame(&FrameHeader {
                magic: FRAME_MAGIC,
                version: 1,
                stream_id: stream.stream_id,
                seq: 0,
                total: 0,
                flags: FLAG_EOF,
            }, &[]),
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: stream.sec_level,
        };
        return tx(env);
    }

    let total = (payload.len() + stream.mtu - 1) / stream.mtu;
    for seq in 0..total {
        let start = seq * stream.mtu;
        let end = core::cmp::min(start + stream.mtu, payload.len());
        let chunk = &payload[start..end];

        let hdr = FrameHeader {
            magic: FRAME_MAGIC,
            version: 1,
            stream_id: stream.stream_id,
            seq: seq as u32,
            total: total as u32,
            flags: if seq + 1 == total { FLAG_EOF } else { 0 },
        };
        let frame = build_frame(&hdr, chunk);
        let env = IpcEnvelope {
            from: stream.from.clone(),
            to: stream.to.clone(),
            message_type: MessageType::Data,
            data: frame,
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: stream.sec_level,
        };
        tx(env)?;
    }
    Ok(())
}

// ----- Framing (binary header) -----

const FRAME_MAGIC: u32 = 0x5354524Du32; // "STRM"
const FLAG_EOF: u8 = 0x01;

#[repr(C, packed)]
struct FrameHeader {
    magic: u32,   // FRAME_MAGIC
    version: u16, // 1
    stream_id: u64,
    seq: u32,
    total: u32,
    flags: u8, // FLAG_EOF etc
}

fn build_frame(h: &FrameHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(core::mem::size_of::<FrameHeader>() + payload.len());
    out.extend_from_slice(&h.magic.to_le_bytes());
    out.extend_from_slice(&h.version.to_le_bytes());
    out.extend_from_slice(&h.stream_id.to_le_bytes());
    out.extend_from_slice(&h.seq.to_le_bytes());
    out.extend_from_slice(&h.total.to_le_bytes());
    out.push(h.flags);
    out.extend_from_slice(payload);
    out
}

// ----- Stream ID generation -----

fn next_stream_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let salt = crate::time::timestamp_millis();
    let c = NEXT.fetch_add(1, Ordering::Relaxed);
    // simple mix
    salt ^ (c.wrapping_mul(0x9E37_79B9_7F4A_7C15))
}
