//! NØNOS IPC Transport Layer
//!
//! Implements encrypted, chunked, session-based IPC streams for high-throughput
//! inter-module communication. This layer abstracts multiple-message framing,
//! session coordination, and optional confidentiality wrappers.

use crate::ipc::message::{IpcEnvelope, MessageType, MsgFlags};
use crate::syscall::capabilities::CapabilityToken;
use alloc::{vec::Vec, string::String, format};
use core::time::Duration;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// Maximum IPC stream chunk size
pub const MAX_CHUNK_SIZE: usize = 1024;

/// Stream transfer session struct
#[derive(Debug)]
pub struct IpcStream {
    pub session_id: &'static str,
    pub from: &'static str,
    pub to: &'static str,
    pub buffer: Mutex<Vec<u8>>,
    pub last_activity: Duration,
    pub encrypted: bool,
    pub sequence: AtomicU64,
}

impl IpcStream {
    pub fn new(session_id: &'static str, from: &'static str, to: &'static str, encrypted: bool) -> Self {
        Self {
            session_id,
            from,
            to,
            buffer: Mutex::new(Vec::new()),
            last_activity: Duration::from_secs(0),
            encrypted,
            sequence: AtomicU64::new(0),
        }
    }

    pub fn push_chunk(&self, chunk: &[u8]) {
        let mut buf = self.buffer.lock();
        buf.extend_from_slice(chunk);
    }

    pub fn flush(&self) -> Vec<u8> {
        let mut buf = self.buffer.lock();
        let flushed = buf.clone();
        buf.clear();
        flushed
    }

    pub fn build_envelope(&self, chunk: &[u8]) -> IpcEnvelope {
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);
        let mut flags = 0;
        if self.encrypted {
            flags |= MsgFlags::ENCRYPTED;
        }

        IpcEnvelope::new(
            MessageType::User,
            self.from,
            self.to,
            chunk,
            Some(self.session_id),
        )
    }

    pub fn is_idle(&self, now: Duration, timeout: Duration) -> bool {
        now.checked_sub(self.last_activity)
            .map(|delta| delta > timeout)
            .unwrap_or(true)
    }
}

/// Send an entire payload as framed stream chunks
pub fn send_stream_payload(
    stream: &IpcStream,
    payload: &[u8],
    tx: impl Fn(IpcEnvelope) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    for chunk in payload.chunks(MAX_CHUNK_SIZE) {
        let env = stream.build_envelope(chunk);
        tx(env)?;
    }
    Ok(())
}
