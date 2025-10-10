//! NØNOS IPC Message Types
//!
//! Provides structured and production-grade IPC message framing for ZeroState
//! inter-module communication. Encapsulates typed envelopes, headers, priority
//! flags, delivery context, and dispatchable payload categories.

use alloc::{format, string::String, vec::Vec};
use core::time::Duration;

/// Enum of all recognized IPC message categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    User,            // General module-level data
    System,          // Kernel/platform control or broadcast
    Signal,          // Control flow: ping, shutdown, suspend
    Capability,      // Capability tokens, handshakes, or revocation
    Error,           // Structured kernel or runtime errors
    Debug,           // Trace or telemetry messaging
    Auth,            // Authentication negotiation or requests
    Timeout,         // Message timeout notification
    DeliveryFailure, // Message delivery failure notification
    Reserved(u8),    // Reserved for future extensions
}

/// Bitflags for message header
pub mod MsgFlags {
    pub const PRIORITY_HIGH: u8 = 0b0000_0001;
    pub const ACK_REQUIRED: u8 = 0b0000_0010;
    pub const ENCRYPTED: u8 = 0b0000_0100;
    pub const SYSTEM_ONLY: u8 = 0b1000_0000;
}

/// Structured IPC message header for routing and introspection
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub msg_type: MessageType,
    pub timestamp: Duration,
    pub flags: u8,
    pub sequence: u64,
    pub ttl: u8, // Optional future use: hop-count / routing TTL
}

/// Full IPC message envelope
#[derive(Debug, Clone)]
pub struct IpcEnvelope {
    pub from: &'static str,
    pub to: &'static str,
    pub message_type: MessageType,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub session_id: Option<&'static str>,
}

impl IpcEnvelope {
    /// Construct a typed message envelope
    pub fn new(
        msg_type: MessageType,
        from: &'static str,
        to: &'static str,
        data: &[u8],
        session_id: Option<&'static str>,
    ) -> Self {
        Self {
            from,
            to,
            message_type: msg_type,
            data: data.to_vec(),
            timestamp: crate::time::timestamp_millis(),
            session_id,
        }
    }

    pub fn is_control(&self) -> bool {
        matches!(self.message_type, MessageType::System | MessageType::Signal | MessageType::Error)
    }

    pub fn is_user(&self) -> bool {
        self.message_type == MessageType::User
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}
