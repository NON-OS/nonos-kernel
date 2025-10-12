#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    None,
    Signed,
    Encrypted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Data,
    Control,
    Timeout,
    DeliveryFailure,
    CapabilityResult,
    Error,
}

#[derive(Debug, Clone)]
pub struct IpcEnvelope {
    pub from: String,
    pub to: String,
    pub message_type: MessageType,
    pub data: Vec<u8>,
    pub timestamp: u64,
    pub session_id: Option<u64>,
    pub sec_level: SecurityLevel,
}

impl IpcEnvelope {
    pub fn new(from: &str, to: &str, message_type: MessageType, data: Vec<u8>) -> Self {
        Self {
            from: alloc::string::String::from(from),
            to: alloc::string::String::from(to),
            message_type,
            data,
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: SecurityLevel::None,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }
}
