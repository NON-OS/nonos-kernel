// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! IPC envelope structure.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use super::builder::EnvelopeBuilder;
use super::types::{MessageError, MessageType, SecurityLevel};

/// Maximum payload size (16 MB)
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// IPC message envelope
///
/// Contains the message payload along with routing and security metadata.
/// All messages in the IPC system are wrapped in envelopes.
#[derive(Debug, Clone)]
pub struct IpcEnvelope {
    /// Source module/process identifier
    pub from: String,
    /// Destination module/process identifier
    pub to: String,
    /// Message classification
    pub message_type: MessageType,
    /// Message payload
    pub data: Vec<u8>,
    /// Timestamp when message was created (milliseconds since boot)
    pub timestamp: u64,
    /// Optional session identifier for request/response correlation
    pub session_id: Option<u64>,
    /// Security level applied to this message
    pub sec_level: SecurityLevel,
}

impl IpcEnvelope {
    /// Create a new envelope with default settings
    pub fn new(from: &str, to: &str, message_type: MessageType, data: Vec<u8>) -> Self {
        Self {
            from: String::from(from),
            to: String::from(to),
            message_type,
            data,
            timestamp: crate::time::timestamp_millis(),
            session_id: None,
            sec_level: SecurityLevel::None,
        }
    }

    /// Create a builder for constructing envelopes
    pub fn builder(from: &str, to: &str) -> EnvelopeBuilder {
        EnvelopeBuilder::new(from, to)
    }

    /// Get payload length
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if payload is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get total envelope size (approximate)
    pub fn total_size(&self) -> usize {
        self.from.len() + self.to.len() + self.data.len() + 32 // overhead estimate
    }

    /// Validate the envelope
    pub fn validate(&self) -> Result<(), MessageError> {
        if self.from.is_empty() {
            return Err(MessageError::EmptySource);
        }
        if self.to.is_empty() {
            return Err(MessageError::EmptyDestination);
        }
        if self.data.len() > MAX_PAYLOAD_SIZE {
            return Err(MessageError::PayloadTooLarge {
                size: self.data.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        Ok(())
    }

    /// Check if message is valid
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Create a response envelope to this message
    pub fn create_response(&self, data: Vec<u8>) -> Self {
        Self {
            from: self.to.clone(),
            to: self.from.clone(),
            message_type: MessageType::Response,
            data,
            timestamp: crate::time::timestamp_millis(),
            session_id: self.session_id,
            sec_level: self.sec_level,
        }
    }

    /// Create an error response envelope
    pub fn create_error_response(&self, error_data: Vec<u8>) -> Self {
        Self {
            from: self.to.clone(),
            to: self.from.clone(),
            message_type: MessageType::Error,
            data: error_data,
            timestamp: crate::time::timestamp_millis(),
            session_id: self.session_id,
            sec_level: self.sec_level,
        }
    }

    /// Create an acknowledgment envelope
    pub fn create_ack(&self) -> Self {
        Self {
            from: self.to.clone(),
            to: self.from.clone(),
            message_type: MessageType::Ack,
            data: Vec::new(),
            timestamp: crate::time::timestamp_millis(),
            session_id: self.session_id,
            sec_level: SecurityLevel::None,
        }
    }

    /// Get message age in milliseconds
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp)
    }
}

impl Default for IpcEnvelope {
    fn default() -> Self {
        Self {
            from: String::new(),
            to: String::new(),
            message_type: MessageType::Data,
            data: Vec::new(),
            timestamp: 0,
            session_id: None,
            sec_level: SecurityLevel::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_new() {
        let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, alloc::vec![1, 2, 3]);
        assert_eq!(env.from, "sender");
        assert_eq!(env.to, "receiver");
        assert_eq!(env.data, alloc::vec![1, 2, 3]);
        assert_eq!(env.len(), 3);
        assert!(!env.is_empty());
    }

    #[test]
    fn test_envelope_validation() {
        let valid = IpcEnvelope::new("a", "b", MessageType::Data, alloc::vec![]);
        assert!(valid.validate().is_ok());

        let empty_from = IpcEnvelope::new("", "b", MessageType::Data, alloc::vec![]);
        assert!(matches!(
            empty_from.validate(),
            Err(MessageError::EmptySource)
        ));

        let empty_to = IpcEnvelope::new("a", "", MessageType::Data, alloc::vec![]);
        assert!(matches!(
            empty_to.validate(),
            Err(MessageError::EmptyDestination)
        ));
    }

    #[test]
    fn test_envelope_response() {
        let request = IpcEnvelope::builder("client", "server")
            .message_type(MessageType::Request)
            .session_id(42)
            .data(alloc::vec![1, 2, 3])
            .build();

        let response = request.create_response(alloc::vec![4, 5, 6]);
        assert_eq!(response.from, "server");
        assert_eq!(response.to, "client");
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.session_id, Some(42));
        assert_eq!(response.data, alloc::vec![4, 5, 6]);
    }

    #[test]
    fn test_envelope_ack() {
        let msg = IpcEnvelope::new("a", "b", MessageType::Data, alloc::vec![1, 2, 3]);
        let ack = msg.create_ack();
        assert_eq!(ack.from, "b");
        assert_eq!(ack.to, "a");
        assert_eq!(ack.message_type, MessageType::Ack);
        assert!(ack.is_empty());
    }
}
