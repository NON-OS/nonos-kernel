// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors 
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
//
//! IPC Message Types
//! Core message structures for inter-process communication:
//! `IpcEnvelope` - Message container with routing and security metadata
//! `MessageType` - Message classification (data, control, error, etc.)
//! `SecurityLevel` - Message security/signing requirements

extern crate alloc;

use alloc::{string::String, vec::Vec};

// ============================================================================
// Security Level
// ============================================================================

/// Message security level
///
/// Determines the cryptographic protection applied to a message.
/// Higher levels require more processing but provide stronger guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    /// No cryptographic protection
    None = 0,
    /// Message is signed (integrity + authenticity)
    Signed = 1,
    /// Message is encrypted (confidentiality + integrity + authenticity)
    Encrypted = 2,
}

impl SecurityLevel {
    /// Get the security level name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Signed => "Signed",
            Self::Encrypted => "Encrypted",
        }
    }

    /// Check if this level provides at least the required protection
    #[inline]
    pub fn meets_requirement(&self, required: SecurityLevel) -> bool {
        (*self as u8) >= (required as u8)
    }

    /// Check if message is cryptographically protected
    #[inline]
    pub fn is_protected(&self) -> bool {
        *self != Self::None
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::None
    }
}

impl core::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Message Type
// ============================================================================

/// IPC message classification
///
/// Determines how the message should be processed by the receiving module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MessageType {
    /// Regular data payload
    Data = 0,
    /// Control/management message
    Control = 1,
    /// Timeout notification
    Timeout = 2,
    /// Delivery failure notification
    DeliveryFailure = 3,
    /// Capability validation result
    CapabilityResult = 4,
    /// Error notification
    Error = 5,
    /// Acknowledgment
    Ack = 6,
    /// Request (expects response)
    Request = 7,
    /// Response to a request
    Response = 8,
}

impl MessageType {
    /// Get the message type name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "Data",
            Self::Control => "Control",
            Self::Timeout => "Timeout",
            Self::DeliveryFailure => "DeliveryFailure",
            Self::CapabilityResult => "CapabilityResult",
            Self::Error => "Error",
            Self::Ack => "Ack",
            Self::Request => "Request",
            Self::Response => "Response",
        }
    }

    /// Check if this is a notification type (no response expected)
    #[inline]
    pub fn is_notification(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::DeliveryFailure | Self::Error | Self::Ack
        )
    }

    /// Check if this is an error/failure type
    #[inline]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error | Self::DeliveryFailure | Self::Timeout)
    }

    /// Check if this expects a response
    #[inline]
    pub fn expects_response(&self) -> bool {
        matches!(self, Self::Request)
    }
}

impl Default for MessageType {
    fn default() -> Self {
        Self::Data
    }
}

impl core::fmt::Display for MessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Message Error
// ============================================================================

/// Message validation/creation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// Source address is empty
    EmptySource,
    /// Destination address is empty
    EmptyDestination,
    /// Payload exceeds maximum size
    PayloadTooLarge { size: usize, max: usize },
    /// Invalid session ID
    InvalidSessionId,
    /// Security level mismatch
    SecurityLevelMismatch { required: SecurityLevel, actual: SecurityLevel },
}

impl MessageError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptySource => "Source address is empty",
            Self::EmptyDestination => "Destination address is empty",
            Self::PayloadTooLarge { .. } => "Payload exceeds maximum size",
            Self::InvalidSessionId => "Invalid session ID",
            Self::SecurityLevelMismatch { .. } => "Security level mismatch",
        }
    }
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptySource => write!(f, "Source address is empty"),
            Self::EmptyDestination => write!(f, "Destination address is empty"),
            Self::PayloadTooLarge { size, max } => {
                write!(f, "Payload too large: {} bytes (max: {})", size, max)
            }
            Self::InvalidSessionId => write!(f, "Invalid session ID"),
            Self::SecurityLevelMismatch { required, actual } => {
                write!(f, "Security level mismatch: required {}, got {}", required, actual)
            }
        }
    }
}

// ============================================================================
// IPC Envelope
// ============================================================================

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

// ============================================================================
// Envelope Builder
// ============================================================================

/// Builder for constructing IPC envelopes
pub struct EnvelopeBuilder {
    from: String,
    to: String,
    message_type: MessageType,
    data: Vec<u8>,
    session_id: Option<u64>,
    sec_level: SecurityLevel,
}

impl EnvelopeBuilder {
    /// Create a new builder
    pub fn new(from: &str, to: &str) -> Self {
        Self {
            from: String::from(from),
            to: String::from(to),
            message_type: MessageType::Data,
            data: Vec::new(),
            session_id: None,
            sec_level: SecurityLevel::None,
        }
    }

    /// Set message type
    pub fn message_type(mut self, msg_type: MessageType) -> Self {
        self.message_type = msg_type;
        self
    }

    /// Set payload data
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set payload from bytes
    pub fn data_from_slice(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Set session ID
    pub fn session_id(mut self, id: u64) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.sec_level = level;
        self
    }

    /// Build the envelope
    pub fn build(self) -> IpcEnvelope {
        IpcEnvelope {
            from: self.from,
            to: self.to,
            message_type: self.message_type,
            data: self.data,
            timestamp: crate::time::timestamp_millis(),
            session_id: self.session_id,
            sec_level: self.sec_level,
        }
    }

    /// Build and validate the envelope
    pub fn build_validated(self) -> Result<IpcEnvelope, MessageError> {
        let envelope = self.build();
        envelope.validate()?;
        Ok(envelope)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_ordering() {
        assert!(SecurityLevel::Encrypted > SecurityLevel::Signed);
        assert!(SecurityLevel::Signed > SecurityLevel::None);
        assert!(SecurityLevel::Encrypted.meets_requirement(SecurityLevel::Signed));
        assert!(SecurityLevel::Signed.meets_requirement(SecurityLevel::None));
        assert!(!SecurityLevel::None.meets_requirement(SecurityLevel::Signed));
    }

    #[test]
    fn test_security_level_display() {
        assert_eq!(format!("{}", SecurityLevel::None), "None");
        assert_eq!(format!("{}", SecurityLevel::Signed), "Signed");
        assert_eq!(format!("{}", SecurityLevel::Encrypted), "Encrypted");
    }

    #[test]
    fn test_security_level_protected() {
        assert!(!SecurityLevel::None.is_protected());
        assert!(SecurityLevel::Signed.is_protected());
        assert!(SecurityLevel::Encrypted.is_protected());
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", MessageType::Data), "Data");
        assert_eq!(format!("{}", MessageType::Error), "Error");
        assert_eq!(format!("{}", MessageType::Request), "Request");
    }

    #[test]
    fn test_message_type_classification() {
        assert!(MessageType::Error.is_error());
        assert!(MessageType::Timeout.is_error());
        assert!(!MessageType::Data.is_error());

        assert!(MessageType::Request.expects_response());
        assert!(!MessageType::Data.expects_response());

        assert!(MessageType::Ack.is_notification());
        assert!(!MessageType::Request.is_notification());
    }

    #[test]
    fn test_envelope_new() {
        let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
        assert_eq!(env.from, "sender");
        assert_eq!(env.to, "receiver");
        assert_eq!(env.data, vec![1, 2, 3]);
        assert_eq!(env.len(), 3);
        assert!(!env.is_empty());
    }

    #[test]
    fn test_envelope_builder() {
        let env = IpcEnvelope::builder("a", "b")
            .message_type(MessageType::Request)
            .data(vec![42])
            .session_id(123)
            .security_level(SecurityLevel::Signed)
            .build();

        assert_eq!(env.from, "a");
        assert_eq!(env.to, "b");
        assert_eq!(env.message_type, MessageType::Request);
        assert_eq!(env.data, vec![42]);
        assert_eq!(env.session_id, Some(123));
        assert_eq!(env.sec_level, SecurityLevel::Signed);
    }

    #[test]
    fn test_envelope_validation() {
        let valid = IpcEnvelope::new("a", "b", MessageType::Data, vec![]);
        assert!(valid.validate().is_ok());

        let empty_from = IpcEnvelope::new("", "b", MessageType::Data, vec![]);
        assert!(matches!(
            empty_from.validate(),
            Err(MessageError::EmptySource)
        ));

        let empty_to = IpcEnvelope::new("a", "", MessageType::Data, vec![]);
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
            .data(vec![1, 2, 3])
            .build();

        let response = request.create_response(vec![4, 5, 6]);
        assert_eq!(response.from, "server");
        assert_eq!(response.to, "client");
        assert_eq!(response.message_type, MessageType::Response);
        assert_eq!(response.session_id, Some(42));
        assert_eq!(response.data, vec![4, 5, 6]);
    }

    #[test]
    fn test_envelope_ack() {
        let msg = IpcEnvelope::new("a", "b", MessageType::Data, vec![1, 2, 3]);
        let ack = msg.create_ack();
        assert_eq!(ack.from, "b");
        assert_eq!(ack.to, "a");
        assert_eq!(ack.message_type, MessageType::Ack);
        assert!(ack.is_empty());
    }

    #[test]
    fn test_message_error_display() {
        let e = MessageError::EmptySource;
        assert!(format!("{}", e).contains("empty"));

        let e = MessageError::PayloadTooLarge { size: 100, max: 50 };
        let msg = format!("{}", e);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }
}
