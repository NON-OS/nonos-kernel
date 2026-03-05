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

//! Security level and message type definitions.

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
    fn test_message_error_display() {
        let e = MessageError::EmptySource;
        assert!(format!("{}", e).contains("empty"));

        let e = MessageError::PayloadTooLarge { size: 100, max: 50 };
        let msg = format!("{}", e);
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }
}
