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

//! Channel and message type definitions.

extern crate alloc;

use alloc::vec::Vec;

/// Channel communication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NonosChannelType {
    /// Shared memory region
    SharedMemory = 0x1000,
    /// Message passing queue
    MessagePassing = 0x2000,
    /// Signal delivery
    Signal = 0x3000,
    /// Pipe (unidirectional)
    Pipe = 0x4000,
    /// Socket-like bidirectional
    Socket = 0x5000,
}

impl NonosChannelType {
    /// Get channel type name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SharedMemory => "SharedMemory",
            Self::MessagePassing => "MessagePassing",
            Self::Signal => "Signal",
            Self::Pipe => "Pipe",
            Self::Socket => "Socket",
        }
    }

    /// Check if channel type supports bidirectional communication
    #[inline]
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, Self::SharedMemory | Self::MessagePassing | Self::Socket)
    }
}

impl Default for NonosChannelType {
    fn default() -> Self {
        Self::MessagePassing
    }
}

impl core::fmt::Display for NonosChannelType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Message classification for priority handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NonosMessageType {
    /// Regular data payload
    Data = 0x1000,
    /// Control/management message
    Control = 0x2000,
    /// Synchronization primitive
    Synchronization = 0x3000,
    /// Signal delivery
    Signal = 0x4000,
    /// Error notification
    Error = 0x5000,
}

impl NonosMessageType {
    /// Get message type name
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Data => "Data",
            Self::Control => "Control",
            Self::Synchronization => "Synchronization",
            Self::Signal => "Signal",
            Self::Error => "Error",
        }
    }

    /// Get priority for this message type (higher = more urgent)
    pub const fn priority(&self) -> u8 {
        match self {
            Self::Control => 255,
            Self::Signal => 200,
            Self::Error => 180,
            Self::Synchronization => 150,
            Self::Data => 100,
        }
    }

    /// Check if this is a high-priority message type
    #[inline]
    pub fn is_high_priority(&self) -> bool {
        self.priority() >= 150
    }
}

impl Default for NonosMessageType {
    fn default() -> Self {
        Self::Data
    }
}

impl core::fmt::Display for NonosMessageType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// IPC message structure
#[derive(Debug, Clone)]
pub struct NonosIPCMessage {
    /// Unique message identifier
    pub message_id: u64,
    /// Sender process ID
    pub sender_id: u64,
    /// Recipient process ID
    pub recipient_id: u64,
    /// Message classification
    pub message_type: NonosMessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Creation timestamp (milliseconds since boot)
    pub timestamp_ms: u64,
    /// Message priority (derived from type)
    pub priority: u8,
}

impl NonosIPCMessage {
    /// Get payload length
    #[inline]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Check if payload is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    /// Get message age in milliseconds
    pub fn age_ms(&self) -> u64 {
        crate::time::timestamp_millis().saturating_sub(self.timestamp_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_type_display() {
        assert_eq!(format!("{}", NonosChannelType::MessagePassing), "MessagePassing");
        assert_eq!(format!("{}", NonosChannelType::Pipe), "Pipe");
    }

    #[test]
    fn test_channel_type_bidirectional() {
        assert!(NonosChannelType::MessagePassing.is_bidirectional());
        assert!(NonosChannelType::Socket.is_bidirectional());
        assert!(!NonosChannelType::Pipe.is_bidirectional());
        assert!(!NonosChannelType::Signal.is_bidirectional());
    }

    #[test]
    fn test_message_type_priority() {
        assert!(NonosMessageType::Control.priority() > NonosMessageType::Data.priority());
        assert!(NonosMessageType::Signal.priority() > NonosMessageType::Data.priority());
        assert!(NonosMessageType::Control.is_high_priority());
        assert!(!NonosMessageType::Data.is_high_priority());
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(format!("{}", NonosMessageType::Data), "Data");
        assert_eq!(format!("{}", NonosMessageType::Control), "Control");
    }

    #[test]
    fn test_message_helpers() {
        let msg = NonosIPCMessage {
            message_id: 1,
            sender_id: 10,
            recipient_id: 20,
            message_type: NonosMessageType::Data,
            payload: alloc::vec![1, 2, 3, 4, 5],
            timestamp_ms: 0,
            priority: 100,
        };

        assert_eq!(msg.len(), 5);
        assert!(!msg.is_empty());
    }
}
