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

//! IPC Manager error types.

/// IPC Manager errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcManagerError {
    /// Channel not found
    ChannelNotFound { channel_id: u64 },
    /// Sender not authorized for channel
    SenderNotAuthorized { sender_id: u64, channel_id: u64 },
    /// Recipient not authorized for channel
    RecipientNotAuthorized { recipient_id: u64, channel_id: u64 },
    /// Receiver not authorized for channel
    ReceiverNotAuthorized { receiver_id: u64, channel_id: u64 },
    /// Destroyer not authorized for channel
    DestroyerNotAuthorized { destroyer_id: u64, channel_id: u64 },
    /// Channel queue is full
    QueueFull { channel_id: u64, capacity: usize },
    /// No participants specified
    NoParticipants,
    /// Too many participants
    TooManyParticipants { count: usize, max: usize },
    /// Payload too large
    PayloadTooLarge { size: usize, max: usize },
    /// Channel ID collision (internal error)
    ChannelIdCollision { channel_id: u64 },
}

impl IpcManagerError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ChannelNotFound { .. } => "Channel not found",
            Self::SenderNotAuthorized { .. } => "Sender not authorized for channel",
            Self::RecipientNotAuthorized { .. } => "Recipient not authorized for channel",
            Self::ReceiverNotAuthorized { .. } => "Receiver not authorized for channel",
            Self::DestroyerNotAuthorized { .. } => "Destroyer not authorized for channel",
            Self::QueueFull { .. } => "Channel queue is full",
            Self::NoParticipants => "No participants specified",
            Self::TooManyParticipants { .. } => "Too many participants",
            Self::PayloadTooLarge { .. } => "Payload too large",
            Self::ChannelIdCollision { .. } => "Channel ID collision",
        }
    }
}

impl core::fmt::Display for IpcManagerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ChannelNotFound { channel_id } => {
                write!(f, "Channel {} not found", channel_id)
            }
            Self::SenderNotAuthorized { sender_id, channel_id } => {
                write!(f, "Sender {} not authorized for channel {}", sender_id, channel_id)
            }
            Self::RecipientNotAuthorized { recipient_id, channel_id } => {
                write!(f, "Recipient {} not authorized for channel {}", recipient_id, channel_id)
            }
            Self::ReceiverNotAuthorized { receiver_id, channel_id } => {
                write!(f, "Receiver {} not authorized for channel {}", receiver_id, channel_id)
            }
            Self::DestroyerNotAuthorized { destroyer_id, channel_id } => {
                write!(f, "Process {} not authorized to destroy channel {}", destroyer_id, channel_id)
            }
            Self::QueueFull { channel_id, capacity } => {
                write!(f, "Channel {} queue full (capacity: {})", channel_id, capacity)
            }
            Self::NoParticipants => write!(f, "No participants specified"),
            Self::TooManyParticipants { count, max } => {
                write!(f, "Too many participants: {} (max: {})", count, max)
            }
            Self::PayloadTooLarge { size, max } => {
                write!(f, "Payload too large: {} bytes (max: {})", size, max)
            }
            Self::ChannelIdCollision { channel_id } => {
                write!(f, "Channel ID {} collision", channel_id)
            }
        }
    }
}

/// Simple IPC error for syscall interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// Channel not found
    ChannelNotFound,
    /// Buffer full
    BufferFull,
    /// No message available (non-blocking)
    WouldBlock,
    /// Permission denied
    PermissionDenied,
    /// Too many channels
    TooManyChannels,
    /// Invalid argument
    InvalidArgument,
    /// I/O error
    IoError,
}

impl IpcError {
    /// Get error description
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ChannelNotFound => "Channel not found",
            Self::BufferFull => "Buffer full",
            Self::WouldBlock => "Would block",
            Self::PermissionDenied => "Permission denied",
            Self::TooManyChannels => "Too many channels",
            Self::InvalidArgument => "Invalid argument",
            Self::IoError => "I/O error",
        }
    }
}

impl core::fmt::Display for IpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<IpcManagerError> for IpcError {
    fn from(e: IpcManagerError) -> Self {
        match e {
            IpcManagerError::ChannelNotFound { .. } => Self::ChannelNotFound,
            IpcManagerError::QueueFull { .. } => Self::BufferFull,
            IpcManagerError::SenderNotAuthorized { .. }
            | IpcManagerError::RecipientNotAuthorized { .. }
            | IpcManagerError::ReceiverNotAuthorized { .. }
            | IpcManagerError::DestroyerNotAuthorized { .. } => Self::PermissionDenied,
            IpcManagerError::TooManyParticipants { .. } => Self::TooManyChannels,
            IpcManagerError::NoParticipants
            | IpcManagerError::PayloadTooLarge { .. } => Self::InvalidArgument,
            IpcManagerError::ChannelIdCollision { .. } => Self::IoError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = IpcManagerError::ChannelNotFound { channel_id: 42 };
        assert!(format!("{}", e).contains("42"));

        let e = IpcManagerError::PayloadTooLarge { size: 2000000, max: 1000000 };
        let msg = format!("{}", e);
        assert!(msg.contains("2000000"));
        assert!(msg.contains("1000000"));
    }
}
