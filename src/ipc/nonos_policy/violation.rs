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

//! Policy violation types.

extern crate alloc;

use alloc::string::String;

use crate::ipc::nonos_message::SecurityLevel;
use super::capability::IpcCapability;

/// Policy violation types for audit logging
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    /// Message exceeds size limit
    MessageTooLarge { size: usize, limit: usize },
    /// Destination not allowed
    DestinationBlocked { from: String, to: String },
    /// Security level insufficient
    SecurityLevelInsufficient {
        required: SecurityLevel,
        actual: SecurityLevel,
    },
    /// Rate limit exceeded
    RateLimitExceeded { module: String, limit: u32 },
    /// Missing capability
    MissingCapability {
        module: String,
        capability: IpcCapability,
    },
    /// Invalid token
    InvalidToken { module: String, reason: &'static str },
    /// Channel creation denied
    ChannelCreationDenied { from: String, to: String },
}

impl core::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MessageTooLarge { size, limit } => {
                write!(f, "Message too large: {} bytes exceeds {} limit", size, limit)
            }
            Self::DestinationBlocked { from, to } => {
                write!(f, "Destination blocked: {} -> {}", from, to)
            }
            Self::SecurityLevelInsufficient { required, actual } => {
                write!(
                    f,
                    "Security level insufficient: required {:?}, got {:?}",
                    required, actual
                )
            }
            Self::RateLimitExceeded { module, limit } => {
                write!(f, "Rate limit exceeded: {} ({}/sec)", module, limit)
            }
            Self::MissingCapability { module, capability } => {
                write!(f, "Missing capability: {} needs {}", module, capability.name())
            }
            Self::InvalidToken { module, reason } => {
                write!(f, "Invalid token for {}: {}", module, reason)
            }
            Self::ChannelCreationDenied { from, to } => {
                write!(f, "Channel creation denied: {} -> {}", from, to)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_violation_display() {
        let v = PolicyViolation::MessageTooLarge {
            size: 100000,
            limit: 65536,
        };
        let msg = alloc::format!("{}", v);
        assert!(msg.contains("100000"));
        assert!(msg.contains("65536"));

        let v = PolicyViolation::MissingCapability {
            module: String::from("test"),
            capability: IpcCapability::KernelAccess,
        };
        let msg = alloc::format!("{}", v);
        assert!(msg.contains("test"));
        assert!(msg.contains("KernelAccess"));
    }
}
