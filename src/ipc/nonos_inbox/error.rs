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

//! Inbox error types.

extern crate alloc;

use alloc::string::String;

/// Inbox operation errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboxError {
    /// Inbox not found for the specified module
    NotFound { module: String },
    /// Inbox is full, cannot enqueue
    Full { module: String, capacity: usize },
    /// Enqueue operation timed out
    Timeout { module: String, waited_ms: u64 },
    /// Invalid capacity value
    InvalidCapacity { value: usize, min: usize, max: usize },
    /// Module name is empty
    EmptyModuleName,
}

impl InboxError {
    /// Get a short description of the error
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "Inbox not found",
            Self::Full { .. } => "Inbox full",
            Self::Timeout { .. } => "Enqueue timeout",
            Self::InvalidCapacity { .. } => "Invalid capacity",
            Self::EmptyModuleName => "Empty module name",
        }
    }
}

impl core::fmt::Display for InboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound { module } => {
                write!(f, "Inbox not found for module '{}'", module)
            }
            Self::Full { module, capacity } => {
                write!(f, "Inbox full for module '{}' (capacity: {})", module, capacity)
            }
            Self::Timeout { module, waited_ms } => {
                write!(f, "Enqueue timeout for module '{}' after {}ms", module, waited_ms)
            }
            Self::InvalidCapacity { value, min, max } => {
                write!(f, "Invalid capacity {}: must be between {} and {}", value, min, max)
            }
            Self::EmptyModuleName => write!(f, "Module name cannot be empty"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbox_error_display() {
        let e = InboxError::NotFound {
            module: "test".into(),
        };
        assert!(format!("{}", e).contains("test"));

        let e = InboxError::Full {
            module: "mod1".into(),
            capacity: 100,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("mod1"));
        assert!(msg.contains("100"));

        let e = InboxError::Timeout {
            module: "mod2".into(),
            waited_ms: 500,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("mod2"));
        assert!(msg.contains("500"));

        let e = InboxError::InvalidCapacity {
            value: 5,
            min: 16,
            max: 65536,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("5"));
        assert!(msg.contains("16"));

        let e = InboxError::EmptyModuleName;
        assert!(format!("{}", e).contains("empty"));
    }
}
