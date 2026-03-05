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

//! Policy error types.

extern crate alloc;

use alloc::string::String;

use super::violation::PolicyViolation;

/// Policy engine errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Policy engine not initialized
    NotInitialized,
    /// Module not registered
    ModuleNotFound { name: String },
    /// Invalid capability token
    InvalidToken { reason: &'static str },
    /// Policy violation occurred
    Violation(PolicyViolation),
}

impl PolicyError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Policy engine not initialized",
            Self::ModuleNotFound { .. } => "Module not found",
            Self::InvalidToken { .. } => "Invalid capability token",
            Self::Violation(_) => "Policy violation",
        }
    }
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "Policy engine not initialized"),
            Self::ModuleNotFound { name } => write!(f, "Module not found: {}", name),
            Self::InvalidToken { reason } => write!(f, "Invalid token: {}", reason),
            Self::Violation(v) => write!(f, "Policy violation: {}", v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_error_display() {
        let e = PolicyError::ModuleNotFound {
            name: String::from("foo"),
        };
        let msg = alloc::format!("{}", e);
        assert!(msg.contains("foo"));

        let e = PolicyError::InvalidToken {
            reason: "expired",
        };
        let msg = alloc::format!("{}", e);
        assert!(msg.contains("expired"));
    }
}
