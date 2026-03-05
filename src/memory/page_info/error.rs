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

//! Page Info Error Types
//!
//! Error types for page metadata operations.

use core::fmt;

/// Errors that can occur during page info operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageInfoError {
    /// Page not found in the tracking table
    PageNotFound,

    /// Page already exists in the tracking table
    PageAlreadyExists,

    /// Page info manager not initialized
    NotInitialized,

    /// Maximum tracked pages exceeded
    TooManyPages,

    /// Invalid page address
    InvalidAddress,

    /// Reference count underflow
    RefCountUnderflow,

    /// Page is locked and cannot be modified
    PageLocked,
}

impl PageInfoError {
    /// Returns a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PageNotFound => "Page not found",
            Self::PageAlreadyExists => "Page already exists",
            Self::NotInitialized => "Page info manager not initialized",
            Self::TooManyPages => "Maximum tracked pages exceeded",
            Self::InvalidAddress => "Invalid page address",
            Self::RefCountUnderflow => "Reference count underflow",
            Self::PageLocked => "Page is locked",
        }
    }

    /// Returns true if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::PageNotFound | Self::PageAlreadyExists)
    }
}

impl fmt::Display for PageInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type alias for page info operations
pub type PageInfoResult<T> = Result<T, PageInfoError>;

impl From<&'static str> for PageInfoError {
    fn from(s: &'static str) -> Self {
        match s {
            "Page not found" => Self::PageNotFound,
            _ => Self::InvalidAddress,
        }
    }
}
