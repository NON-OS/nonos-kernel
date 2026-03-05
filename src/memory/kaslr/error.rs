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

//! KASLR Error Types
//!
//! Error types for Kernel Address Space Layout Randomization.

use core::fmt;

/// Errors that can occur during KASLR operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KaslrError {
    /// KASLR not initialized
    NotInitialized,

    /// Invalid policy: min_slide >= max_slide
    InvalidPolicy,

    /// Invalid alignment granularity
    InvalidAlignment,

    /// KASLR range too small for alignment
    RangeTooSmall,

    /// Generated slide out of valid range
    SlideOutOfRange,

    /// Generated slide not properly aligned
    SlideNotAligned,

    /// Insufficient entropy for secure randomization
    InsufficientEntropy,

    /// Layout application failed
    LayoutApplyFailed,

    /// Slide integrity check failed
    IntegrityCheckFailed,

    /// RDRAND/RDSEED not available
    HardwareRngUnavailable,

    /// Key derivation failed
    KeyDerivationFailed,
}

impl KaslrError {
    /// Returns a human-readable description of the error
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "KASLR not initialized",
            Self::InvalidPolicy => "Invalid KASLR policy: min_slide >= max_slide",
            Self::InvalidAlignment => "Invalid alignment granularity",
            Self::RangeTooSmall => "KASLR range too small for alignment",
            Self::SlideOutOfRange => "Generated slide out of range",
            Self::SlideNotAligned => "Generated slide not properly aligned",
            Self::InsufficientEntropy => "Insufficient entropy for KASLR",
            Self::LayoutApplyFailed => "Failed to apply KASLR slide to layout",
            Self::IntegrityCheckFailed => "KASLR integrity check failed",
            Self::HardwareRngUnavailable => "Hardware RNG not available",
            Self::KeyDerivationFailed => "Key derivation failed",
        }
    }

    /// Returns true if this is a security-critical error
    pub fn is_security_critical(&self) -> bool {
        matches!(
            self,
            Self::InsufficientEntropy | Self::IntegrityCheckFailed | Self::SlideNotAligned
        )
    }
}

impl fmt::Display for KaslrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result type alias for KASLR operations
pub type KaslrResult<T> = Result<T, KaslrError>;

impl From<&'static str> for KaslrError {
    fn from(s: &'static str) -> Self {
        match s {
            "KASLR not initialized" => Self::NotInitialized,
            "Invalid KASLR policy: min_slide >= max_slide" => Self::InvalidPolicy,
            "Invalid alignment granularity" => Self::InvalidAlignment,
            "KASLR range too small for alignment" => Self::RangeTooSmall,
            "Generated slide out of range" => Self::SlideOutOfRange,
            "Generated slide not properly aligned" => Self::SlideNotAligned,
            "KASLR slide not page-aligned" => Self::SlideNotAligned,
            "KASLR slide out of safe range" => Self::SlideOutOfRange,
            _ => Self::NotInitialized,
        }
    }
}
