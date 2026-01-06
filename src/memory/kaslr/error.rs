// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KaslrError {
    NotInitialized,
    InvalidPolicy, /// Invalid policy: min_slide >= max_slide
    InvalidAlignment,
    RangeTooSmall,
    SlideOutOfRange,
    SlideNotAligned,
    InsufficientEntropy,
    LayoutApplyFailed,
    IntegrityCheckFailed,
    HardwareRngUnavailable,
    KeyDerivationFailed,
}

impl KaslrError {
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
