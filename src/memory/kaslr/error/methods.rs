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

use super::types::KaslrError;

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
