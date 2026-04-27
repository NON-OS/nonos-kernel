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
use core::fmt;

impl fmt::Display for KaslrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
