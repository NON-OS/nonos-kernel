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
pub enum HardeningError {
    NotInitialized,
    WXViolation,
    GuardPageViolation,
    StackOverflow,
    HeapCorruption,
    DoubleFree,
    UseAfterFree,
    CanaryCorrupted,
    GuardPageNotFound,
    CanaryNotFound,
    MemoryNotMapped,
    InvalidPointer,
}

impl HardeningError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "Hardening not initialized",
            Self::WXViolation => "W^X violation: memory cannot be both writable and executable",
            Self::GuardPageViolation => "Guard page access detected",
            Self::StackOverflow => "Stack overflow detected",
            Self::HeapCorruption => "Heap corruption detected",
            Self::DoubleFree => "Double free detected",
            Self::UseAfterFree => "Use after free detected",
            Self::CanaryCorrupted => "Stack canary corrupted",
            Self::GuardPageNotFound => "Guard page not found",
            Self::CanaryNotFound => "Stack canary not found",
            Self::MemoryNotMapped => "Memory not mapped",
            Self::InvalidPointer => "Invalid pointer",
        }
    }
    pub const fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Self::WXViolation
                | Self::GuardPageViolation
                | Self::StackOverflow
                | Self::HeapCorruption
                | Self::DoubleFree
                | Self::UseAfterFree
                | Self::CanaryCorrupted
        )
    }
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::StackOverflow | Self::HeapCorruption | Self::CanaryCorrupted
        )
    }
    pub const fn is_memory_safety_issue(&self) -> bool {
        matches!(
            self,
            Self::DoubleFree | Self::UseAfterFree | Self::HeapCorruption
        )
    }
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
pub type HardeningResult<T> = Result<T, HardeningError>;
