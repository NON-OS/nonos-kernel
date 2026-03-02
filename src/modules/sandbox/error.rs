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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxError {
    ZeroMemoryLimit,
    MemoryLimitExceeded,
    AllocationFailed,
    SandboxNotFound,
    SandboxAlreadyExists,
    TooManySandboxes,
    CapabilityViolation,
    EraseFailed,
}

impl SandboxError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ZeroMemoryLimit => "Zero memory limit",
            Self::MemoryLimitExceeded => "Memory limit exceeded",
            Self::AllocationFailed => "Memory allocation failed",
            Self::SandboxNotFound => "Sandbox not found",
            Self::SandboxAlreadyExists => "Sandbox already exists",
            Self::TooManySandboxes => "Too many sandboxes",
            Self::CapabilityViolation => "Capability violation",
            Self::EraseFailed => "Secure erase failed",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::ZeroMemoryLimit => -22,
            Self::MemoryLimitExceeded => -12,
            Self::AllocationFailed => -12,
            Self::SandboxNotFound => -2,
            Self::SandboxAlreadyExists => -17,
            Self::TooManySandboxes => -12,
            Self::CapabilityViolation => -1,
            Self::EraseFailed => -5,
        }
    }
}

pub type SandboxResult<T> = Result<T, SandboxError>;
