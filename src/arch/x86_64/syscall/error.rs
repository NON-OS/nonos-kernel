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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallError {
    NotInitialized,
    AlreadyInitialized,
    InvalidSyscallNumber { number: u64 },
    HandlerNotFound { number: u64 },
    InvalidUserPointer { address: u64 },
    PermissionDenied { syscall: u64, reason: &'static str },
    RateLimitExceeded { syscall: u64 },
    InvalidPath { address: u64 },
    NoProcessContext,
    BadFileDescriptor { fd: u64 },
    SecurityViolation { reason: &'static str },
    IntegrityViolation,
    MsrAccessFailed { msr: u32 },
    InvalidSelector { selector: u16 },
    BlockedByPolicy { syscall: u64 },
    InternalError { message: &'static str },
}

impl SyscallError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SyscallError::NotInitialized => "Syscall subsystem not initialized",
            SyscallError::AlreadyInitialized => "Syscall subsystem already initialized",
            SyscallError::InvalidSyscallNumber { .. } => "Invalid syscall number",
            SyscallError::HandlerNotFound { .. } => "Syscall handler not found",
            SyscallError::InvalidUserPointer { .. } => "Invalid user pointer address",
            SyscallError::PermissionDenied { .. } => "Permission denied for syscall",
            SyscallError::RateLimitExceeded { .. } => "Rate limit exceeded for syscall",
            SyscallError::InvalidPath { .. } => "Invalid path pointer",
            SyscallError::NoProcessContext => "No process context available",
            SyscallError::BadFileDescriptor { .. } => "Bad file descriptor",
            SyscallError::SecurityViolation { .. } => "Security policy violation",
            SyscallError::IntegrityViolation => "Syscall table integrity violation detected",
            SyscallError::MsrAccessFailed { .. } => "MSR access failed",
            SyscallError::InvalidSelector { .. } => "Invalid segment selector",
            SyscallError::BlockedByPolicy { .. } => "Syscall blocked by security policy",
            SyscallError::InternalError { .. } => "Internal syscall error",
        }
    }

    pub const fn to_errno(&self) -> i64 {
        match self {
            SyscallError::NotInitialized => -1,
            SyscallError::AlreadyInitialized => -1,
            SyscallError::InvalidSyscallNumber { .. } => -38,
            SyscallError::HandlerNotFound { .. } => -38,
            SyscallError::InvalidUserPointer { .. } => -14,
            SyscallError::PermissionDenied { .. } => -1,
            SyscallError::RateLimitExceeded { .. } => -11,
            SyscallError::InvalidPath { .. } => -14,
            SyscallError::NoProcessContext => -3,
            SyscallError::BadFileDescriptor { .. } => -9,
            SyscallError::SecurityViolation { .. } => -1,
            SyscallError::IntegrityViolation => -1,
            SyscallError::MsrAccessFailed { .. } => -5,
            SyscallError::InvalidSelector { .. } => -22,
            SyscallError::BlockedByPolicy { .. } => -1,
            SyscallError::InternalError { .. } => -5,
        }
    }
}

impl core::fmt::Display for SyscallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "Syscall subsystem not initialized"),
            Self::AlreadyInitialized => write!(f, "Syscall subsystem already initialized"),
            Self::InvalidSyscallNumber { number } => write!(f, "Invalid syscall number: {}", number),
            Self::HandlerNotFound { number } => write!(f, "Handler not found for: {}", number),
            Self::InvalidUserPointer { address } => write!(f, "Invalid pointer: 0x{:016X}", address),
            Self::PermissionDenied { syscall, reason } => write!(f, "Permission denied for {}: {}", syscall, reason),
            Self::RateLimitExceeded { syscall } => write!(f, "Rate limit exceeded for {}", syscall),
            Self::InvalidPath { address } => write!(f, "Invalid path: 0x{:016X}", address),
            Self::NoProcessContext => write!(f, "No process context available"),
            Self::BadFileDescriptor { fd } => write!(f, "Bad file descriptor: {}", fd),
            Self::SecurityViolation { reason } => write!(f, "Security violation: {}", reason),
            Self::IntegrityViolation => write!(f, "Syscall table integrity violation"),
            Self::MsrAccessFailed { msr } => write!(f, "MSR access failed: 0x{:08X}", msr),
            Self::InvalidSelector { selector } => write!(f, "Invalid selector: 0x{:04X}", selector),
            Self::BlockedByPolicy { syscall } => write!(f, "Syscall {} blocked by policy", syscall),
            Self::InternalError { message } => write!(f, "Internal error: {}", message),
        }
    }
}
