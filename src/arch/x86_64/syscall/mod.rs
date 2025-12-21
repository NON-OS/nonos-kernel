// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! NØNOS x86_64 System Call Module

pub mod nonos_syscall;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_syscall::SyscallError;

// ============================================================================
// Constants
// ============================================================================

pub use nonos_syscall::syscall_numbers;

// ============================================================================
// Type Aliases
// ============================================================================

pub use nonos_syscall::SyscallHandler;

// ============================================================================
// Core Types
// ============================================================================

pub use nonos_syscall::SyscallInfo;
pub use nonos_syscall::SyscallRecord;
pub use nonos_syscall::SecurityConfig;

// ============================================================================
// Statistics
// ============================================================================

pub use nonos_syscall::SyscallStats;

// ============================================================================
// Manager
// ============================================================================

pub use nonos_syscall::SyscallManager;

// ============================================================================
// Security
// ============================================================================

pub use nonos_syscall::security;

// ============================================================================
// Public API
// ============================================================================

/// Initialize syscall subsystem
#[inline]
pub fn init() -> Result<(), SyscallError> {
    nonos_syscall::init()
}

/// Check if syscall subsystem is initialized
#[inline]
pub fn is_initialized() -> bool {
    nonos_syscall::is_initialized()
}

/// Detect syscall hooks
#[inline]
pub fn detect_syscall_hooks() -> bool {
    nonos_syscall::detect_syscall_hooks()
}

/// Verify syscall table integrity
#[inline]
pub fn verify_syscall_table_integrity() -> bool {
    nonos_syscall::verify_syscall_table_integrity()
}

/// Get recent syscalls
#[inline]
pub fn get_recent_calls() -> alloc::vec::Vec<SyscallRecord> {
    nonos_syscall::get_recent_calls()
}

/// Get syscall statistics
#[inline]
pub fn get_syscall_stats() -> SyscallStats {
    nonos_syscall::get_syscall_stats()
}

/// Configure security settings
#[inline]
pub fn configure_security(config: SecurityConfig) {
    nonos_syscall::configure_security(config)
}
