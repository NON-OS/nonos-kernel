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

//! RNG error types.

/// Errors that can occur during RNG operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// RNG has not been initialized.
    NotInitialized,
    /// RNG is already initialized.
    AlreadyInitialized,
    /// Hardware entropy source (RDRAND/RDSEED) failed after retries.
    HardwareEntropyFailed,
    /// Insufficient entropy collected for seeding.
    InsufficientEntropy,
    /// Failed to acquire RNG lock.
    LockFailed,
    /// No adequate entropy source available (hardware or bootloader).
    EntropyUnavailable,
}

impl RngError {
    /// Returns a human-readable description of the error.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "RNG has not been initialized",
            Self::AlreadyInitialized => "RNG is already initialized",
            Self::HardwareEntropyFailed => "Hardware entropy source failed after retries",
            Self::InsufficientEntropy => "Insufficient entropy collected for seeding",
            Self::LockFailed => "Failed to acquire RNG lock",
            Self::EntropyUnavailable => "No adequate entropy source available",
        }
    }
}

/// Result type for RNG operations.
pub type RngResult<T> = Result<T, RngError>;
