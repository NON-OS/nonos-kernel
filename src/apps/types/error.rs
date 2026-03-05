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

//! Application error types.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppError {
    NotFound,
    AlreadyRegistered,
    NotRunning,
    AlreadyRunning,
    PermissionDenied,
    InvalidState,
    NetworkRequired,
    CryptoRequired,
    ResourceExhausted,
    InitFailed,
    Timeout,
    Cancelled,
    Internal,
}

impl AppError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "Application not found",
            Self::AlreadyRegistered => "Application already registered",
            Self::NotRunning => "Application not running",
            Self::AlreadyRunning => "Application already running",
            Self::PermissionDenied => "Permission denied",
            Self::InvalidState => "Invalid application state",
            Self::NetworkRequired => "Network connectivity required",
            Self::CryptoRequired => "Cryptographic subsystem required",
            Self::ResourceExhausted => "Resources exhausted",
            Self::InitFailed => "Initialization failed",
            Self::Timeout => "Operation timed out",
            Self::Cancelled => "Operation cancelled",
            Self::Internal => "Internal error",
        }
    }
}

impl core::fmt::Display for AppError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type AppResult<T> = Result<T, AppError>;
