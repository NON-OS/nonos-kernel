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

use alloc::string::String;
use core::fmt;

#[derive(Clone, Debug)]
pub enum NoxError {
    NotInitialized,
    FormulaNotFound(String),
    TapNotFound(String),
    TapAlreadyExists(String),
    DownloadFailed(String),
    ChecksumMismatch { expected: String, actual: String },
    InstallFailed(String),
    RemoveFailed(String),
    BuildFailed(String),
    DependencyConflict(String),
    CircularDependency(String),
    GitHubApiError(String),
    GitHubRateLimit,
    NetworkError(String),
    IoError(String),
    ParseError(String),
    PermissionDenied,
    AlreadyInstalled(String),
    NotInstalled(String),
    InvalidFormula(String),
    UnsupportedArchitecture,
    CacheError(String),
    LockFailed,
    Interrupted,
}

impl fmt::Display for NoxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "nox not initialized"),
            Self::FormulaNotFound(n) => write!(f, "formula not found: {}", n),
            Self::TapNotFound(n) => write!(f, "tap not found: {}", n),
            Self::TapAlreadyExists(n) => write!(f, "tap already exists: {}", n),
            Self::DownloadFailed(u) => write!(f, "download failed: {}", u),
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "checksum mismatch: expected {}, got {}", expected, actual)
            }
            Self::InstallFailed(r) => write!(f, "install failed: {}", r),
            Self::RemoveFailed(r) => write!(f, "remove failed: {}", r),
            Self::BuildFailed(r) => write!(f, "build failed: {}", r),
            Self::DependencyConflict(d) => write!(f, "dependency conflict: {}", d),
            Self::CircularDependency(d) => write!(f, "circular dependency: {}", d),
            Self::GitHubApiError(e) => write!(f, "GitHub API error: {}", e),
            Self::GitHubRateLimit => write!(f, "GitHub API rate limit exceeded"),
            Self::NetworkError(e) => write!(f, "network error: {}", e),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::ParseError(e) => write!(f, "parse error: {}", e),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::AlreadyInstalled(n) => write!(f, "{} is already installed", n),
            Self::NotInstalled(n) => write!(f, "{} is not installed", n),
            Self::InvalidFormula(r) => write!(f, "invalid formula: {}", r),
            Self::UnsupportedArchitecture => write!(f, "unsupported architecture"),
            Self::CacheError(e) => write!(f, "cache error: {}", e),
            Self::LockFailed => write!(f, "failed to acquire lock"),
            Self::Interrupted => write!(f, "operation interrupted"),
        }
    }
}
