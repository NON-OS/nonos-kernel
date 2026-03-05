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

#[derive(Debug, Clone)]
pub enum NpkgError {
    PackageNotFound(String),
    VersionNotFound(String, String),
    DependencyConflict(String, String),
    DependencyMissing(String),
    CircularDependency(String),
    ChecksumMismatch(String),
    SignatureInvalid(String),
    SignatureKeyNotFound,
    DownloadFailed(String),
    NetworkUnavailable,
    RepositoryNotFound(String),
    RepositorySyncFailed(String),
    ManifestParseError(String),
    ArchiveCorrupt(String),
    ExtractionFailed(String),
    InstallationFailed(String),
    RemovalFailed(String),
    FileConflict(String, String),
    PermissionDenied(String),
    DiskFull,
    DatabaseCorrupt,
    DatabaseLocked,
    IoError(String),
    InternalError(String),
    InvalidPackageName(String),
    InvalidVersion(String),
    HookFailed(String),
    SandboxViolation(String),
    PackageOnHold(String),
    AlreadyInstalled(String),
    NotInstalled(String),
    UpgradeNotNeeded(String),
}

impl NpkgError {
    pub fn message(&self) -> String {
        match self {
            Self::PackageNotFound(name) => alloc::format!("package not found: {}", name),
            Self::VersionNotFound(name, ver) => alloc::format!("version {} not found for {}", ver, name),
            Self::DependencyConflict(a, b) => alloc::format!("conflict between {} and {}", a, b),
            Self::DependencyMissing(dep) => alloc::format!("missing dependency: {}", dep),
            Self::CircularDependency(chain) => alloc::format!("circular dependency: {}", chain),
            Self::ChecksumMismatch(pkg) => alloc::format!("checksum mismatch: {}", pkg),
            Self::SignatureInvalid(pkg) => alloc::format!("invalid signature: {}", pkg),
            Self::SignatureKeyNotFound => String::from("signing key not found"),
            Self::DownloadFailed(url) => alloc::format!("download failed: {}", url),
            Self::NetworkUnavailable => String::from("network unavailable"),
            Self::RepositoryNotFound(repo) => alloc::format!("repository not found: {}", repo),
            Self::RepositorySyncFailed(repo) => alloc::format!("sync failed: {}", repo),
            Self::ManifestParseError(msg) => alloc::format!("manifest error: {}", msg),
            Self::ArchiveCorrupt(pkg) => alloc::format!("corrupt archive: {}", pkg),
            Self::ExtractionFailed(msg) => alloc::format!("extraction failed: {}", msg),
            Self::InstallationFailed(msg) => alloc::format!("installation failed: {}", msg),
            Self::RemovalFailed(msg) => alloc::format!("removal failed: {}", msg),
            Self::FileConflict(file, owner) => alloc::format!("file {} owned by {}", file, owner),
            Self::PermissionDenied(path) => alloc::format!("permission denied: {}", path),
            Self::DiskFull => String::from("disk full"),
            Self::DatabaseCorrupt => String::from("package database corrupt"),
            Self::DatabaseLocked => String::from("package database locked"),
            Self::IoError(msg) => alloc::format!("I/O error: {}", msg),
            Self::InternalError(msg) => alloc::format!("internal error: {}", msg),
            Self::InvalidPackageName(name) => alloc::format!("invalid package name: {}", name),
            Self::InvalidVersion(ver) => alloc::format!("invalid version: {}", ver),
            Self::HookFailed(hook) => alloc::format!("hook failed: {}", hook),
            Self::SandboxViolation(msg) => alloc::format!("sandbox violation: {}", msg),
            Self::PackageOnHold(pkg) => alloc::format!("package on hold: {}", pkg),
            Self::AlreadyInstalled(pkg) => alloc::format!("already installed: {}", pkg),
            Self::NotInstalled(pkg) => alloc::format!("not installed: {}", pkg),
            Self::UpgradeNotNeeded(pkg) => alloc::format!("already up to date: {}", pkg),
        }
    }

    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::DatabaseCorrupt | Self::InternalError(_) => false,
            _ => true,
        }
    }
}

pub type NpkgResult<T> = Result<T, NpkgError>;
