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
pub enum FsError {
    NotInitialized,
    NotFound,
    AlreadyExists,
    PathTooLong,
    InvalidPath,
    FileTooLarge,
    TooManyFiles,
    NoEncryptionKey,
    DataTooShort,
    DecryptionFailed,
    EncryptionFailed,
    DirectoryNotFound,
    NotADirectory,
    DirectoryNotEmpty,
    PermissionDenied,
    IoError(&'static str),
}

impl FsError {
    pub const fn to_errno(self) -> i32 {
        match self {
            FsError::NotInitialized => -5,
            FsError::NotFound => -2,
            FsError::AlreadyExists => -17,
            FsError::PathTooLong => -36,
            FsError::InvalidPath => -22,
            FsError::FileTooLarge => -27,
            FsError::TooManyFiles => -28,
            FsError::NoEncryptionKey => -5,
            FsError::DataTooShort => -5,
            FsError::DecryptionFailed => -5,
            FsError::EncryptionFailed => -5,
            FsError::DirectoryNotFound => -2,
            FsError::NotADirectory => -20,
            FsError::DirectoryNotEmpty => -39,
            FsError::PermissionDenied => -13,
            FsError::IoError(_) => -5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            FsError::NotInitialized => "Filesystem not initialized",
            FsError::NotFound => "File not found",
            FsError::AlreadyExists => "File already exists",
            FsError::PathTooLong => "Path too long",
            FsError::InvalidPath => "Invalid path",
            FsError::FileTooLarge => "File too large",
            FsError::TooManyFiles => "Too many files",
            FsError::NoEncryptionKey => "No encryption key found",
            FsError::DataTooShort => "Encrypted data too short",
            FsError::DecryptionFailed => "Decryption failed",
            FsError::EncryptionFailed => "Encryption failed",
            FsError::DirectoryNotFound => "Directory not found",
            FsError::NotADirectory => "Not a directory",
            FsError::DirectoryNotEmpty => "Directory not empty",
            FsError::PermissionDenied => "Permission denied",
            FsError::IoError(msg) => msg,
        }
    }
}

impl FsError {
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    pub fn len(&self) -> usize {
        self.as_str().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }
}

impl From<FsError> for &'static str {
    fn from(err: FsError) -> Self {
        err.as_str()
    }
}

pub type FsResult<T> = Result<T, FsError>;
