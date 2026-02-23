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
pub enum UtilsError {
    VfsNotInitialized,
    InvalidPath,
    PathTooLong,
    PathTraversal,
    DirectoryNotFound,
    PermissionDenied,
    TooManyFiles,
    RecursionLimit,
    PatternInvalid,
    IoError,
}

impl UtilsError {
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::VfsNotInitialized => -5,
            Self::InvalidPath => -22,
            Self::PathTooLong => -36,
            Self::PathTraversal => -22,
            Self::DirectoryNotFound => -2,
            Self::PermissionDenied => -13,
            Self::TooManyFiles => -24,
            Self::RecursionLimit => -40,
            Self::PatternInvalid => -22,
            Self::IoError => -5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VfsNotInitialized => "VFS not initialized",
            Self::InvalidPath => "Invalid path",
            Self::PathTooLong => "Path too long",
            Self::PathTraversal => "Path traversal detected",
            Self::DirectoryNotFound => "Directory not found",
            Self::PermissionDenied => "Permission denied",
            Self::TooManyFiles => "Too many files",
            Self::RecursionLimit => "Recursion limit exceeded",
            Self::PatternInvalid => "Invalid pattern",
            Self::IoError => "I/O error",
        }
    }
}

impl From<UtilsError> for &'static str {
    fn from(err: UtilsError) -> Self {
        err.as_str()
    }
}

pub type UtilsResult<T> = Result<T, UtilsError>;
