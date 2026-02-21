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
pub enum PathError {
    NullPointer,
    TooLong,
    InvalidUtf8,
    Empty,
    ContainsNull,
    ComponentTooLong,
    InvalidCharacter,
    TraversalAttempt,
    NotAbsolute,
    NotRelative,
}

impl PathError {
    pub const fn to_errno(self) -> i32 {
        match self {
            PathError::NullPointer => -14,        // EFAULT
            PathError::TooLong => -36,            // ENAMETOOLONG
            PathError::InvalidUtf8 => -22,        // EINVAL
            PathError::Empty => -22,              // EINVAL
            PathError::ContainsNull => -22,       // EINVAL
            PathError::ComponentTooLong => -36,   // ENAMETOOLONG
            PathError::InvalidCharacter => -22,   // EINVAL
            PathError::TraversalAttempt => -1,    // EPERM
            PathError::NotAbsolute => -22,        // EINVAL
            PathError::NotRelative => -22,        // EINVAL
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            PathError::NullPointer => "Null pointer",
            PathError::TooLong => "Path too long",
            PathError::InvalidUtf8 => "Invalid UTF-8 in path",
            PathError::Empty => "Empty path",
            PathError::ContainsNull => "Path contains null byte",
            PathError::ComponentTooLong => "Path component too long",
            PathError::InvalidCharacter => "Invalid character in path",
            PathError::TraversalAttempt => "Path traversal attempt",
            PathError::NotAbsolute => "Path is not absolute",
            PathError::NotRelative => "Path is not relative",
        }
    }
}

impl From<PathError> for &'static str {
    fn from(err: PathError) -> Self {
        err.as_str()
    }
}

pub type PathResult<T> = Result<T, PathError>;
