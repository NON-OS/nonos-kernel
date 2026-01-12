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
pub enum ManifestError {
    EmptyName,
    NameTooLong,
    VersionTooLong,
    AuthorTooLong,
    DescriptionTooLong,
    TooManyCapabilities,
    InvalidPrivacyPolicy,
    HashMismatch,
    InvalidFormat,
}

impl ManifestError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyName => "Empty module name",
            Self::NameTooLong => "Module name too long",
            Self::VersionTooLong => "Version string too long",
            Self::AuthorTooLong => "Author string too long",
            Self::DescriptionTooLong => "Description too long",
            Self::TooManyCapabilities => "Too many capabilities",
            Self::InvalidPrivacyPolicy => "Invalid privacy policy",
            Self::HashMismatch => "Hash mismatch",
            Self::InvalidFormat => "Invalid manifest format",
        }
    }

    pub const fn to_errno(&self) -> i32 {
        match self {
            Self::EmptyName => -22,
            Self::NameTooLong => -36,
            Self::VersionTooLong => -36,
            Self::AuthorTooLong => -36,
            Self::DescriptionTooLong => -36,
            Self::TooManyCapabilities => -7,
            Self::InvalidPrivacyPolicy => -22,
            Self::HashMismatch => -5,
            Self::InvalidFormat => -22,
        }
    }
}

pub type ManifestResult<T> = Result<T, ManifestError>;
