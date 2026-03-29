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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    ImageTooSmall,
    FooterMagicInvalid,
    FooterVersionUnsupported,
    HashAlgorithmUnsupported,
    SignatureAlgorithmUnsupported,
    KernelOffsetOverflow,
    SignatureOffsetOverflow,
    ProofOffsetOverflow,
    KernelOutOfBounds,
    SignatureOutOfBounds,
    ProofOutOfBounds,
    TotalSizeMismatch,
    OverlappingRegions,
}

impl ParseError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ImageTooSmall => "image too small for footer",
            Self::FooterMagicInvalid => "invalid footer magic",
            Self::FooterVersionUnsupported => "unsupported footer version",
            Self::HashAlgorithmUnsupported => "unsupported hash algorithm",
            Self::SignatureAlgorithmUnsupported => "unsupported signature algorithm",
            Self::KernelOffsetOverflow => "kernel offset arithmetic overflow",
            Self::SignatureOffsetOverflow => "signature offset arithmetic overflow",
            Self::ProofOffsetOverflow => "proof offset arithmetic overflow",
            Self::KernelOutOfBounds => "kernel region out of bounds",
            Self::SignatureOutOfBounds => "signature region out of bounds",
            Self::ProofOutOfBounds => "proof region out of bounds",
            Self::TotalSizeMismatch => "total size does not match file size",
            Self::OverlappingRegions => "image regions overlap",
        }
    }
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
