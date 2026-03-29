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

use crate::image_format::parse::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageValidationError {
    ParseError(ParseError),
    KernelTooSmall,
    KernelNotElf,
    SignatureSizeMismatch,
    SignatureAllZeros,
    ProofTooSmall,
    ProofMagicInvalid,
    HashAlgorithmMismatch,
    SignatureAlgorithmMismatch,
}

impl From<ParseError> for ImageValidationError {
    fn from(e: ParseError) -> Self {
        Self::ParseError(e)
    }
}

impl ImageValidationError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ParseError(_) => "image parse error",
            Self::KernelTooSmall => "kernel payload too small",
            Self::KernelNotElf => "kernel is not valid ELF",
            Self::SignatureSizeMismatch => "signature size mismatch",
            Self::SignatureAllZeros => "signature is all zeros",
            Self::ProofTooSmall => "ZK proof too small",
            Self::ProofMagicInvalid => "ZK proof magic invalid",
            Self::HashAlgorithmMismatch => "hash algorithm mismatch",
            Self::SignatureAlgorithmMismatch => "signature algorithm mismatch",
        }
    }
}

impl core::fmt::Display for ImageValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ParseError(e) => write!(f, "parse error: {}", e),
            _ => write!(f, "{}", self.as_str()),
        }
    }
}
