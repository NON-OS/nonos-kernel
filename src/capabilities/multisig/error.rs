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
pub enum MultiSigError {
    NoSigners,
    TooManySigners { count: usize, max: usize },
    ThresholdExceedsSigners { threshold: usize, signers: usize },
    ZeroThreshold,
    DuplicateSigner { signer_id: u64 },
    UnauthorizedSigner { signer_id: u64 },
    ThresholdNotMet { have: usize, need: usize },
    TokenExpired,
    InvalidSignature { signer_id: u64 },
}

impl MultiSigError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoSigners => "No signers specified",
            Self::TooManySigners { .. } => "Too many signers",
            Self::ThresholdExceedsSigners { .. } => "Threshold exceeds signer count",
            Self::ZeroThreshold => "Threshold cannot be zero",
            Self::DuplicateSigner { .. } => "Signer already signed",
            Self::UnauthorizedSigner { .. } => "Signer not authorized",
            Self::ThresholdNotMet { .. } => "Insufficient signatures",
            Self::TokenExpired => "Token has expired",
            Self::InvalidSignature { .. } => "Invalid signature",
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::DuplicateSigner { .. } | Self::ThresholdNotMet { .. }
        )
    }
}

impl core::fmt::Display for MultiSigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSigners => write!(f, "No signers specified"),
            Self::TooManySigners { count, max } => {
                write!(f, "Too many signers: {} (max: {})", count, max)
            }
            Self::ThresholdExceedsSigners { threshold, signers } => {
                write!(f, "Threshold {} exceeds signer count {}", threshold, signers)
            }
            Self::ZeroThreshold => write!(f, "Threshold cannot be zero"),
            Self::DuplicateSigner { signer_id } => {
                write!(f, "Signer {} already signed", signer_id)
            }
            Self::UnauthorizedSigner { signer_id } => {
                write!(f, "Signer {} not authorized", signer_id)
            }
            Self::ThresholdNotMet { have, need } => {
                write!(f, "Have {} signatures, need {}", have, need)
            }
            Self::TokenExpired => write!(f, "Token has expired"),
            Self::InvalidSignature { signer_id } => {
                write!(f, "Invalid signature from signer {}", signer_id)
            }
        }
    }
}
