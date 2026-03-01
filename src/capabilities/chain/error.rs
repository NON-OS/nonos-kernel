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
pub enum ChainError {
    EmptyChain,
    TooDeep { depth: usize, max: usize },
    InvalidToken { index: usize },
    ExpiredToken { index: usize },
    BrokenLink { index: usize },
    CapabilityNotFound,
}

impl ChainError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyChain => "Chain is empty",
            Self::TooDeep { .. } => "Chain exceeds maximum depth",
            Self::InvalidToken { .. } => "Token signature invalid",
            Self::ExpiredToken { .. } => "Token has expired",
            Self::BrokenLink { .. } => "Chain link broken",
            Self::CapabilityNotFound => "Capability not in chain",
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::ExpiredToken { .. } | Self::CapabilityNotFound)
    }

    pub fn failed_index(&self) -> Option<usize> {
        match self {
            Self::InvalidToken { index }
            | Self::ExpiredToken { index }
            | Self::BrokenLink { index } => Some(*index),
            _ => None,
        }
    }
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChain => write!(f, "Chain is empty"),
            Self::TooDeep { depth, max } => {
                write!(f, "Chain depth {} exceeds maximum {}", depth, max)
            }
            Self::InvalidToken { index } => {
                write!(f, "Token at index {} has invalid signature", index)
            }
            Self::ExpiredToken { index } => {
                write!(f, "Token at index {} has expired", index)
            }
            Self::BrokenLink { index } => {
                write!(f, "Chain link broken at index {}", index)
            }
            Self::CapabilityNotFound => write!(f, "Capability not found in chain"),
        }
    }
}
