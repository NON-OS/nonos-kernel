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

use crate::error::SignError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgId {
    Ed25519 = 0x01,
    MlDsa44 = 0x02,
    MlDsa65 = 0x03,
    MlDsa87 = 0x04,
}

impl AlgId {
    pub const fn pubkey_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    pub const fn sig_len(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa44 => "mldsa44",
            Self::MlDsa65 => "mldsa65",
            Self::MlDsa87 => "mldsa87",
        }
    }

    // Seed-file length for the algorithms with deterministic-from-seed
    // signing. For ml-dsa-65 the pqclean-clean implementation has no
    // seed-driven keygen; we store the full 4032-byte secret key as
    // the "seed" for sign().
    pub const fn seed_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    pub fn from_u8(b: u8) -> Result<Self, SignError> {
        Ok(match b {
            0x01 => Self::Ed25519,
            0x02 => Self::MlDsa44,
            0x03 => Self::MlDsa65,
            0x04 => Self::MlDsa87,
            other => return Err(SignError::UnknownAlgId(other)),
        })
    }
}

pub fn parse_alg(s: &str) -> Result<AlgId, SignError> {
    match s {
        "ed25519" => Ok(AlgId::Ed25519),
        "mldsa65" => Ok(AlgId::MlDsa65),
        other => Err(SignError::UnsupportedAlg(other.to_string())),
    }
}
