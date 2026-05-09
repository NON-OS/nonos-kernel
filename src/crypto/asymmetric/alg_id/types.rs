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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgId {
    Ed25519 = 0x01,
    MlDsa44 = 0x02,
    MlDsa65 = 0x03,
    MlDsa87 = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgIdError {
    Unknown(u8),
    Unsupported(AlgId),
    PubkeyLen { alg: AlgId, expected: usize, got: usize },
    SigLen { alg: AlgId, expected: usize, got: usize },
}

impl AlgId {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(b: u8) -> Result<Self, AlgIdError> {
        match b {
            0x01 => Ok(Self::Ed25519),
            0x02 => Ok(Self::MlDsa44),
            0x03 => Ok(Self::MlDsa65),
            0x04 => Ok(Self::MlDsa87),
            other => Err(AlgIdError::Unknown(other)),
        }
    }
}
