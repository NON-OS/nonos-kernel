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

use super::types::AlgId;

pub const ED25519_PUBKEY_BYTES: usize = 32;
pub const ED25519_SIG_BYTES: usize = 64;

pub const MLDSA44_PUBKEY_BYTES: usize = 1312;
pub const MLDSA44_SIG_BYTES: usize = 2420;

pub const MLDSA65_PUBKEY_BYTES: usize = 1952;
pub const MLDSA65_SIG_BYTES: usize = 3309;

pub const MLDSA87_PUBKEY_BYTES: usize = 2592;
pub const MLDSA87_SIG_BYTES: usize = 4627;

pub const MAX_PUBKEY_BYTES: usize = MLDSA87_PUBKEY_BYTES;
pub const MAX_SIG_BYTES: usize = MLDSA87_SIG_BYTES;

pub const fn pubkey_len(alg: AlgId) -> usize {
    match alg {
        AlgId::Ed25519 => ED25519_PUBKEY_BYTES,
        AlgId::MlDsa44 => MLDSA44_PUBKEY_BYTES,
        AlgId::MlDsa65 => MLDSA65_PUBKEY_BYTES,
        AlgId::MlDsa87 => MLDSA87_PUBKEY_BYTES,
    }
}

pub const fn sig_len(alg: AlgId) -> usize {
    match alg {
        AlgId::Ed25519 => ED25519_SIG_BYTES,
        AlgId::MlDsa44 => MLDSA44_SIG_BYTES,
        AlgId::MlDsa65 => MLDSA65_SIG_BYTES,
        AlgId::MlDsa87 => MLDSA87_SIG_BYTES,
    }
}
