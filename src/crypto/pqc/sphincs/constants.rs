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

pub const SPHINCS_N: usize = 16;
pub const SPHINCS_H: usize = 63;
pub const SPHINCS_D: usize = 7;
pub const SPHINCS_K: usize = 14;
pub const SPHINCS_A: usize = 12;
pub const SPHINCS_W: usize = 16;

pub const SPHINCS_WOTS_LEN1: usize = 2 * SPHINCS_N;
pub const SPHINCS_WOTS_LEN2: usize = 3;
pub const SPHINCS_WOTS_LEN: usize = SPHINCS_WOTS_LEN1 + SPHINCS_WOTS_LEN2;
pub const SPHINCS_WOTS_SIG_BYTES: usize = SPHINCS_WOTS_LEN * SPHINCS_N;

pub const SPHINCS_FORS_MSG_BYTES: usize = (SPHINCS_K * SPHINCS_A + 7) / 8;
pub const SPHINCS_FORS_SIG_BYTES: usize = SPHINCS_K * (SPHINCS_A + 1) * SPHINCS_N;

pub const SPHINCS_SK_SEED_BYTES: usize = SPHINCS_N;
pub const SPHINCS_SK_PRF_BYTES: usize = SPHINCS_N;
pub const SPHINCS_PK_SEED_BYTES: usize = SPHINCS_N;
pub const SPHINCS_PK_ROOT_BYTES: usize = SPHINCS_N;

pub const SPHINCS_SK_BYTES: usize = 2 * SPHINCS_N + SPHINCS_PK_BYTES;
pub const SPHINCS_PK_BYTES: usize = 2 * SPHINCS_N;

pub const SPHINCS_SIG_BYTES: usize = SPHINCS_N
    + SPHINCS_FORS_SIG_BYTES
    + SPHINCS_D * (SPHINCS_WOTS_SIG_BYTES + (SPHINCS_H / SPHINCS_D) * SPHINCS_N);

pub const fn sphincs_param_name() -> &'static str {
    "SPHINCS+-128s-simple"
}
