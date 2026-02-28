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

pub const MCELIECE_N: usize = 3488;
pub const MCELIECE_K: usize = 2720;
pub const MCELIECE_T: usize = 64;
pub const MCELIECE_M: usize = 12;

pub const MCELIECE_PUBLICKEY_BYTES: usize = (MCELIECE_N - MCELIECE_K) * MCELIECE_K / 8;
pub const MCELIECE_SECRETKEY_BYTES: usize = MCELIECE_N / 8 + MCELIECE_M * MCELIECE_T / 8 + 40;
pub const MCELIECE_CIPHERTEXT_BYTES: usize = MCELIECE_N / 8;
pub const MCELIECE_SHARED_SECRET_BYTES: usize = 32;

pub(crate) const FIELD_SIZE: usize = 1 << MCELIECE_M;

pub const fn mceliece_param_name() -> &'static str {
    "McEliece348864"
}
