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

pub const NTRU_N: usize = 821;
pub const NTRU_Q: u16 = 4096;
pub const NTRU_LOG_Q: usize = 12;

pub const NTRU_PUBLICKEY_BYTES: usize = (NTRU_N * NTRU_LOG_Q + 7) / 8;
pub const NTRU_SECRETKEY_BYTES: usize = NTRU_N + NTRU_PUBLICKEY_BYTES;
pub const NTRU_CIPHERTEXT_BYTES: usize = (NTRU_N * NTRU_LOG_Q + 7) / 8;
pub const NTRU_SHARED_SECRET_BYTES: usize = 32;

pub(crate) const NTRU_WEIGHT: usize = 286;

pub const fn ntru_param_name() -> &'static str {
    "NTRU-HPS-4096-821"
}
