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

pub const BN254_MODULUS: [u64; 4] =
    [0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029];

pub const MONTGOMERY_R: [u64; 4] =
    [0xd35d438dc58f0d9d, 0xa78eb28f5c70b3dd, 0x666ea36f7879462c, 0x0e0a77c19a07df2f];

pub const MONTGOMERY_R2: [u64; 4] =
    [0xf32cfc5b538afa89, 0xb5e71911d44501fb, 0x47ab1eff0a417ff6, 0x06d89f71cab8351f];

pub const MONTGOMERY_INV: u64 = 0x87d20782e4866389;
