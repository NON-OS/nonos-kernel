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

//! NIST P-384 (secp384r1) constants.
//! All multi-limb values are in little-endian limb order.

/// Field prime: p = 2^384 − 2^128 − 2^96 + 2^32 − 1
pub(crate) const P384_P: [u64; 6] = [
    0x00000000FFFFFFFF, // limb 0 (least significant)
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Group order n
pub(crate) const P384_N: [u64; 6] = [
    0xECEC196ACCC52973,
    0x581A0DB248B0A77A,
    0xC7634D81F4372DDF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Generator x-coordinate
pub(crate) const P384_GX: [u64; 6] = [
    0x3A545E3872760AB7,
    0x5502F25DBF55296C,
    0x59F741E082542A38,
    0x6E1D3B628BA79B98,
    0x8EB1C71EF320AD74,
    0xAA87CA22BE8B0537,
];

/// Generator y-coordinate
pub(crate) const P384_GY: [u64; 6] = [
    0x7A431D7C90EA0E5F,
    0x0A60B1CE1D7E819D,
    0xE9DA3113B5F0B8C0,
    0xF8F41DBD289A147C,
    0x5D9E98BF9292DC29,
    0x3617DE4A96262C6F,
];

/// Curve parameter a = p − 3
pub(crate) const P384_A: [u64; 6] = [
    0x00000000FFFFFFFC,
    0xFFFFFFFF00000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Curve parameter b
pub(crate) const P384_B: [u64; 6] = [
    0x2A85C8EDD3EC2AEF,
    0xC656398D8A2ED19D,
    0x0314088F5013875A,
    0x181D9C6EFE814112,
    0x988E056BE3F82D19,
    0xB3312FA7E23EE7E4,
];

pub type SecretKey = [u8; 48];
pub type PublicKey = [u8; 97]; // 0x04 + 48 (x) + 48 (y)
pub type CompressedPublicKey = [u8; 49];
pub type Signature = [u8; 96]; // 48 (r) + 48 (s)
