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

use super::super::types::RootCaFingerprint;

pub(super) static ISRG_ROOTS: &[RootCaFingerprint] = &[
    RootCaFingerprint { spki_sha256: [0x0b,0x9f,0xa5,0xa5,0x9e,0xed,0x71,0x5c,0x26,0xc1,0x02,0x0c,0x71,0x1b,0x4f,0x6e,0xc4,0x2d,0x58,0xb0,0x01,0x5e,0x14,0x33,0x7a,0x39,0xda,0xd3,0x01,0xc5,0xaf,0xc3], name: "ISRG Root X1" },
    RootCaFingerprint { spki_sha256: [0x76,0x21,0x95,0xc2,0x25,0x58,0x6e,0xe6,0xc0,0x23,0x74,0x56,0xe2,0x10,0x7d,0xc5,0x4f,0x1e,0xfc,0x21,0xf6,0x1a,0x79,0x2e,0xbd,0x51,0x59,0x13,0xcc,0xe6,0x83,0x32], name: "ISRG Root X2" },
];
