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
    RootCaFingerprint { spki_sha256: [0x0b,0x9f,0xa5,0xa5,0x9e,0xed,0x71,0x5c,0x26,0xc1,0x02,0x0c,0x71,0x1b,0x4f,0x6e,0xc4,0x2d,0x58,0xb0,0x01,0x5e,0x14,0x33,0x7a,0x39,0xda,0xad,0xa0,0x95,0xeb,0x4d], name: "ISRG Root X1" },
    RootCaFingerprint { spki_sha256: [0x76,0x2e,0xfc,0xf8,0x00,0xfa,0x5b,0x05,0x4a,0x38,0xd5,0xef,0x7d,0x5b,0x9b,0x0e,0x07,0x28,0x5f,0x7a,0xc8,0x34,0xe0,0x66,0x3d,0x42,0x3d,0xb7,0xd0,0x20,0x97,0x82], name: "ISRG Root X2" },
];
