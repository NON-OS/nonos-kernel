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

use super::constants::{HDR_LEN, NCMP_MAGIC, NCMP_VERSION, OP_HEALTHCHECK};

pub fn encode_healthcheck_header(buf: &mut [u8; HDR_LEN]) {
    buf[0..4].copy_from_slice(&NCMP_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&NCMP_VERSION.to_le_bytes());
    buf[6..8].copy_from_slice(&OP_HEALTHCHECK.to_le_bytes());
    buf[8..10].copy_from_slice(&0u16.to_le_bytes());
    buf[12..16].copy_from_slice(&1u32.to_le_bytes());
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());
}
