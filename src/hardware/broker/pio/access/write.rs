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

//! Kernel-mediated PIO write. Width selects which architectural
//! `out` instruction fires; the high bits of the supplied `u32`
//! are discarded for narrower widths.

use super::super::types::{PioError, PioWidth};
use super::raw::{out16, out32, out8};
use super::resolve::resolve;

pub fn write(
    pid: u32,
    grant_id: u64,
    port_offset: u16,
    width: PioWidth,
    value: u32,
) -> Result<(), PioError> {
    let g = resolve(pid, grant_id, port_offset, width)?;
    let port = g.port_base + port_offset;
    unsafe {
        match width {
            PioWidth::U8 => out8::raw_out8(port, value as u8),
            PioWidth::U16 => out16::raw_out16(port, value as u16),
            PioWidth::U32 => out32::raw_out32(port, value),
        }
    }
    Ok(())
}
