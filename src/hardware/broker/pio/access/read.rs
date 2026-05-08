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

//! Kernel-mediated PIO read. Width selects which architectural
//! `in` instruction fires; everything narrower than the requested
//! width zeros the upper bits of the returned `u32`.

use super::super::types::{PioError, PioWidth};
use super::raw::{in16, in32, in8};
use super::resolve::resolve;

pub fn read(pid: u32, grant_id: u64, port_offset: u16, width: PioWidth) -> Result<u32, PioError> {
    let g = resolve(pid, grant_id, port_offset, width)?;
    let port = g.port_base + port_offset;
    let value = unsafe {
        match width {
            PioWidth::U8 => in8::raw_in8(port) as u32,
            PioWidth::U16 => in16::raw_in16(port) as u32,
            PioWidth::U32 => in32::raw_in32(port),
        }
    };
    Ok(value)
}
