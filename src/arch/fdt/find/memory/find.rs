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

use crate::arch::fdt::error::FdtError;
use crate::arch::fdt::parser::Fdt;
use crate::arch::fdt::walker::Event;

use super::range::MemoryRange;

// Walk every `/memory` (or `device_type = "memory"`) node and fill
// `out`. Ranges beyond `out.len()` are dropped. /memory at top level
// uses root #address-cells / #size-cells.
pub fn find(fdt: &Fdt, out: &mut [MemoryRange]) -> Result<usize, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut at_memory = false;
    let mut address_cells: u32 = 2;
    let mut size_cells: u32 = 1;
    let mut filled = 0usize;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { name } => {
                depth += 1;
                if depth == 1 && (name == b"memory" || starts_with(name, b"memory@")) {
                    at_memory = true;
                }
            }
            Event::EndNode => {
                if depth == 1 && at_memory {
                    at_memory = false;
                }
                depth -= 1;
            }
            Event::Property(prop) => {
                if depth == 0 {
                    if prop.name == b"#address-cells" {
                        address_cells = prop.u32()?;
                    } else if prop.name == b"#size-cells" {
                        size_cells = prop.u32()?;
                    }
                } else if at_memory && prop.name == b"reg" {
                    for (base, size) in prop.reg_iter(address_cells, size_cells) {
                        if filled < out.len() {
                            out[filled] = MemoryRange { base, size };
                            filled += 1;
                        }
                    }
                }
            }
        }
    }
    Ok(filled)
}

#[inline]
fn starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && &haystack[..prefix.len()] == prefix
}
