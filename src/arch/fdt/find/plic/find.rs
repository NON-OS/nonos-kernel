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

use super::compatible::matches;
use super::info::PlicInfo;

pub fn find(fdt: &Fdt) -> Result<Option<PlicInfo>, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut matched = false;
    let mut base_out: Option<u64> = None;
    let mut address_cells: u32 = 2;
    let mut size_cells: u32 = 1;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { .. } => {
                depth += 1;
                if depth == 1 {
                    matched = false;
                    base_out = None;
                }
            }
            Event::EndNode => {
                if depth == 1 {
                    if matched {
                        if let Some(b) = base_out {
                            return Ok(Some(PlicInfo { base: b }));
                        }
                    }
                    matched = false;
                    base_out = None;
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
                } else if depth == 1 {
                    if prop.name == b"compatible" {
                        matched = matches(&prop);
                    } else if prop.name == b"reg" && matched {
                        if let Some((b, _)) = prop.reg_iter(address_cells, size_cells).next() {
                            base_out = Some(b);
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}
