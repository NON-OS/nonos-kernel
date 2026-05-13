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

use super::compatible::classify;
use super::info::UartInfo;
use super::kind::UartKind;

pub fn find(fdt: &Fdt) -> Result<Option<UartInfo>, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut current_kind: Option<UartKind> = None;
    let mut found_base: Option<u64> = None;
    let mut address_cells: u32 = 2;
    let mut size_cells: u32 = 1;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { .. } => {
                depth += 1;
                if depth == 1 {
                    current_kind = None;
                    found_base = None;
                }
            }
            Event::EndNode => {
                if depth == 1 {
                    if let (Some(kind), Some(base)) = (current_kind, found_base) {
                        return Ok(Some(UartInfo { kind, base }));
                    }
                    current_kind = None;
                    found_base = None;
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
                        current_kind = classify(&prop);
                    } else if prop.name == b"reg" && current_kind.is_some() {
                        if let Some((base, _)) = prop.reg_iter(address_cells, size_cells).next() {
                            found_base = Some(base);
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}
