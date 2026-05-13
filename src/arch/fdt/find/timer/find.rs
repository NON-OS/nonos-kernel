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
use super::info::TimerInfo;
use super::intid::{decode, entry_count};

// Walk for the first arm,armv8-timer / arm,armv7-timer node and return
// its interrupts as resolved GIC intids. The binding fixes the order
// of cells as secure-phys / non-sec-phys / virt / hyp-phys.
pub fn find(fdt: &Fdt) -> Result<Option<TimerInfo>, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut matched = false;
    let mut info = TimerInfo::default();
    let mut got_interrupts = false;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { .. } => {
                depth += 1;
                if depth == 1 {
                    matched = false;
                    info = TimerInfo::default();
                    got_interrupts = false;
                }
            }
            Event::EndNode => {
                if depth == 1 && matched && got_interrupts {
                    return Ok(Some(info));
                }
                depth -= 1;
            }
            Event::Property(prop) => {
                if depth == 1 {
                    if prop.name == b"compatible" {
                        matched = matches(&prop);
                    } else if prop.name == b"interrupts" && matched {
                        let n = entry_count(prop.data.len());
                        if n >= 1 {
                            info.secure_phys_intid = decode(prop.data, 0).unwrap_or(0);
                        }
                        if n >= 2 {
                            info.nonsecure_phys_intid = decode(prop.data, 1).unwrap_or(0);
                        }
                        if n >= 3 {
                            info.virtual_intid = decode(prop.data, 2).unwrap_or(0);
                        }
                        if n >= 4 {
                            info.hyp_phys_intid = decode(prop.data, 3).unwrap_or(0);
                        }
                        got_interrupts = n >= 2;
                    }
                }
            }
        }
    }
    Ok(None)
}
