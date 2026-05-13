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
use super::info::GicInfo;
use super::version::GicVersion;

// arm,gic-v3 reg = (dist, redist[, ...]); GICv2 reg = (dist, cpu[, ...]).
// We take the first two entries.
pub fn find(fdt: &Fdt) -> Result<Option<GicInfo>, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut version: Option<GicVersion> = None;
    let mut bases: [u64; 2] = [0; 2];
    let mut bases_filled = 0usize;
    let mut address_cells: u32 = 2;
    let mut size_cells: u32 = 1;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { .. } => {
                depth += 1;
                if depth == 1 {
                    version = None;
                    bases_filled = 0;
                }
            }
            Event::EndNode => {
                if depth == 1 {
                    if let Some(v) = version {
                        if bases_filled >= 2 {
                            return Ok(Some(GicInfo {
                                version: v,
                                dist_base: bases[0],
                                redist_or_cpu_base: bases[1],
                            }));
                        }
                    }
                    version = None;
                    bases_filled = 0;
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
                        version = classify(&prop);
                    } else if prop.name == b"reg" && version.is_some() {
                        for (base, _) in prop.reg_iter(address_cells, size_cells) {
                            if bases_filled < 2 {
                                bases[bases_filled] = base;
                                bases_filled += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(None)
}
