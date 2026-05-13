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

use crate::arch::fdt::endian::be_cells;
use crate::arch::fdt::error::FdtError;
use crate::arch::fdt::parser::Fdt;
use crate::arch::fdt::walker::Event;

// Walk `/cpus/cpu@*` and collect each CPU's `reg` (MPIDR Aff bits on
// aarch64, hart id on riscv64). Returns the number of ids written.
pub fn find(fdt: &Fdt, out: &mut [u64]) -> Result<usize, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut in_cpus = false;
    let mut at_cpu = false;
    let mut address_cells: u32 = 1;
    let mut filled = 0usize;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { name } => {
                depth += 1;
                if depth == 1 && name == b"cpus" {
                    in_cpus = true;
                }
                if in_cpus && depth == 2 && (name == b"cpu" || starts_with(name, b"cpu@")) {
                    at_cpu = true;
                }
            }
            Event::EndNode => {
                if at_cpu && depth == 2 {
                    at_cpu = false;
                }
                if in_cpus && depth == 1 {
                    in_cpus = false;
                }
                depth -= 1;
            }
            Event::Property(prop) => {
                if in_cpus && depth == 1 && prop.name == b"#address-cells" {
                    address_cells = prop.u32()?;
                } else if at_cpu && prop.name == b"reg" {
                    if let Ok(id) = be_cells(prop.data, 0, address_cells) {
                        if filled < out.len() {
                            out[filled] = id;
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
