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

// Prefer /cpus/timebase-frequency. Fall back to the first per-cpu
// child timebase-frequency.
pub fn find(fdt: &Fdt) -> Result<Option<u64>, FdtError> {
    let mut walker = fdt.walker();
    let mut depth: i32 = -1;
    let mut in_cpus = false;
    let mut child_freq: Option<u64> = None;

    while let Some(event) = walker.next()? {
        match event {
            Event::BeginNode { name } => {
                depth += 1;
                if depth == 1 && name == b"cpus" {
                    in_cpus = true;
                }
            }
            Event::EndNode => {
                if depth == 1 && in_cpus {
                    in_cpus = false;
                }
                depth -= 1;
            }
            Event::Property(prop) => {
                if in_cpus && depth == 1 && prop.name == b"timebase-frequency" {
                    return Ok(Some(prop.u32()? as u64));
                }
                if in_cpus
                    && depth == 2
                    && prop.name == b"timebase-frequency"
                    && child_freq.is_none()
                {
                    child_freq = Some(prop.u32()? as u64);
                }
            }
        }
    }
    Ok(child_freq)
}
