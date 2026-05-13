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

use crate::arch::fdt::endian::be_u32;
use crate::arch::fdt::error::FdtError;

// GIC interrupt cell layout (3 cells per IRQ when #interrupt-cells=3):
//   cell[0] = type (0 = SPI, 1 = PPI)
//   cell[1] = interrupt number
//   cell[2] = trigger flags
//
// PPI intid = 16 + ppi_number  (16 SGIs precede the PPI bank)
// SPI intid = 32 + spi_number  (16 SGIs + 16 PPIs precede SPIs)
//
// `entry_index` selects which 3-cell tuple to read (0-based).
pub fn decode(data: &[u8], entry_index: usize) -> Result<u32, FdtError> {
    const CELL_BYTES: usize = 4;
    const CELLS_PER_IRQ: usize = 3;
    let base = entry_index * CELLS_PER_IRQ * CELL_BYTES;
    let kind = be_u32(data, base)?;
    let number = be_u32(data, base + CELL_BYTES)?;
    Ok(match kind {
        0 => 32u32.saturating_add(number),
        1 => 16u32.saturating_add(number),
        _ => return Err(FdtError::OutOfBounds),
    })
}

// Number of complete 3-cell interrupts in a property of length `len`.
pub fn entry_count(len: usize) -> usize {
    len / (3 * 4)
}
