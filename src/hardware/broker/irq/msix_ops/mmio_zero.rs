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

// x86-only: MSI-X entry layout (msg-addr-lo/hi, data, vector-control).
#![cfg(target_arch = "x86_64")]

use crate::drivers::pci::constants::{MSIX_ENTRY_MASKED, MSIX_ENTRY_SIZE};
use crate::drivers::pci::types::{MsixInfo, PciBar};
use crate::memory::addr::VirtAddr;
use crate::memory::mmio::mmio_w32;

pub(super) fn zero_table_entry(msix: &MsixInfo, bars: &[PciBar; 6], device_vector: u16) {
    let Some(bar) = bars.get(msix.table_bar as usize) else { return };
    let Some(table_base) = bar.address() else { return };
    let entry_offset = msix.table_offset + (device_vector as u32) * MSIX_ENTRY_SIZE;
    let base = VirtAddr::new(table_base.as_u64() + entry_offset as u64);
    mmio_w32(base, 0);
    mmio_w32(base + 4u64, 0);
    mmio_w32(base + 8u64, 0);
    mmio_w32(base + 12u64, MSIX_ENTRY_MASKED);
}
