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

use alloc::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct PciStats {
    pub total_devices: usize,
    pub devices_by_class: BTreeMap<u8, usize>,
    pub msix_devices: usize,
    pub dma_engines: u64,
    pub config_reads: u64,
    pub config_writes: u64,
    pub dma_transfers: u64,
    pub dma_bytes: u64,
    pub interrupts: u64,
    pub msi_interrupts: u64,
    pub errors: u64,
}

impl PciStats {
    pub const fn new() -> Self {
        Self {
            total_devices: 0,
            devices_by_class: BTreeMap::new(),
            msix_devices: 0,
            dma_engines: 0,
            config_reads: 0,
            config_writes: 0,
            dma_transfers: 0,
            dma_bytes: 0,
            interrupts: 0,
            msi_interrupts: 0,
            errors: 0,
        }
    }
}

impl Default for PciStats {
    fn default() -> Self {
        Self::new()
    }
}
