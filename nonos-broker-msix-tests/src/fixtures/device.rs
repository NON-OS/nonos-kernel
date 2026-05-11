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

use crate::broker::pci_index::{self, PciHandle};
use crate::drivers::pci::types::{MsixInfo, PciAddress, PciBar};
use crate::memory::addr::PhysAddr;

pub fn good_msix_info() -> MsixInfo {
    MsixInfo {
        offset: 0x40,
        table_size: 7,
        table_bar: 0,
        table_offset: 0x1000,
        pba_bar: 0,
        pba_offset: 0x2000,
        enabled: false,
        function_mask: false,
    }
}

pub fn mmio_bar(address: u64, size: u64) -> PciBar {
    PciBar::Memory64 { address: PhysAddr::new(address), size, prefetchable: false }
}

pub fn install_pci_msix_device(
    device_id: u64,
    address: PciAddress,
    bars: [PciBar; 6],
    msix: Option<MsixInfo>,
) {
    pci_index::install(alloc::vec![PciHandle { device_id, address, bars, msix }]);
}
