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

use core::sync::atomic::AtomicU64;
use crate::memory::addr::{PhysAddr, VirtAddr};

use crate::drivers::pci::PciDevice;
use crate::drivers::rtl8139::constants::TX_DESC_COUNT;

pub struct Rtl8139Device {
    pub pci_device: PciDevice,
    pub(crate) io_base: u16,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    pub(crate) rx_buffer_phys: PhysAddr,
    pub(crate) rx_buffer_virt: VirtAddr,
    pub(crate) rx_offset: u16,
    pub(crate) tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    pub(crate) tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    pub(crate) tx_cur: usize,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

// SAFETY: DMA-coherent memory and atomic operations ensure thread safety
unsafe impl Send for Rtl8139Device {}
unsafe impl Sync for Rtl8139Device {}
