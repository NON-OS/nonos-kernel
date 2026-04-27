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
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::e1000::constants::{RX_DESC_COUNT, TX_DESC_COUNT};
use crate::drivers::pci::PciDevice;

pub struct E1000Device {
    pub pci_device: PciDevice,
    pub(crate) mmio_base: VirtAddr,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    pub full_duplex: bool,
    pub(crate) rx_descs_phys: PhysAddr,
    pub(crate) rx_descs_virt: VirtAddr,
    pub(crate) rx_buffers_phys: [PhysAddr; RX_DESC_COUNT],
    pub(crate) rx_buffers_virt: [VirtAddr; RX_DESC_COUNT],
    pub(crate) rx_tail: usize,
    pub(crate) tx_descs_phys: PhysAddr,
    pub(crate) tx_descs_virt: VirtAddr,
    pub(crate) tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    pub(crate) tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    pub(crate) tx_tail: usize,
    pub(crate) tx_in_flight: [bool; TX_DESC_COUNT],
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

// SAFETY: E1000Device uses DMA-coherent memory and proper synchronization
unsafe impl Send for E1000Device {}
unsafe impl Sync for E1000Device {}
