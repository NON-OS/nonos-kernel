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

use crate::drivers::pci::PciDevice;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::super::constants::*;

pub struct Rtl8139Device {
    pub pci_device: PciDevice,
    pub(super) io_base: u16,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    pub(super) rx_buffer_phys: PhysAddr,
    pub(super) rx_buffer_virt: VirtAddr,
    pub(super) rx_offset: u16,
    pub(super) tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    pub(super) tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    pub(super) tx_cur: usize,
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

impl Rtl8139Device {
    pub(super) fn alloc_rx_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
        let constraints = DmaConstraints {
            alignment: 8,
            max_segment_size: RX_BUFFER_SIZE,
            dma32_only: true,
            coherent: true,
        };
        let region = alloc_dma_coherent(RX_BUFFER_SIZE, constraints)
            .map_err(|_| "Failed to allocate RX buffer")?;
        // SAFETY: region.virt_addr points to valid DMA memory of RX_BUFFER_SIZE bytes
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, RX_BUFFER_SIZE);
        }
        Ok((region.phys_addr, region.virt_addr))
    }

    pub(super) fn alloc_tx_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
        let constraints = DmaConstraints {
            alignment: 8,
            max_segment_size: TX_BUFFER_SIZE,
            dma32_only: true,
            coherent: true,
        };
        let region = alloc_dma_coherent(TX_BUFFER_SIZE, constraints)
            .map_err(|_| "Failed to allocate TX buffer")?;
        // SAFETY: region.virt_addr points to valid DMA memory of TX_BUFFER_SIZE bytes
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, TX_BUFFER_SIZE);
        }
        Ok((region.phys_addr, region.virt_addr))
    }
}
