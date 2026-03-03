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

extern crate alloc;

use core::sync::atomic::AtomicU64;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::super::constants::*;

pub struct E1000Device {
    pub pci_device: PciDevice,
    pub(super) mmio_base: VirtAddr,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    pub full_duplex: bool,
    pub(super) rx_descs_phys: PhysAddr,
    pub(super) rx_descs_virt: VirtAddr,
    pub(super) rx_buffers_phys: [PhysAddr; RX_DESC_COUNT],
    pub(super) rx_buffers_virt: [VirtAddr; RX_DESC_COUNT],
    pub(super) rx_tail: usize,
    pub(super) tx_descs_phys: PhysAddr,
    pub(super) tx_descs_virt: VirtAddr,
    pub(super) tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    pub(super) tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    pub(super) tx_tail: usize,
    pub(super) tx_in_flight: [bool; TX_DESC_COUNT],
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

impl E1000Device {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        let bar0 = pci_device.get_bar(0).ok_or("E1000: BAR0 not present")?;
        let (mmio_base, _) = bar0.mmio_region().ok_or("E1000: BAR0 is not MMIO")?;

        crate::log::info!("e1000: MMIO base at {:#x}", mmio_base.as_u64());

        let cmd = pci_read_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x04,
        );
        pci_write_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x04,
            cmd | 0x06,
        );

        let mmio_virt = VirtAddr::new(mmio_base.as_u64());

        let (rx_descs_phys, rx_descs_virt) = Self::alloc_desc_ring(RX_DESC_COUNT)?;
        let (tx_descs_phys, tx_descs_virt) = Self::alloc_desc_ring(TX_DESC_COUNT)?;

        let mut rx_buffers_phys = [PhysAddr::zero(); RX_DESC_COUNT];
        let mut rx_buffers_virt = [VirtAddr::zero(); RX_DESC_COUNT];
        let mut tx_buffers_phys = [PhysAddr::zero(); TX_DESC_COUNT];
        let mut tx_buffers_virt = [VirtAddr::zero(); TX_DESC_COUNT];

        for i in 0..RX_DESC_COUNT {
            let (phys, virt) = Self::alloc_buffer()?;
            rx_buffers_phys[i] = phys;
            rx_buffers_virt[i] = virt;
        }

        for i in 0..TX_DESC_COUNT {
            let (phys, virt) = Self::alloc_buffer()?;
            tx_buffers_phys[i] = phys;
            tx_buffers_virt[i] = virt;
        }

        let mut dev = Self {
            pci_device,
            mmio_base: mmio_virt,
            mac_address: [0; 6],
            link_up: false,
            link_speed: 0,
            full_duplex: false,
            rx_descs_phys,
            rx_descs_virt,
            rx_buffers_phys,
            rx_buffers_virt,
            rx_tail: 0,
            tx_descs_phys,
            tx_descs_virt,
            tx_buffers_phys,
            tx_buffers_virt,
            tx_tail: 0,
            tx_in_flight: [false; TX_DESC_COUNT],
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        };

        if !dev.reset() {
            return Err("E1000: Hardware reset failed");
        }
        dev.read_mac_address();
        dev.init_rx();
        dev.init_tx();
        dev.enable_interrupts();
        dev.update_link_status();

        crate::log::info!(
            "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev.mac_address[0],
            dev.mac_address[1],
            dev.mac_address[2],
            dev.mac_address[3],
            dev.mac_address[4],
            dev.mac_address[5]
        );

        if dev.link_up {
            crate::log::info!(
                "e1000: Link UP {}Mbps {}",
                dev.link_speed,
                if dev.full_duplex { "FD" } else { "HD" }
            );
        } else {
            crate::log::info!("e1000: Link DOWN");
        }

        Ok(dev)
    }

    pub(super) fn alloc_desc_ring(count: usize) -> Result<(PhysAddr, VirtAddr), &'static str> {
        let size = count * 16;
        let constraints = DmaConstraints {
            alignment: DESC_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };
        let region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "Failed to allocate descriptor ring")?;
        // SAFETY: region.virt_addr is valid and properly aligned from alloc_dma_coherent
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, size);
        }
        Ok((region.phys_addr, region.virt_addr))
    }

    pub(super) fn alloc_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
        let constraints = DmaConstraints {
            alignment: 16,
            max_segment_size: BUFFER_SIZE,
            dma32_only: false,
            coherent: true,
        };
        let region = alloc_dma_coherent(BUFFER_SIZE, constraints)
            .map_err(|_| "Failed to allocate packet buffer")?;
        // SAFETY: region.virt_addr is valid and properly aligned from alloc_dma_coherent
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, BUFFER_SIZE);
        }
        Ok((region.phys_addr, region.virt_addr))
    }

    #[inline]
    pub(super) fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    #[inline]
    pub(super) fn write_reg(&self, offset: u32, value: u32) {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }
}
