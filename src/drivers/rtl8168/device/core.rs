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

use super::super::constants::{RX_BUFFER_SIZE, RX_DESC_COUNT, TX_BUFFER_SIZE, TX_DESC_COUNT};
use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

const DESC_ALIGNMENT: usize = 256;

pub struct Rtl8168Device {
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
    pub(super) rx_index: usize,
    pub(super) tx_descs_phys: PhysAddr,
    pub(super) tx_descs_virt: VirtAddr,
    pub(super) tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    pub(super) tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    pub(super) tx_index: usize,
    pub(super) tx_clean: usize,
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
}

unsafe impl Send for Rtl8168Device {}
unsafe impl Sync for Rtl8168Device {}

impl Rtl8168Device {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        let bar0 = pci_device.get_bar(0).ok_or("RTL8168: BAR0 not present")?;
        let (mmio_base, _) = bar0.mmio_region().ok_or("RTL8168: BAR0 is not MMIO")?;

        crate::log::info!("rtl8168: MMIO base at {:#x}", mmio_base.as_u64());

        let cmd_reg = pci_read_config32(
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
            cmd_reg | 0x06,
        );

        let mmio_virt = VirtAddr::new(mmio_base.as_u64());

        let (rx_descs_phys, rx_descs_virt) = Self::alloc_desc_ring(RX_DESC_COUNT)?;
        let (tx_descs_phys, tx_descs_virt) = Self::alloc_desc_ring(TX_DESC_COUNT)?;

        let mut rx_buffers_phys = [PhysAddr::zero(); RX_DESC_COUNT];
        let mut rx_buffers_virt = [VirtAddr::zero(); RX_DESC_COUNT];
        let mut tx_buffers_phys = [PhysAddr::zero(); TX_DESC_COUNT];
        let mut tx_buffers_virt = [VirtAddr::zero(); TX_DESC_COUNT];

        for i in 0..RX_DESC_COUNT {
            let (phys, virt) = Self::alloc_buffer(RX_BUFFER_SIZE)?;
            rx_buffers_phys[i] = phys;
            rx_buffers_virt[i] = virt;
        }

        for i in 0..TX_DESC_COUNT {
            let (phys, virt) = Self::alloc_buffer(TX_BUFFER_SIZE)?;
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
            rx_index: 0,
            tx_descs_phys,
            tx_descs_virt,
            tx_buffers_phys,
            tx_buffers_virt,
            tx_index: 0,
            tx_clean: 0,
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        };

        dev.software_reset()?;
        dev.read_mac_address();
        dev.init_rx();
        dev.init_tx();
        dev.enable_interrupts();
        dev.enable_rx_tx();
        dev.update_link_status();

        crate::log::info!(
            "rtl8168: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev.mac_address[0], dev.mac_address[1], dev.mac_address[2],
            dev.mac_address[3], dev.mac_address[4], dev.mac_address[5]
        );

        if dev.link_up {
            crate::log::info!(
                "rtl8168: Link UP {}Mbps {}",
                dev.link_speed,
                if dev.full_duplex { "FD" } else { "HD" }
            );
        } else {
            crate::log::info!("rtl8168: Link DOWN");
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
            .map_err(|_| "RTL8168: Failed to allocate descriptor ring")?;
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, size);
        }
        Ok((region.phys_addr, region.virt_addr))
    }

    pub(super) fn alloc_buffer(size: usize) -> Result<(PhysAddr, VirtAddr), &'static str> {
        let constraints = DmaConstraints {
            alignment: 8,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };
        let region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "RTL8168: Failed to allocate packet buffer")?;
        unsafe {
            core::ptr::write_bytes(region.virt_addr.as_mut_ptr::<u8>(), 0, size);
        }
        Ok((region.phys_addr, region.virt_addr))
    }

    pub(super) fn read8(&self, offset: u16) -> u8 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u8) }
    }

    pub(super) fn read16(&self, offset: u16) -> u16 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u16) }
    }

    pub(super) fn read32(&self, offset: u16) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u32) }
    }

    pub(super) fn write8(&self, offset: u16, value: u8) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u8, value) }
    }

    pub(super) fn write16(&self, offset: u16, value: u16) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u16, value) }
    }

    pub(super) fn write32(&self, offset: u16, value: u32) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u32, value) }
    }

    pub(super) fn spin_delay(&self, us: u64) {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        while crate::arch::x86_64::time::tsc::elapsed_us() - start < us {
            core::hint::spin_loop();
        }
    }
}
