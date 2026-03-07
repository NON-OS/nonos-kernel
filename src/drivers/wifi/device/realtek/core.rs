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

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::super::super::error::WifiError;
use super::super::super::scan::{ScanResult, SecurityType};
use super::super::types::WifiState;
use super::constants::*;
use super::descriptors::{RtlTxDesc, RtlRxDesc};

pub struct RealtekWifiDevice {
    pub(crate) mmio_base: VirtAddr,
    pub(crate) state: WifiState,
    pub(crate) device_id: u16,
    pub(crate) mac_address: [u8; 6],
    pub(crate) current_ssid: Option<String>,
    pub(crate) current_bssid: Option<[u8; 6]>,
    pub(crate) current_channel: u8,
    pub(crate) current_security: SecurityType,
    pub(crate) rssi: i8,
    pub(crate) scan_results: Vec<ScanResult>,
    pub(crate) tx_ring_phys: PhysAddr,
    pub(crate) tx_ring_virt: VirtAddr,
    pub(crate) rx_ring_phys: PhysAddr,
    pub(crate) rx_ring_virt: VirtAddr,
    pub(crate) tx_buffers_phys: PhysAddr,
    pub(crate) tx_buffers_virt: VirtAddr,
    pub(crate) rx_buffers_phys: PhysAddr,
    pub(crate) rx_buffers_virt: VirtAddr,
    pub(crate) tx_head: usize,
    pub(crate) rx_head: usize,
    pub(crate) firmware_loaded: bool,
    #[allow(dead_code)]
    pub(crate) pci_device: PciDevice,
}

// SAFETY: RealtekWifiDevice uses DMA-coherent memory and proper synchronization
unsafe impl Send for RealtekWifiDevice {}
unsafe impl Sync for RealtekWifiDevice {}

impl RealtekWifiDevice {
    pub fn new(pci_device: PciDevice) -> Result<Self, WifiError> {
        let device_id = pci_device.device_id_value();

        let bar0 = pci_device.get_bar(0).ok_or(WifiError::DeviceNotFound)?;
        let (mmio_phys, _) = bar0.mmio_region().ok_or(WifiError::DeviceNotFound)?;
        let mmio_base = VirtAddr::new(mmio_phys.as_u64());

        crate::log::info!("rtlwifi: MMIO base at {:#x}", mmio_base.as_u64());

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

        let tx_ring_size = TX_RING_SIZE * core::mem::size_of::<RtlTxDesc>();
        let rx_ring_size = RX_RING_SIZE * core::mem::size_of::<RtlRxDesc>();
        let tx_buf_total = TX_RING_SIZE * TX_BUFFER_SIZE;
        let rx_buf_total = RX_RING_SIZE * RX_BUFFER_SIZE;

        let constraints = DmaConstraints {
            alignment: DESC_ALIGNMENT,
            max_segment_size: tx_ring_size.max(rx_ring_size),
            dma32_only: true,
            coherent: true,
        };

        let tx_ring_region = alloc_dma_coherent(tx_ring_size, constraints)
            .map_err(|_| WifiError::OutOfMemory)?;
        let rx_ring_region = alloc_dma_coherent(rx_ring_size, constraints)
            .map_err(|_| WifiError::OutOfMemory)?;

        let buf_constraints = DmaConstraints {
            alignment: 4096,
            max_segment_size: tx_buf_total.max(rx_buf_total),
            dma32_only: true,
            coherent: true,
        };

        let tx_buffers_region = alloc_dma_coherent(tx_buf_total, buf_constraints)
            .map_err(|_| WifiError::OutOfMemory)?;
        let rx_buffers_region = alloc_dma_coherent(rx_buf_total, buf_constraints)
            .map_err(|_| WifiError::OutOfMemory)?;

        // SAFETY: Zeroing DMA memory we just allocated
        unsafe {
            ptr::write_bytes(tx_ring_region.virt_addr.as_mut_ptr::<u8>(), 0, tx_ring_size);
            ptr::write_bytes(rx_ring_region.virt_addr.as_mut_ptr::<u8>(), 0, rx_ring_size);
            ptr::write_bytes(tx_buffers_region.virt_addr.as_mut_ptr::<u8>(), 0, tx_buf_total);
            ptr::write_bytes(rx_buffers_region.virt_addr.as_mut_ptr::<u8>(), 0, rx_buf_total);
        }

        let mut dev = Self {
            mmio_base,
            state: WifiState::Uninitialized,
            device_id,
            mac_address: [0; 6],
            current_ssid: None,
            current_bssid: None,
            current_channel: 0,
            current_security: SecurityType::Open,
            rssi: RSSI_INVALID,
            scan_results: Vec::new(),
            tx_ring_phys: tx_ring_region.phys_addr,
            tx_ring_virt: tx_ring_region.virt_addr,
            rx_ring_phys: rx_ring_region.phys_addr,
            rx_ring_virt: rx_ring_region.virt_addr,
            tx_buffers_phys: tx_buffers_region.phys_addr,
            tx_buffers_virt: tx_buffers_region.virt_addr,
            rx_buffers_phys: rx_buffers_region.phys_addr,
            rx_buffers_virt: rx_buffers_region.virt_addr,
            tx_head: 0,
            rx_head: 0,
            firmware_loaded: false,
            pci_device,
        };

        dev.hw_init()?;
        dev.read_mac_address();
        dev.setup_rings();
        dev.state = WifiState::HwReady;

        crate::log::info!(
            "rtlwifi: Device ready, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev.mac_address[0],
            dev.mac_address[1],
            dev.mac_address[2],
            dev.mac_address[3],
            dev.mac_address[4],
            dev.mac_address[5]
        );

        Ok(dev)
    }

    pub(crate) fn read8(&self, offset: u16) -> u8 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u8)
        }
    }

    pub(crate) fn read16(&self, offset: u16) -> u16 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u16)
        }
    }

    pub(crate) fn read32(&self, offset: u16) -> u32 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u32)
        }
    }

    pub(crate) fn write8(&self, offset: u16, value: u8) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u8, value);
        }
    }

    pub(crate) fn write16(&self, offset: u16, value: u16) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u16, value);
        }
    }

    pub(crate) fn write32(&self, offset: u16, value: u32) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u32, value);
        }
    }

    pub(crate) fn delay_us(&self, us: u64) {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        while crate::arch::x86_64::time::tsc::elapsed_us() - start < us {
            core::hint::spin_loop();
        }
    }
}
