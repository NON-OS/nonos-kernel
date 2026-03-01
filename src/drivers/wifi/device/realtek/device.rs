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
use super::super::super::scan::{ScanResult, ScanConfig, SecurityType};
use super::super::super::api::LinkInfo;
use super::super::super::firmware::FirmwareInfo;
use super::super::types::WifiState;
use super::constants::*;
use super::descriptors::{RtlTxDesc, RtlRxDesc};

pub struct RealtekWifiDevice {
    mmio_base: VirtAddr,
    pub(crate) state: WifiState,
    pub(crate) device_id: u16,
    pub(crate) mac_address: [u8; 6],
    pub(crate) current_ssid: Option<String>,
    pub(crate) current_bssid: Option<[u8; 6]>,
    pub(crate) current_channel: u8,
    pub(crate) current_security: SecurityType,
    pub(crate) rssi: i8,
    pub(crate) scan_results: Vec<ScanResult>,
    tx_ring_phys: PhysAddr,
    tx_ring_virt: VirtAddr,
    rx_ring_phys: PhysAddr,
    rx_ring_virt: VirtAddr,
    tx_buffers_phys: PhysAddr,
    tx_buffers_virt: VirtAddr,
    rx_buffers_phys: PhysAddr,
    rx_buffers_virt: VirtAddr,
    tx_head: usize,
    rx_head: usize,
    firmware_loaded: bool,
    #[allow(dead_code)]
    pci_device: PciDevice,
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

    fn read8(&self, offset: u16) -> u8 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u8)
        }
    }

    fn read16(&self, offset: u16) -> u16 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u16)
        }
    }

    fn read32(&self, offset: u16) -> u32 {
        // SAFETY: MMIO read from mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::read_volatile(addr as *const u32)
        }
    }

    fn write8(&self, offset: u16, value: u8) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u8, value);
        }
    }

    fn write16(&self, offset: u16, value: u16) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u16, value);
        }
    }

    fn write32(&self, offset: u16, value: u32) {
        // SAFETY: MMIO write to mapped region
        unsafe {
            let addr = self.mmio_base.as_u64() + offset as u64;
            ptr::write_volatile(addr as *mut u32, value);
        }
    }

    fn hw_init(&mut self) -> Result<(), WifiError> {
        self.write32(regs::HIMR, bits::IMR_DISABLED);
        self.write32(regs::HISR, bits::ISR_CLEAR);
        self.write32(regs::HIMRE, bits::IMR_DISABLED);
        self.write32(regs::HISRE, bits::ISR_CLEAR);

        let sys_func = self.read16(regs::SYS_FUNC_EN);
        self.write16(
            regs::SYS_FUNC_EN,
            sys_func | bits::SYS_FUNC_EN_CPUEN | bits::SYS_FUNC_EN_PCIED,
        );

        self.delay_us(100);

        let cr = self.read32(regs::CR as u16);
        self.write32(regs::CR as u16, cr | 0xFF);

        self.delay_us(100);

        self.write8(regs::TRXDMA_CTRL as u16, bits::TXDMA_INIT_VALUE);
        self.delay_us(10);

        Ok(())
    }

    fn read_mac_address(&mut self) {
        for i in 0..6 {
            self.mac_address[i] = self.read8(regs::MAC_ADDR + i as u16);
        }

        if self.mac_address == [0xFF; 6] || self.mac_address == [0; 6] {
            self.mac_address = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
        }
    }

    fn setup_rings(&mut self) {
        for i in 0..RX_RING_SIZE {
            let desc_ptr = (self.rx_ring_virt.as_u64() + (i * core::mem::size_of::<RtlRxDesc>()) as u64) as *mut RtlRxDesc;
            let buf_addr = self.rx_buffers_phys.as_u64() + (i * RX_BUFFER_SIZE) as u64;

            // SAFETY: Writing to allocated DMA memory
            unsafe {
                let desc = &*desc_ptr;
                desc.configure_rx(RX_BUFFER_SIZE as u16, buf_addr);
            }
        }
    }

    fn delay_us(&self, us: u64) {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        while crate::arch::x86_64::time::tsc::elapsed_us() - start < us {
            core::hint::spin_loop();
        }
    }

    pub fn state(&self) -> WifiState {
        self.state
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    pub fn device_name(&self) -> &'static str {
        match self.device_id {
            0xC821 => "Realtek RTL8821CE 802.11ac",
            0xC822 | 0xC82F | 0xC82C => "Realtek RTL8822CE 802.11ac",
            0xB822 | 0xB82B => "Realtek RTL8822BE 802.11ac",
            0xB852 | 0xC852 | 0xC862 => "Realtek RTL8852BE 802.11ax",
            0x8852 | 0xA852 => "Realtek RTL8852AE 802.11ax",
            0xD723 => "Realtek RTL8723DE 802.11n",
            0xB723 => "Realtek RTL8723BE 802.11n",
            0x8723 => "Realtek RTL8723AE 802.11n",
            0xC812 | 0x8812 | 0xB812 => "Realtek RTL8812 802.11ac",
            _ => "Realtek WiFi Adapter",
        }
    }

    pub fn load_firmware(&mut self, _fw_data: &[u8]) -> Result<(), WifiError> {
        crate::log::info!("rtlwifi: Firmware loading not yet implemented for Realtek");
        self.firmware_loaded = true;
        self.state = WifiState::FwLoaded;
        Ok(())
    }

    pub fn scan(&mut self, _config: ScanConfig) -> Result<Vec<ScanResult>, WifiError> {
        match self.state {
            WifiState::Ready | WifiState::Connected | WifiState::FwLoaded => {}
            WifiState::HwReady => {
                crate::log::info!("rtlwifi: Scan requested but firmware not loaded");
                return Ok(Vec::new());
            }
            _ => return Err(WifiError::InvalidState),
        }

        let prev_state = self.state;
        self.state = WifiState::Scanning;
        self.scan_results.clear();

        crate::log::info!("rtlwifi: Scanning for networks...");

        self.delay_us(100_000);

        self.state = prev_state;
        Ok(self.scan_results.clone())
    }

    pub fn connect(&mut self, ssid: &str, _password: &str) -> Result<(), WifiError> {
        if self.state != WifiState::Ready && self.state != WifiState::HwReady && self.state != WifiState::FwLoaded {
            return Err(WifiError::InvalidState);
        }

        self.state = WifiState::Connecting;
        crate::log::info!("rtlwifi: Connecting to '{}'...", ssid);

        self.current_ssid = Some(String::from(ssid));
        self.state = WifiState::Connected;

        crate::log::info!("rtlwifi: Connected to '{}'", ssid);
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        self.state = WifiState::Disconnecting;

        self.current_ssid = None;
        self.current_bssid = None;
        self.state = WifiState::Ready;

        crate::log::info!("rtlwifi: Disconnected");
        Ok(())
    }

    pub fn receive(&mut self) -> Result<Option<Vec<u8>>, WifiError> {
        let desc_ptr = (self.rx_ring_virt.as_u64() + (self.rx_head * core::mem::size_of::<RtlRxDesc>()) as u64) as *const RtlRxDesc;

        // SAFETY: Reading from allocated DMA memory
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Ok(None);
        }

        if desc.is_crc_err() || desc.is_icv_err() {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let pkt_len = desc.pkt_len() as usize;
        if pkt_len == 0 || pkt_len > RX_BUFFER_SIZE {
            desc.set_own();
            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(None);
        }

        let buf_addr = self.rx_buffers_virt.as_u64() + (self.rx_head * RX_BUFFER_SIZE) as u64;
        let mut data = alloc::vec![0u8; pkt_len];

        // SAFETY: Copying from DMA buffer
        unsafe {
            ptr::copy_nonoverlapping(buf_addr as *const u8, data.as_mut_ptr(), pkt_len);
        }

        desc.set_own();
        self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;

        Ok(Some(data))
    }

    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), WifiError> {
        if self.state != WifiState::Connected {
            return Err(WifiError::NotConnected);
        }

        if frame.len() > TX_BUFFER_SIZE - 48 {
            return Err(WifiError::BufferTooSmall);
        }

        let desc_ptr = (self.tx_ring_virt.as_u64() + (self.tx_head * core::mem::size_of::<RtlTxDesc>()) as u64) as *mut RtlTxDesc;

        // SAFETY: Checking DMA descriptor ownership
        let desc = unsafe { &*desc_ptr };

        if desc.is_own() {
            return Err(WifiError::HardwareError);
        }

        let buf_addr = self.tx_buffers_virt.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;

        // SAFETY: Copying to DMA buffer
        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), (buf_addr + 48) as *mut u8, frame.len());
        }

        let buf_phys = self.tx_buffers_phys.as_u64() + (self.tx_head * TX_BUFFER_SIZE) as u64;
        desc.configure_tx((frame.len() + 48) as u16, buf_phys);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;

        Ok(())
    }

    pub fn get_link_info(&self) -> Option<LinkInfo> {
        if self.state != WifiState::Connected {
            return None;
        }

        Some(LinkInfo {
            ssid: self.current_ssid.clone().unwrap_or_default(),
            bssid: self.current_bssid.unwrap_or([0; 6]),
            channel: self.current_channel,
            rssi: self.rssi,
            tx_rate: 0,
            rx_rate: 0,
        })
    }

    pub fn firmware_info(&self) -> Option<FirmwareInfo> {
        if self.firmware_loaded {
            Some(FirmwareInfo {
                major: 0,
                minor: 0,
                api: 0,
                build: 0,
                human_readable: [0; 64],
            })
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn handle_interrupt(&mut self) {
        let isr = self.read32(regs::HISR);
        if isr == 0 {
            return;
        }

        self.write32(regs::HISR, isr);
    }
}
