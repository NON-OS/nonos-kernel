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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{PhysAddr, VirtAddr};

use super::constants::{reg, cmd, rcr, tcr, int, desc_status, tx_desc};
use super::constants::{RX_DESC_COUNT, TX_DESC_COUNT, RX_BUFFER_SIZE, TX_BUFFER_SIZE, MAX_MTU};
use super::descriptors::{Rtl8168RxDesc, Rtl8168TxDesc};
use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

const DESC_ALIGNMENT: usize = 256;

pub struct Rtl8168Device {
    pub pci_device: PciDevice,
    mmio_base: VirtAddr,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    pub full_duplex: bool,
    rx_descs_phys: PhysAddr,
    rx_descs_virt: VirtAddr,
    rx_buffers_phys: [PhysAddr; RX_DESC_COUNT],
    rx_buffers_virt: [VirtAddr; RX_DESC_COUNT],
    rx_index: usize,
    tx_descs_phys: PhysAddr,
    tx_descs_virt: VirtAddr,
    tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    tx_index: usize,
    tx_clean: usize,
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

    fn alloc_desc_ring(count: usize) -> Result<(PhysAddr, VirtAddr), &'static str> {
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

    fn alloc_buffer(size: usize) -> Result<(PhysAddr, VirtAddr), &'static str> {
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

    fn software_reset(&mut self) -> Result<(), &'static str> {
        self.write8(reg::CR, cmd::RST);

        for _ in 0..1000 {
            if (self.read8(reg::CR) & cmd::RST) == 0 {
                return Ok(());
            }
            self.spin_delay(10);
        }

        Err("RTL8168: Reset timeout")
    }

    fn read_mac_address(&mut self) {
        let mac0 = self.read32(reg::MAC0);
        let mac4 = self.read32(reg::MAC4);

        self.mac_address[0] = mac0 as u8;
        self.mac_address[1] = (mac0 >> 8) as u8;
        self.mac_address[2] = (mac0 >> 16) as u8;
        self.mac_address[3] = (mac0 >> 24) as u8;
        self.mac_address[4] = mac4 as u8;
        self.mac_address[5] = (mac4 >> 8) as u8;
    }

    fn init_rx(&mut self) {
        let descs = self.rx_descs_virt.as_mut_ptr::<Rtl8168RxDesc>();

        for i in 0..RX_DESC_COUNT {
            let phys = self.rx_buffers_phys[i];
            let is_last = i == RX_DESC_COUNT - 1;

            unsafe {
                let desc = &*descs.add(i);
                let mut opts1 = (RX_BUFFER_SIZE as u32) & 0x3FFF;
                opts1 |= desc_status::OWN;
                if is_last {
                    opts1 |= desc_status::EOR;
                }
                desc.addr_low.store(phys.as_u64() as u32, Ordering::Release);
                desc.addr_high.store((phys.as_u64() >> 32) as u32, Ordering::Release);
                desc.opts2.store(0, Ordering::Release);
                desc.opts1.store(opts1, Ordering::Release);
            }
        }

        self.write32(reg::RDSAR_LOW, self.rx_descs_phys.as_u64() as u32);
        self.write32(reg::RDSAR_HIGH, (self.rx_descs_phys.as_u64() >> 32) as u32);

        self.write32(
            reg::RCR,
            rcr::AAP | rcr::APM | rcr::AM | rcr::AB | rcr::RXFTH_NONE | rcr::MXDMA_UNLIM,
        );

        self.write16(reg::RMS, RX_BUFFER_SIZE as u16);
    }

    fn init_tx(&mut self) {
        let descs = self.tx_descs_virt.as_mut_ptr::<Rtl8168TxDesc>();

        for i in 0..TX_DESC_COUNT {
            let phys = self.tx_buffers_phys[i];
            let is_last = i == TX_DESC_COUNT - 1;

            unsafe {
                let desc = &*descs.add(i);
                desc.addr_low.store(phys.as_u64() as u32, Ordering::Release);
                desc.addr_high.store((phys.as_u64() >> 32) as u32, Ordering::Release);
                desc.opts2.store(0, Ordering::Release);
                let opts1 = if is_last { tx_desc::EOR } else { 0 };
                desc.opts1.store(opts1, Ordering::Release);
            }
        }

        self.write32(reg::TNPDS_LOW, self.tx_descs_phys.as_u64() as u32);
        self.write32(reg::TNPDS_HIGH, (self.tx_descs_phys.as_u64() >> 32) as u32);

        self.write32(reg::TCR, tcr::IFG_STD | tcr::MXDMA_UNLIM);

        self.write8(reg::MTPS, (TX_BUFFER_SIZE / 128) as u8);
    }

    fn enable_interrupts(&mut self) {
        self.write16(
            reg::IMR,
            int::ROK | int::RER | int::TOK | int::TER | int::RDU | int::LINK_CHG | int::TDU,
        );
    }

    fn enable_rx_tx(&mut self) {
        let cr = self.read8(reg::CR);
        self.write8(reg::CR, cr | cmd::RE | cmd::TE);
    }

    pub fn update_link_status(&mut self) {
        let status = self.read8(reg::PHY_STATUS);

        self.link_up = (status & 0x02) != 0;

        if self.link_up {
            let speed_bits = status & 0x30;
            self.link_speed = match speed_bits {
                0x00 => 10,
                0x10 => 100,
                0x20 => 1000,
                _ => 0,
            };
            self.full_duplex = (status & 0x01) != 0;
        } else {
            self.link_speed = 0;
            self.full_duplex = false;
        }
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > MAX_MTU + 14 {
            return Err("Packet too large");
        }

        let descs = self.tx_descs_virt.as_ptr::<Rtl8168TxDesc>();

        unsafe {
            let desc = &*descs.add(self.tx_index);
            if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                self.reclaim_tx();
                if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                    return Err("TX ring full");
                }
            }
        }

        let buf_virt = self.tx_buffers_virt[self.tx_index];
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_virt.as_mut_ptr(), data.len());
        }

        let is_last_ring = self.tx_index == TX_DESC_COUNT - 1;
        unsafe {
            let desc = &*descs.add(self.tx_index);
            let mut opts1 = (data.len() as u32) & 0xFFFF;
            opts1 |= tx_desc::OWN | tx_desc::FS | tx_desc::LS;
            if is_last_ring {
                opts1 |= tx_desc::EOR;
            }
            desc.opts2.store(0, Ordering::Release);
            desc.opts1.store(opts1, Ordering::Release);
        }

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        self.tx_index = (self.tx_index + 1) % TX_DESC_COUNT;

        self.write8(reg::TPP, 0x40);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let descs = self.rx_descs_virt.as_ptr::<Rtl8168RxDesc>();

        for _ in 0..RX_DESC_COUNT {
            unsafe {
                let desc = &*descs.add(self.rx_index);
                let opts1 = desc.opts1.load(Ordering::Acquire);

                if (opts1 & desc_status::OWN) != 0 {
                    break;
                }

                if (opts1 & 0x00200000) != 0 {
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    let length = (opts1 & 0x3FFF) as usize;
                    if length >= 14 && length <= RX_BUFFER_SIZE {
                        let buf_virt = self.rx_buffers_virt[self.rx_index];
                        let mut packet = alloc::vec![0u8; length];
                        core::ptr::copy_nonoverlapping(
                            buf_virt.as_ptr(),
                            packet.as_mut_ptr(),
                            length,
                        );
                        packets.push(packet);
                        self.rx_packets.fetch_add(1, Ordering::Relaxed);
                        self.rx_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    }
                }

                let is_last = self.rx_index == RX_DESC_COUNT - 1;
                let mut new_opts1 = (RX_BUFFER_SIZE as u32) & 0x3FFF;
                new_opts1 |= desc_status::OWN;
                if is_last {
                    new_opts1 |= desc_status::EOR;
                }
                desc.opts2.store(0, Ordering::Release);
                desc.opts1.store(new_opts1, Ordering::Release);

                self.rx_index = (self.rx_index + 1) % RX_DESC_COUNT;
            }
        }

        packets
    }

    pub fn reclaim_tx(&mut self) {
        let descs = self.tx_descs_virt.as_ptr::<Rtl8168TxDesc>();

        while self.tx_clean != self.tx_index {
            unsafe {
                let desc = &*descs.add(self.tx_clean);
                if (desc.opts1.load(Ordering::Acquire) & tx_desc::OWN) != 0 {
                    break;
                }
                let is_last = self.tx_clean == TX_DESC_COUNT - 1;
                let opts1 = if is_last { tx_desc::EOR } else { 0 };
                desc.opts1.store(opts1, Ordering::Release);
            }
            self.tx_clean = (self.tx_clean + 1) % TX_DESC_COUNT;
        }
    }

    pub fn handle_interrupt(&mut self) {
        let isr = self.read16(reg::ISR);
        self.write16(reg::ISR, isr);

        if (isr & int::LINK_CHG) != 0 {
            self.update_link_status();
        }

        if (isr & (int::TOK | int::TER | int::TDU)) != 0 {
            self.reclaim_tx();
        }

        if (isr & int::TER) != 0 {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
        }

        if (isr & int::RER) != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_rx_stats(&self) -> (u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.rx_errors.load(Ordering::Relaxed),
        )
    }

    pub fn get_tx_stats(&self) -> (u64, u64, u64) {
        (
            self.tx_packets.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.tx_errors.load(Ordering::Relaxed),
        )
    }

    fn read8(&self, offset: u16) -> u8 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u8) }
    }

    fn read16(&self, offset: u16) -> u16 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u16) }
    }

    fn read32(&self, offset: u16) -> u32 {
        unsafe { core::ptr::read_volatile((self.mmio_base.as_u64() + offset as u64) as *const u32) }
    }

    fn write8(&self, offset: u16, value: u8) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u8, value) }
    }

    fn write16(&self, offset: u16, value: u16) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u16, value) }
    }

    fn write32(&self, offset: u16, value: u32) {
        unsafe { core::ptr::write_volatile((self.mmio_base.as_u64() + offset as u64) as *mut u32, value) }
    }

    fn spin_delay(&self, us: u64) {
        let start = crate::arch::x86_64::time::tsc::elapsed_us();
        while crate::arch::x86_64::time::tsc::elapsed_us() - start < us {
            core::hint::spin_loop();
        }
    }
}
