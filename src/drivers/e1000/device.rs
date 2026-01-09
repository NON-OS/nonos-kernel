// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::constants::*;
use super::descriptors::{E1000RxDesc, E1000TxDesc};

pub struct E1000Device {
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
    rx_tail: usize,
    tx_descs_phys: PhysAddr,
    tx_descs_virt: VirtAddr,
    tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    tx_tail: usize,
    tx_in_flight: [bool; TX_DESC_COUNT],
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

    fn alloc_desc_ring(count: usize) -> Result<(PhysAddr, VirtAddr), &'static str> {
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

    fn alloc_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
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
    fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        // SAFETY: mmio_base + offset is a valid MMIO register address
        unsafe {
            let addr = (self.mmio_base.as_u64() + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    fn reset(&self) -> bool {
        self.write_reg(reg::CTRL, ctrl::RST);

        let mut reset_complete = false;
        for _ in 0..10000 {
            if self.read_reg(reg::CTRL) & ctrl::RST == 0 {
                reset_complete = true;
                break;
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        if !reset_complete {
            crate::log_warn!("e1000: Reset timeout - hardware may be in unknown state");
        }

        self.write_reg(reg::IMC, 0xFFFFFFFF);
        let _icr = self.read_reg(reg::ICR);

        reset_complete
    }

    fn read_mac_address(&mut self) {
        let ral = self.read_reg(reg::RAL0);
        let rah = self.read_reg(reg::RAH0);

        if ral != 0 || (rah & 0xFFFF) != 0 {
            self.mac_address[0] = (ral & 0xFF) as u8;
            self.mac_address[1] = ((ral >> 8) & 0xFF) as u8;
            self.mac_address[2] = ((ral >> 16) & 0xFF) as u8;
            self.mac_address[3] = ((ral >> 24) & 0xFF) as u8;
            self.mac_address[4] = (rah & 0xFF) as u8;
            self.mac_address[5] = ((rah >> 8) & 0xFF) as u8;
        } else {
            for i in 0..3 {
                let word = self.eeprom_read(i as u8).unwrap_or(0);
                self.mac_address[i * 2] = (word & 0xFF) as u8;
                self.mac_address[i * 2 + 1] = ((word >> 8) & 0xFF) as u8;
            }
            if self.mac_address == [0u8; 6] {
                crate::log_warn!("e1000: Failed to read MAC address from EEPROM, using fallback");
                self.mac_address = [0x02, 0x00, 0x00, 0xE1, 0x00, 0x00];
            }
        }

        let ral_val = (self.mac_address[0] as u32)
            | ((self.mac_address[1] as u32) << 8)
            | ((self.mac_address[2] as u32) << 16)
            | ((self.mac_address[3] as u32) << 24);
        let rah_val = (self.mac_address[4] as u32)
            | ((self.mac_address[5] as u32) << 8)
            | (1 << 31);

        self.write_reg(reg::RAL0, ral_val);
        self.write_reg(reg::RAH0, rah_val);
    }

    fn eeprom_read(&self, addr: u8) -> Option<u16> {
        self.write_reg(reg::EERD, 1 | ((addr as u32) << 8));

        for _ in 0..10000 {
            let val = self.read_reg(reg::EERD);
            if val & (1 << 4) != 0 {
                return Some(((val >> 16) & 0xFFFF) as u16);
            }
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }

        crate::log_warn!("e1000: EEPROM read timeout at address {}", addr);
        None
    }

    fn init_rx(&mut self) {
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();
        for i in 0..RX_DESC_COUNT {
            // SAFETY: rx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *rx_descs.add(i);
                desc.buffer_addr = self.rx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.checksum = 0;
                desc.status = 0;
                desc.errors = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::RDBAL, (self.rx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::RDBAH, (self.rx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::RDLEN, (RX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::RDH, 0);
        self.write_reg(reg::RDT, (RX_DESC_COUNT - 1) as u32);

        self.rx_tail = RX_DESC_COUNT - 1;

        for i in 0..128 {
            self.write_reg(reg::MTA + (i * 4), 0);
        }

        let rctl_val = rctl::EN | rctl::BAM | rctl::BSIZE_2048 | rctl::SECRC;
        self.write_reg(reg::RCTL, rctl_val);
    }

    fn init_tx(&mut self) {
        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();
        for i in 0..TX_DESC_COUNT {
            // SAFETY: tx_descs points to valid descriptor ring memory
            unsafe {
                let desc = &mut *tx_descs.add(i);
                desc.buffer_addr = self.tx_buffers_phys[i].as_u64();
                desc.length = 0;
                desc.cso = 0;
                desc.cmd = 0;
                desc.status = 1;
                desc.css = 0;
                desc.special = 0;
            }
        }

        self.write_reg(reg::TDBAL, (self.tx_descs_phys.as_u64() & 0xFFFFFFFF) as u32);
        self.write_reg(reg::TDBAH, (self.tx_descs_phys.as_u64() >> 32) as u32);
        self.write_reg(reg::TDLEN, (TX_DESC_COUNT * 16) as u32);
        self.write_reg(reg::TDH, 0);
        self.write_reg(reg::TDT, 0);

        self.tx_tail = 0;

        self.write_reg(reg::TIPG, DEFAULT_TIPG);

        let tctl_val = tctl::EN
            | tctl::PSP
            | (DEFAULT_COLLISION_THRESHOLD << tctl::CT_SHIFT)
            | (DEFAULT_COLLISION_DISTANCE << tctl::COLD_SHIFT)
            | tctl::RTLC;
        self.write_reg(reg::TCTL, tctl_val);
    }

    fn enable_interrupts(&self) {
        self.write_reg(reg::IMS, int::TXDW | int::LSC | int::RXT0 | int::RXDMT0);
    }

    pub fn update_link_status(&mut self) {
        let status_val = self.read_reg(reg::STATUS);
        self.link_up = (status_val & status::LU) != 0;
        self.full_duplex = (status_val & status::FD) != 0;
        self.link_speed = match status_val & status::SPEED_MASK {
            status::SPEED_10 => 10,
            status::SPEED_100 => 100,
            status::SPEED_1000 => 1000,
            _ => 0,
        };

        let ctrl_val = self.read_reg(reg::CTRL);
        self.write_reg(reg::CTRL, ctrl_val | ctrl::SLU | ctrl::ASDE);
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > BUFFER_SIZE {
            return Err("Packet too large");
        }
        if data.len() < MIN_FRAME_SIZE {
            return Err("Packet too small");
        }

        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();
        let desc_idx = self.tx_tail;

        // SAFETY: tx_descs and tx_buffers_virt point to valid DMA memory
        unsafe {
            let desc = &mut *tx_descs.add(desc_idx);

            if desc.status & 0x01 == 0 {
                return Err("TX ring full");
            }

            let buf_ptr = self.tx_buffers_virt[desc_idx].as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());

            desc.length = data.len() as u16;
            desc.cso = 0;
            desc.cmd = tx_cmd::EOP | tx_cmd::IFCS | tx_cmd::RS;
            desc.status = 0;
            desc.css = 0;
            desc.special = 0;
        }

        self.tx_in_flight[desc_idx] = true;

        self.tx_tail = (self.tx_tail + 1) % TX_DESC_COUNT;
        self.write_reg(reg::TDT, self.tx_tail as u32);

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let rx_descs = self.rx_descs_virt.as_mut_ptr::<E1000RxDesc>();

        loop {
            let desc_idx = (self.rx_tail + 1) % RX_DESC_COUNT;

            // SAFETY: rx_descs and rx_buffers_virt point to valid DMA memory
            unsafe {
                let desc = &mut *rx_descs.add(desc_idx);

                if !desc.is_done() {
                    break;
                }

                if desc.has_error() {
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                } else if desc.is_eop() && desc.length > 0 {
                    let len = desc.length as usize;
                    if len > BUFFER_SIZE {
                        crate::log_warn!("e1000: RX packet length {} exceeds buffer size", len);
                        self.rx_errors.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let buf_ptr = self.rx_buffers_virt[desc_idx].as_ptr::<u8>();
                        let mut packet = Vec::with_capacity(len);
                        packet.extend_from_slice(core::slice::from_raw_parts(buf_ptr, len));
                        packets.push(packet);

                        self.rx_packets.fetch_add(1, Ordering::Relaxed);
                        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                }

                desc.reset();
            }

            self.rx_tail = desc_idx;
            self.write_reg(reg::RDT, self.rx_tail as u32);
        }

        packets
    }

    pub fn handle_interrupt(&mut self) {
        let icr = self.read_reg(reg::ICR);

        if icr & int::LSC != 0 {
            self.update_link_status();
            if self.link_up {
                crate::log::info!("e1000: Link UP {}Mbps", self.link_speed);
            } else {
                crate::log::info!("e1000: Link DOWN");
            }
        }

        if icr & int::RXT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::RXDMT0 != 0 {
            let _packets = self.receive();
        }

        if icr & int::TXDW != 0 {
            self.reclaim_tx();
        }
    }

    pub fn reclaim_tx(&mut self) {
        let tx_descs = self.tx_descs_virt.as_mut_ptr::<E1000TxDesc>();

        for i in 0..TX_DESC_COUNT {
            if self.tx_in_flight[i] {
                // SAFETY: tx_descs points to valid descriptor ring memory
                unsafe {
                    let desc = &*tx_descs.add(i);
                    if desc.is_done() {
                        if desc.has_error() {
                            self.tx_errors.fetch_add(1, Ordering::Relaxed);
                            if desc.had_excess_collisions() {
                                crate::log_warn!("e1000: TX excess collisions on descriptor {}", i);
                            }
                            if desc.had_late_collision() {
                                crate::log_warn!("e1000: TX late collision on descriptor {}", i);
                            }
                        }
                        self.tx_in_flight[i] = false;
                    }
                }
            }
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
}
