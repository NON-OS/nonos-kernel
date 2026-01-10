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

use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciBar, PciDevice};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::constants::*;
use super::io::{inb, inl, inw, outb, outl, outw};

pub struct Rtl8139Device {
    pub pci_device: PciDevice,
    io_base: u16,
    pub mac_address: [u8; 6],
    pub link_up: bool,
    pub link_speed: u16,
    rx_buffer_phys: PhysAddr,
    rx_buffer_virt: VirtAddr,
    rx_offset: u16,
    tx_buffers_phys: [PhysAddr; TX_DESC_COUNT],
    tx_buffers_virt: [VirtAddr; TX_DESC_COUNT],
    tx_cur: usize,
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
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        let bar0 = pci_device.get_bar(0).ok_or("RTL8139: BAR0 not present")?;
        let io_base = match bar0 {
            PciBar::Io { port, .. } => *port,
            _ => return Err("RTL8139: BAR0 is not I/O"),
        };

        crate::log::info!("rtl8139: I/O base at {:#x}", io_base);

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
            cmd | 0x05,
        );

        let (rx_buffer_phys, rx_buffer_virt) = Self::alloc_rx_buffer()?;

        let mut tx_buffers_phys = [PhysAddr::zero(); TX_DESC_COUNT];
        let mut tx_buffers_virt = [VirtAddr::zero(); TX_DESC_COUNT];

        for i in 0..TX_DESC_COUNT {
            let (phys, virt) = Self::alloc_tx_buffer()?;
            tx_buffers_phys[i] = phys;
            tx_buffers_virt[i] = virt;
        }

        let mut dev = Self {
            pci_device,
            io_base,
            mac_address: [0; 6],
            link_up: false,
            link_speed: 0,
            rx_buffer_phys,
            rx_buffer_virt,
            rx_offset: 0,
            tx_buffers_phys,
            tx_buffers_virt,
            tx_cur: 0,
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        };

        dev.reset()?;
        dev.read_mac_address();
        dev.init_rx();
        dev.init_tx();
        dev.enable_transceiver();
        dev.enable_interrupts();
        dev.update_link_status();

        crate::log::info!(
            "rtl8139: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dev.mac_address[0],
            dev.mac_address[1],
            dev.mac_address[2],
            dev.mac_address[3],
            dev.mac_address[4],
            dev.mac_address[5]
        );

        if dev.link_up {
            crate::log::info!("rtl8139: Link UP {}Mbps", dev.link_speed);
        } else {
            crate::log::info!("rtl8139: Link DOWN");
        }

        Ok(dev)
    }

    fn alloc_rx_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
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

    fn alloc_tx_buffer() -> Result<(PhysAddr, VirtAddr), &'static str> {
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

    fn reset(&self) -> Result<(), &'static str> {
        outb(self.io_base + reg::CONFIG1, 0);
        outb(self.io_base + reg::CR, cmd::RST);

        for _ in 0..10000 {
            if inb(self.io_base + reg::CR) & cmd::RST == 0 {
                return Ok(());
            }
            for _ in 0..1000 {
                core::hint::spin_loop();
            }
        }

        crate::log_warn!("rtl8139: reset timeout");
        Err("RTL8139: reset timeout")
    }

    fn read_mac_address(&mut self) {
        let mac0 = inl(self.io_base + reg::IDR0);
        let mac4 = inw(self.io_base + reg::IDR4);

        self.mac_address[0] = (mac0 & 0xFF) as u8;
        self.mac_address[1] = ((mac0 >> 8) & 0xFF) as u8;
        self.mac_address[2] = ((mac0 >> 16) & 0xFF) as u8;
        self.mac_address[3] = ((mac0 >> 24) & 0xFF) as u8;
        self.mac_address[4] = (mac4 & 0xFF) as u8;
        self.mac_address[5] = ((mac4 >> 8) & 0xFF) as u8;
    }

    fn init_rx(&self) {
        outl(
            self.io_base + reg::RBSTART,
            self.rx_buffer_phys.as_u64() as u32,
        );

        let rcr_val = rcr::AB | rcr::AM | rcr::APM | rcr::RBLEN_8K | rcr::WRAP;
        outl(self.io_base + reg::RCR, rcr_val);

        outw(self.io_base + reg::CAPR, 0xFFF0);
    }

    fn init_tx(&self) {
        outl(
            self.io_base + reg::TSAD0,
            self.tx_buffers_phys[0].as_u64() as u32,
        );
        outl(
            self.io_base + reg::TSAD1,
            self.tx_buffers_phys[1].as_u64() as u32,
        );
        outl(
            self.io_base + reg::TSAD2,
            self.tx_buffers_phys[2].as_u64() as u32,
        );
        outl(
            self.io_base + reg::TSAD3,
            self.tx_buffers_phys[3].as_u64() as u32,
        );

        let tcr_val = tcr::MXDMA_256 | tcr::IFG_STD;
        outl(self.io_base + reg::TCR, tcr_val);
    }

    fn enable_transceiver(&self) {
        outb(self.io_base + reg::CR, cmd::TE | cmd::RE);
    }

    fn enable_interrupts(&self) {
        outw(
            self.io_base + reg::IMR,
            int::ROK | int::TOK | int::RER | int::TER | int::RXOVW | int::FOVW | int::PUN,
        );
    }

    pub fn update_link_status(&mut self) {
        let msr_val = inb(self.io_base + reg::MSR);
        self.link_up = (msr_val & msr::LINKB) == 0;
        self.link_speed = if msr_val & msr::SPEED10 != 0 {
            10
        } else {
            100
        };
    }

    pub fn transmit(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > TX_BUFFER_SIZE {
            return Err("Packet too large");
        }
        if data.len() < MIN_FRAME_SIZE {
            return Err("Packet too small");
        }

        let desc = self.tx_cur;
        let tsd_reg = match desc {
            0 => reg::TSD0,
            1 => reg::TSD1,
            2 => reg::TSD2,
            3 => reg::TSD3,
            _ => return Err("Invalid TX descriptor"),
        };

        let tsd_val = inl(self.io_base + tsd_reg);
        if tsd_val & tsd::OWN != 0 {
            return Err("TX descriptor busy");
        }

        // SAFETY: tx_buffers_virt[desc] points to valid DMA memory of TX_BUFFER_SIZE bytes
        unsafe {
            let buf_ptr = self.tx_buffers_virt[desc].as_mut_ptr::<u8>();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());
        }

        let new_tsd = (data.len() as u32) & 0x1FFF;
        outl(self.io_base + tsd_reg, new_tsd);

        self.tx_cur = (self.tx_cur + 1) % TX_DESC_COUNT;

        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn receive(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        let cr = inb(self.io_base + reg::CR);
        if cr & cmd::BUFE != 0 {
            return packets;
        }

        let rx_buf = self.rx_buffer_virt.as_ptr::<u8>();

        loop {
            let header_offset = self.rx_offset as usize;

            if header_offset >= RX_BUFFER_SIZE - 4 {
                break;
            }

            // SAFETY: rx_buf points to valid DMA memory, header_offset is bounds-checked
            unsafe {
                let header = core::ptr::read_volatile(rx_buf.add(header_offset) as *const u32);
                let status = (header & 0xFFFF) as u16;
                let length = ((header >> 16) & 0xFFFF) as u16;

                if status & 0x0001 == 0 {
                    if status == 0 {
                        break;
                    }
                    self.rx_errors.fetch_add(1, Ordering::Relaxed);
                    self.rx_offset = (self.rx_offset + length + 4 + 3) & !3;
                    continue;
                }

                if length < 8 || length > 1518 + 4 {
                    break;
                }

                let data_offset = (header_offset + 4) % (RX_BUFFER_SIZE - 16);
                let data_len = (length - 4) as usize;

                let mut packet = Vec::with_capacity(data_len);
                packet.set_len(data_len);

                let first_part = (RX_BUFFER_SIZE - 16 - data_offset).min(data_len);
                core::ptr::copy_nonoverlapping(
                    rx_buf.add(data_offset),
                    packet.as_mut_ptr(),
                    first_part,
                );

                if first_part < data_len {
                    core::ptr::copy_nonoverlapping(
                        rx_buf,
                        packet.as_mut_ptr().add(first_part),
                        data_len - first_part,
                    );
                }

                packets.push(packet);

                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(data_len as u64, Ordering::Relaxed);

                self.rx_offset =
                    ((self.rx_offset + length + 4 + 3) & !3) % (RX_BUFFER_SIZE as u16 - 16);

                outw(self.io_base + reg::CAPR, self.rx_offset.wrapping_sub(0x10));
            }

            if packets.len() >= 32 {
                break;
            }
        }

        packets
    }

    pub fn handle_interrupt(&mut self) {
        let isr = inw(self.io_base + reg::ISR);

        outw(self.io_base + reg::ISR, isr);

        if isr & int::RER != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
        }
        if isr & int::TER != 0 {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
        }
        if isr & int::RXOVW != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            crate::log_warn!("rtl8139: RX buffer overflow");
        }
        if isr & int::FOVW != 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            crate::log_warn!("rtl8139: RX FIFO overflow");
        }
        if isr & int::PUN != 0 {
            self.update_link_status();
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
