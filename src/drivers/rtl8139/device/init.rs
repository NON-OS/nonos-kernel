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

use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciBar, PciDevice};

use super::super::constants::*;
use super::super::io::{inb, inl, inw, outb, outl, outw};
use super::core::Rtl8139Device;

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
}
