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
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::core::Rtl8139Device;
use crate::drivers::rtl8139::constants::{cmd, reg};
use crate::drivers::rtl8139::constants::{RX_BUFFER_SIZE, TX_BUFFER_SIZE, TX_DESC_COUNT};
use crate::drivers::rtl8139::io::{inb, outb};

impl Rtl8139Device {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        let bar0 = pci_device.get_bar(0).ok_or("RTL8139: BAR0 not present")?;
        let io_base = match bar0 {
            PciBar::Io { port, .. } => *port,
            _ => return Err("RTL8139: BAR0 is not I/O"),
        };

        crate::log::info!("rtl8139: I/O region configured successfully");

        let cmd_reg =
            pci_read_config32(pci_device.bus, pci_device.device, pci_device.function, 0x04);
        pci_write_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x04,
            cmd_reg | 0x05,
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

    pub(super) fn reset(&self) -> Result<(), &'static str> {
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
}
