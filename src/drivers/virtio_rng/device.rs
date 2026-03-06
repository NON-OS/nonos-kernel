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

use core::ptr;
use crate::drivers::pci::{PciBar, PciDevice};
use super::queue::RngQueue;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;

const LEG_HOST_FEATURES: u16 = 0x00;
const LEG_GUEST_FEATURES: u16 = 0x04;
const LEG_QUEUE_PFN: u16 = 0x08;
const LEG_QUEUE_NUM: u16 = 0x0C;
const LEG_QUEUE_SEL: u16 = 0x0E;
const LEG_NOTIFY: u16 = 0x10;
const LEG_STATUS: u16 = 0x12;

enum AccessMode {
    Io(u16),
    Mmio(u64),
}

pub(super) struct VirtioRngDevice {
    access: AccessMode,
    queue: RngQueue,
}

impl VirtioRngDevice {
    pub(super) fn new(pci_dev: &PciDevice) -> Result<Self, &'static str> {
        let bar = pci_dev.bars.first().ok_or("virtio-rng: no BAR0")?;

        let access = match bar {
            PciBar::Io { port, .. } => AccessMode::Io(*port as u16),
            PciBar::Memory32 { address, .. } => AccessMode::Mmio(address.as_u64()),
            PciBar::Memory64 { address, .. } => AccessMode::Mmio(address.as_u64()),
            PciBar::Memory { address, .. } => AccessMode::Mmio(address.as_u64()),
            _ => return Err("virtio-rng: unsupported BAR type"),
        };

        let mut dev = Self {
            access,
            queue: RngQueue::new()?,
        };

        dev.init_legacy()?;
        Ok(dev)
    }

    fn init_legacy(&mut self) -> Result<(), &'static str> {
        self.write8(LEG_STATUS, 0);
        self.write8(LEG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        let cur = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, cur | VIRTIO_STATUS_DRIVER);

        let _host_features = self.read32(LEG_HOST_FEATURES);
        self.write32(LEG_GUEST_FEATURES, 0);

        let c2 = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, c2 | VIRTIO_STATUS_FEATURES_OK);

        self.write16(LEG_QUEUE_SEL, 0);

        let qmax = self.read16(LEG_QUEUE_NUM);
        if qmax == 0 {
            return Err("virtio-rng: queue not available");
        }

        let queue_phys = self.queue.desc_table_phys();
        let pfn = (queue_phys >> 12) as u32;
        self.write32(LEG_QUEUE_PFN, pfn);

        match &self.access {
            AccessMode::Io(iobase) => {
                self.queue.set_notify_addr(*iobase + LEG_NOTIFY);
            }
            AccessMode::Mmio(mmio_base) => {
                self.queue.set_notify_mmio(*mmio_base + LEG_NOTIFY as u64);
            }
        }

        let s = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, s | VIRTIO_STATUS_DRIVER_OK);

        Ok(())
    }

    pub(super) fn get_random_bytes(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }

        self.queue.request_random(buf.len().min(4096))?;

        let mut timeout = 100_000u32;
        while !self.queue.has_completed() && timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }

        if timeout == 0 {
            return Err("virtio-rng: timeout");
        }

        let received = self.queue.get_received_bytes(buf);
        Ok(received)
    }

    #[inline]
    fn read8(&self, offset: u16) -> u8 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u8;
                unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u8) }
            }
        }
    }

    #[inline]
    fn write8(&self, offset: u16, val: u8) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::write_volatile((*base + offset as u64) as *mut u8, val); }
            }
        }
    }

    #[inline]
    fn read16(&self, offset: u16) -> u16 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u16;
                unsafe { core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u16) }
            }
        }
    }

    #[inline]
    fn write16(&self, offset: u16, val: u16) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::write_volatile((*base + offset as u64) as *mut u16, val); }
            }
        }
    }

    #[inline]
    fn read32(&self, offset: u16) -> u32 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u32;
                unsafe { core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u32) }
            }
        }
    }

    #[inline]
    fn write32(&self, offset: u16, val: u32) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                unsafe { ptr::write_volatile((*base + offset as u64) as *mut u32, val); }
            }
        }
    }
}

impl Drop for VirtioRngDevice {
    fn drop(&mut self) {
        self.write8(LEG_STATUS, 0);
    }
}
