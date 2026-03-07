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
    /// Create a VirtIO-RNG device from a raw BAR0 value.
    ///
    /// BAR0 bit 0 determines the access mode:
    ///   - bit 0 set   → I/O port (bits [31:2] = base port)
    ///   - bit 0 clear → MMIO (bits [31:4] = base address)
    pub(super) fn from_bar0(bar0: u32) -> Result<Self, &'static str> {
        if bar0 == 0 {
            return Err("virtio-rng: BAR0 is zero");
        }

        let access = if bar0 & 1 != 0 {
            // I/O port: mask off the type bit
            let port = (bar0 & 0xFFFC) as u16;
            AccessMode::Io(port)
        } else {
            // MMIO: mask off the type and size bits
            let addr = (bar0 & 0xFFFFFFF0) as u64;
            AccessMode::Mmio(addr)
        };

        let queue = RngQueue::new()?;
        let mut dev = Self { access, queue };

        dev.init_legacy()?;
        Ok(dev)
    }

    fn init_legacy(&mut self) -> Result<(), &'static str> {
        // Reset the device
        self.write8(LEG_STATUS, 0);
        self.write8(LEG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);

        let cur = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, cur | VIRTIO_STATUS_DRIVER);

        let host_features = self.read32(LEG_HOST_FEATURES);
        let _ = host_features; // RNG device has no guest-relevant features
        self.write32(LEG_GUEST_FEATURES, 0);

        let c2 = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, c2 | VIRTIO_STATUS_FEATURES_OK);

        self.write16(LEG_QUEUE_SEL, 0);

        let qmax = self.read16(LEG_QUEUE_NUM);
        if qmax == 0 {
            return Err("virtio-rng: queue not available");
        }

        // Program the PFN — points to the base of the contiguous virtqueue region
        // which contains desc, avail, and used rings at spec-defined offsets.
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

        let final_status = self.read8(LEG_STATUS);
        if final_status & VIRTIO_STATUS_DRIVER_OK == 0 {
            return Err("virtio-rng: device rejected DRIVER_OK");
        }

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
                // SAFETY: Port I/O read from VirtIO device BAR0 I/O space.
                // The port was obtained from a validated PCI BAR during device probe.
                unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO read from VirtIO device BAR0 memory space.
                // The base address was obtained from a validated PCI BAR.
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u8) }
            }
        }
    }

    #[inline]
    fn write8(&self, offset: u16, val: u8) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                // SAFETY: Port I/O write to VirtIO device BAR0 I/O space.
                unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO write to VirtIO device BAR0 memory space.
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
                // SAFETY: Port I/O read from VirtIO device BAR0 I/O space.
                unsafe { core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO read from VirtIO device BAR0 memory space.
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u16) }
            }
        }
    }

    #[inline]
    fn write16(&self, offset: u16, val: u16) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                // SAFETY: Port I/O write to VirtIO device BAR0 I/O space.
                unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO write to VirtIO device BAR0 memory space.
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
                // SAFETY: Port I/O read from VirtIO device BAR0 I/O space.
                unsafe { core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags)); }
                val
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO read from VirtIO device BAR0 memory space.
                unsafe { ptr::read_volatile((*base + offset as u64) as *const u32) }
            }
        }
    }

    #[inline]
    fn write32(&self, offset: u16, val: u32) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                // SAFETY: Port I/O write to VirtIO device BAR0 I/O space.
                unsafe { core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags)); }
            }
            AccessMode::Mmio(base) => {
                // SAFETY: MMIO write to VirtIO device BAR0 memory space.
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── VirtIO status bits (VirtIO 1.0 §2.1) ────────────────────────────

    #[test]
    fn test_status_acknowledge() {
        assert_eq!(VIRTIO_STATUS_ACKNOWLEDGE, 1);
    }

    #[test]
    fn test_status_driver() {
        assert_eq!(VIRTIO_STATUS_DRIVER, 2);
    }

    #[test]
    fn test_status_driver_ok() {
        assert_eq!(VIRTIO_STATUS_DRIVER_OK, 4);
    }

    #[test]
    fn test_status_features_ok() {
        assert_eq!(VIRTIO_STATUS_FEATURES_OK, 8);
    }

    #[test]
    fn test_status_bits_are_distinct() {
        let all = [
            VIRTIO_STATUS_ACKNOWLEDGE,
            VIRTIO_STATUS_DRIVER,
            VIRTIO_STATUS_DRIVER_OK,
            VIRTIO_STATUS_FEATURES_OK,
        ];
        for (i, &a) in all.iter().enumerate() {
            assert!(a.is_power_of_two(), "status bit {i} must be a power of 2");
            for &b in &all[i + 1..] {
                assert_ne!(a, b, "status bits must be distinct");
            }
        }
    }

    #[test]
    fn test_full_init_status() {
        // After full init, device status should have ACK | DRIVER | FEATURES_OK | DRIVER_OK = 0x0F
        let expected = VIRTIO_STATUS_ACKNOWLEDGE
            | VIRTIO_STATUS_DRIVER
            | VIRTIO_STATUS_FEATURES_OK
            | VIRTIO_STATUS_DRIVER_OK;
        assert_eq!(expected, 0x0F);
    }

    // ── Legacy register offsets (VirtIO §4.1.4.8) ────────────────────────

    #[test]
    fn test_register_offsets() {
        assert_eq!(LEG_HOST_FEATURES, 0x00);
        assert_eq!(LEG_GUEST_FEATURES, 0x04);
        assert_eq!(LEG_QUEUE_PFN, 0x08);
        assert_eq!(LEG_QUEUE_NUM, 0x0C);
        assert_eq!(LEG_QUEUE_SEL, 0x0E);
        assert_eq!(LEG_NOTIFY, 0x10);
        assert_eq!(LEG_STATUS, 0x12);
    }

    #[test]
    fn test_register_offsets_non_overlapping() {
        let offsets = [
            ("HOST_FEATURES", LEG_HOST_FEATURES, 4u16),
            ("GUEST_FEATURES", LEG_GUEST_FEATURES, 4),
            ("QUEUE_PFN", LEG_QUEUE_PFN, 4),
            ("QUEUE_NUM", LEG_QUEUE_NUM, 2),
            ("QUEUE_SEL", LEG_QUEUE_SEL, 2),
            ("NOTIFY", LEG_NOTIFY, 2),
            ("STATUS", LEG_STATUS, 1),
        ];
        for (i, &(name_a, off_a, sz_a)) in offsets.iter().enumerate() {
            for &(name_b, off_b, _) in &offsets[i + 1..] {
                assert!(
                    off_a + sz_a <= off_b,
                    "{name_a} (0x{off_a:02X}+{sz_a}) overlaps {name_b} (0x{off_b:02X})"
                );
            }
        }
    }

    // ── BAR0 parsing ─────────────────────────────────────────────────────

    #[test]
    fn test_bar0_zero_is_error() {
        let result = VirtioRngDevice::from_bar0(0);
        match result {
            Err(msg) => assert_eq!(msg, "virtio-rng: BAR0 is zero"),
            Ok(_) => panic!("expected Err for BAR0 = 0"),
        }
    }

    #[test]
    fn test_bar0_io_port_detection() {
        // BAR0 = 0x60A1 → bit 0 set → I/O port mode, port = 0x60A0
        let bar0: u32 = 0x60A1;
        assert_eq!(bar0 & 1, 1, "bit 0 should indicate I/O port");
        let port = (bar0 & 0xFFFC) as u16;
        assert_eq!(port, 0x60A0);
    }

    #[test]
    fn test_bar0_mmio_detection() {
        // BAR0 = 0xFEBF_1000 → bit 0 clear → MMIO mode
        let bar0: u32 = 0xFEBF_1000;
        assert_eq!(bar0 & 1, 0, "bit 0 should be clear for MMIO");
        let addr = (bar0 & 0xFFFFFFF0) as u64;
        assert_eq!(addr, 0xFEBF_1000);
    }

    #[test]
    fn test_bar0_io_port_mask() {
        // Various I/O port BAR values — mask bits [1:0]
        for bar0 in [0x0001u32, 0xC041, 0xFF01, 0x60A1] {
            assert_eq!(bar0 & 1, 1);
            let port = (bar0 & 0xFFFC) as u16;
            assert_eq!(port & 0x3, 0, "I/O port must be 4-byte aligned after masking");
        }
    }

    #[test]
    fn test_bar0_mmio_mask() {
        // Various MMIO BAR values — mask bits [3:0]
        for bar0 in [0x1000_0000u32, 0xFEBF_1000, 0x8000_0000] {
            assert_eq!(bar0 & 1, 0);
            let addr = bar0 & 0xFFFFFFF0;
            assert_eq!(addr & 0xF, 0, "MMIO address must be 16-byte aligned after masking");
        }
    }
}
