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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::types::{BlockDevice, BlockDeviceType, MAX_BLOCK_DEVICES};

const SERIAL_PORT: u16 = 0x3F8;

#[inline(always)]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Serial port I/O is safe when port is valid
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Serial port I/O is safe when port is valid
    unsafe {
        let value: u8;
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
        value
    }
}

fn serial_write_byte(ch: u8) {
    // SAFETY: Serial port access is safe
    unsafe {
        while (inb(SERIAL_PORT + 5) & 0x20) == 0 {}
        outb(SERIAL_PORT, ch);
    }
}

fn serial_print(s: &[u8]) {
    for &ch in s {
        serial_write_byte(ch);
    }
}

fn serial_println(s: &[u8]) {
    serial_print(s);
    serial_print(b"\r\n");
}

fn serial_print_dec(mut val: u64) {
    if val == 0 {
        serial_write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        serial_write_byte(buf[i]);
    }
}

static mut BLOCK_DEVICES: [BlockDevice; MAX_BLOCK_DEVICES] = [BlockDevice::empty(); MAX_BLOCK_DEVICES];
static DEVICE_COUNT: AtomicU64 = AtomicU64::new(0);
static SUBSYS_INIT: AtomicBool = AtomicBool::new(false);

pub fn init() {
    if SUBSYS_INIT.load(Ordering::Relaxed) {
        return;
    }
    serial_println(b"[BLOCK] Block device subsystem initialized");
    SUBSYS_INIT.store(true, Ordering::SeqCst);
}

pub fn register_device(
    device_type: BlockDeviceType,
    block_size: u32,
    total_blocks: u64,
    removable: bool,
    read_only: bool,
) -> Option<u8> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    if count >= MAX_BLOCK_DEVICES {
        serial_println(b"[BLOCK] ERROR: Maximum devices reached");
        return None;
    }

    let id = count as u8;
    let device = BlockDevice {
        id,
        device_type,
        block_size,
        total_blocks,
        removable,
        read_only,
        present: true,
    };

    // SAFETY: Protected by atomic counter
    unsafe {
        BLOCK_DEVICES[count] = device;
    }
    DEVICE_COUNT.fetch_add(1, Ordering::SeqCst);

    serial_print(b"[BLOCK] Registered device ");
    serial_print_dec(id as u64);
    serial_print(b": ");
    serial_print_dec(device.capacity_mb());
    serial_println(b" MB");

    Some(id)
}

pub fn unregister_device(id: u8) {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    let id_usize = id as usize;

    if id_usize < count {
        // SAFETY: Index checked against counter
        unsafe {
            BLOCK_DEVICES[id_usize].present = false;
        }
        serial_print(b"[BLOCK] Unregistered device ");
        serial_print_dec(id as u64);
        serial_println(b"");
    }
}

pub fn get_device(id: u8) -> Option<BlockDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    let id_usize = id as usize;

    if id_usize < count {
        // SAFETY: Index checked against counter
        let dev = unsafe { BLOCK_DEVICES[id_usize] };
        if dev.present {
            return Some(dev);
        }
    }
    None
}

pub fn device_count() -> usize {
    DEVICE_COUNT.load(Ordering::Relaxed) as usize
}

pub fn find_device(device_type: BlockDeviceType) -> Option<BlockDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;

    for i in 0..count {
        // SAFETY: Index checked against counter
        let dev = unsafe { BLOCK_DEVICES[i] };
        if dev.present && dev.device_type == device_type {
            return Some(dev);
        }
    }
    None
}

pub fn is_init() -> bool {
    SUBSYS_INIT.load(Ordering::Relaxed)
}

pub fn list_devices() {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;

    serial_print(b"[BLOCK] ");
    serial_print_dec(count as u64);
    serial_println(b" device(s) registered:");

    for i in 0..count {
        // SAFETY: Index checked against counter
        let dev = unsafe { BLOCK_DEVICES[i] };
        if dev.present {
            serial_print(b"  [");
            serial_print_dec(dev.id as u64);
            serial_print(b"] ");
            match dev.device_type {
                BlockDeviceType::UsbMassStorage => serial_print(b"USB "),
                BlockDeviceType::SataAhci => serial_print(b"SATA "),
                BlockDeviceType::Nvme => serial_print(b"NVMe "),
                BlockDeviceType::Unknown => serial_print(b"Unknown "),
            }
            serial_print_dec(dev.capacity_mb());
            serial_print(b" MB");
            if dev.removable {
                serial_print(b" (removable)");
            }
            if dev.read_only {
                serial_print(b" (read-only)");
            }
            serial_println(b"");
        }
    }
}
