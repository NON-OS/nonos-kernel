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

use core::sync::atomic::{AtomicBool, Ordering};
use crate::storage::block::{BlockError, BlockResult};
use super::types::{Fat32, Fat32BootSector, BOOT_SIGNATURE};

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

pub(crate) fn serial_print(s: &[u8]) {
    for &ch in s {
        serial_write_byte(ch);
    }
}

pub(crate) fn serial_println(s: &[u8]) {
    serial_print(s);
    serial_print(b"\r\n");
}

pub(crate) fn serial_print_dec(mut val: u64) {
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

fn serial_print_hex(val: u32) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    serial_print(b"0x");
    for i in (0..8).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as usize;
        serial_write_byte(HEX[nibble]);
    }
}

const MAX_FILESYSTEMS: usize = 4;

static mut FILESYSTEMS: [Fat32; MAX_FILESYSTEMS] = [Fat32::empty(); MAX_FILESYSTEMS];
static mut FS_COUNT: usize = 0;
static FAT32_INIT: AtomicBool = AtomicBool::new(false);

pub(crate) static mut SECTOR_BUFFER: [u8; 4096] = [0u8; 4096];

pub fn init() {
    if FAT32_INIT.load(Ordering::Relaxed) {
        return;
    }
    serial_println(b"[FAT32] Filesystem subsystem initialized");
    FAT32_INIT.store(true, Ordering::SeqCst);
}

pub fn mount(device_id: u8, read_fn: fn(u8, u64, &mut [u8]) -> BlockResult<()>) -> BlockResult<u8> {
    // SAFETY: Protected by atomic init flag
    let fs_count = unsafe { FS_COUNT };
    if fs_count >= MAX_FILESYSTEMS {
        serial_println(b"[FAT32] ERROR: Maximum filesystems mounted");
        return Err(BlockError::IoError);
    }

    serial_print(b"[FAT32] Mounting device ");
    serial_print_dec(device_id as u64);
    serial_println(b"...");

    // SAFETY: Buffer is used exclusively in single-threaded context
    let sector_buf = unsafe { &mut SECTOR_BUFFER[..512] };
    read_fn(device_id, 0, sector_buf)?;

    let sig = u16::from_le_bytes([sector_buf[510], sector_buf[511]]);
    if sig != BOOT_SIGNATURE {
        serial_print(b"[FAT32] Invalid boot signature: ");
        serial_print_hex(sig as u32);
        serial_println(b"");
        return Err(BlockError::IoError);
    }

    // SAFETY: Buffer contains valid boot sector data
    let bpb = unsafe { &*(sector_buf.as_ptr() as *const Fat32BootSector) };

    if !bpb.is_valid() {
        serial_println(b"[FAT32] Invalid BPB");
        return Err(BlockError::IoError);
    }

    let fs = Fat32 {
        device_id,
        bytes_per_sector: bpb.bytes_per_sector,
        sectors_per_cluster: bpb.sectors_per_cluster,
        reserved_sectors: bpb.reserved_sectors,
        num_fats: bpb.num_fats,
        fat_size: bpb.fat_size_32,
        root_cluster: bpb.root_cluster,
        total_sectors: bpb.total_sectors_32,
        first_data_sector: bpb.first_data_sector(),
        cluster_size: bpb.cluster_size(),
    };

    let fs_id = fs_count as u8;
    // SAFETY: Index checked, single-threaded access
    unsafe {
        FILESYSTEMS[fs_count] = fs;
        FS_COUNT += 1;
    }

    serial_print(b"[FAT32] Mounted: ");
    serial_print_dec(bpb.bytes_per_sector as u64);
    serial_print(b" bytes/sector, ");
    serial_print_dec(bpb.sectors_per_cluster as u64);
    serial_print(b" sectors/cluster, root=");
    serial_print_dec(bpb.root_cluster as u64);
    serial_println(b"");

    Ok(fs_id)
}

pub fn get_fs(fs_id: u8) -> Option<Fat32> {
    // SAFETY: Atomic read, bounds checked
    let fs_count = unsafe { FS_COUNT };
    if (fs_id as usize) < fs_count {
        Some(unsafe { FILESYSTEMS[fs_id as usize] })
    } else {
        None
    }
}

pub fn fs_count() -> usize {
    // SAFETY: Atomic read
    unsafe { FS_COUNT }
}

pub fn is_init() -> bool {
    FAT32_INIT.load(Ordering::Relaxed)
}
