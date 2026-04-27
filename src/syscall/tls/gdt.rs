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

use super::types::{GdtEntry64, UserDesc, GDT_ENTRIES, GDT_ENTRY_TLS_MIN};
use core::arch::asm;

#[repr(C, packed)]
pub struct GdtPtr {
    pub limit: u16,
    pub base: u64,
}

static mut GDT: [GdtEntry64; GDT_ENTRIES] = [GdtEntry64 {
    limit_low: 0,
    base_low: 0,
    base_mid: 0,
    access: 0,
    granularity: 0,
    base_high: 0,
}; GDT_ENTRIES];

pub fn install_tls_descriptor(entry_number: usize, desc: &UserDesc) {
    if entry_number >= GDT_ENTRIES {
        return;
    }
    let gdt_entry = desc.to_gdt_entry();
    unsafe {
        GDT[entry_number] = gdt_entry;
    }
    reload_gdt_entry(entry_number);
}

pub fn clear_tls_descriptor(entry_number: usize) {
    if entry_number >= GDT_ENTRIES {
        return;
    }
    unsafe {
        GDT[entry_number] = GdtEntry64::default();
    }
    reload_gdt_entry(entry_number);
}

fn reload_gdt_entry(entry_number: usize) {
    let selector = ((entry_number as u16) << 3) | 3;
    if entry_number >= GDT_ENTRY_TLS_MIN && entry_number < GDT_ENTRY_TLS_MIN + 3 {
        unsafe {
            asm!(
                "mov gs, {0:x}",
                in(reg) selector,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

pub fn get_gdt_base() -> u64 {
    let mut gdt_ptr = GdtPtr { limit: 0, base: 0 };
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdt_ptr, options(nostack, preserves_flags));
    }
    gdt_ptr.base
}

pub fn get_gdt_limit() -> u16 {
    let mut gdt_ptr = GdtPtr { limit: 0, base: 0 };
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdt_ptr, options(nostack, preserves_flags));
    }
    gdt_ptr.limit
}

pub fn load_gdt(base: u64, limit: u16) {
    let gdt_ptr = GdtPtr { limit, base };
    unsafe {
        asm!("lgdt [{}]", in(reg) &gdt_ptr, options(nostack, preserves_flags));
    }
}

pub fn get_cs() -> u16 {
    let cs: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
    }
    cs
}

pub fn get_ds() -> u16 {
    let ds: u16;
    unsafe {
        asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
    }
    ds
}

pub fn get_ss() -> u16 {
    let ss: u16;
    unsafe {
        asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
    }
    ss
}

pub fn get_gs() -> u16 {
    let gs: u16;
    unsafe {
        asm!("mov {0:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));
    }
    gs
}

pub fn get_fs() -> u16 {
    let fs: u16;
    unsafe {
        asm!("mov {0:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
    }
    fs
}
