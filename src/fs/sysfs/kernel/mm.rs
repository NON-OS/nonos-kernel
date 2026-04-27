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

use super::get_kernel_ino;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

static TRANSPARENT_HUGEPAGE: AtomicU32 = AtomicU32::new(1);
static OVERCOMMIT_MEMORY: AtomicU32 = AtomicU32::new(0);

static mut MM_INO: u64 = 0;

pub fn init_mm_subsystem() {
    unsafe {
        MM_INO = register_kobject("mm", KobjectType::Subsystem, get_kernel_ino());
    }
    let thp_ino =
        register_kobject("transparent_hugepage", KobjectType::Subsystem, unsafe { MM_INO });
    register_attribute(
        thp_ino,
        SysfsAttribute::readwrite(
            "enabled",
            || {
                let v = TRANSPARENT_HUGEPAGE.load(Ordering::Relaxed);
                match v {
                    0 => String::from("never\n"),
                    1 => String::from("[always] madvise never\n"),
                    _ => String::from("always [madvise] never\n"),
                }
            },
            |s| {
                let val = match s.trim() {
                    "always" => 1,
                    "madvise" => 2,
                    "never" => 0,
                    _ => return Err(-22),
                };
                TRANSPARENT_HUGEPAGE.store(val, Ordering::Relaxed);
                Ok(())
            },
        ),
    );
    register_attribute(
        thp_ino,
        SysfsAttribute::readonly("defrag", || {
            String::from("[always] defer defer+madvise madvise never\n")
        }),
    );
    register_attribute(
        unsafe { MM_INO },
        SysfsAttribute::readwrite(
            "overcommit_memory",
            || format!("{}\n", OVERCOMMIT_MEMORY.load(Ordering::Relaxed)),
            |s| {
                let val: u32 = s.trim().parse().map_err(|_| -22)?;
                if val > 2 {
                    return Err(-22);
                }
                OVERCOMMIT_MEMORY.store(val, Ordering::Relaxed);
                Ok(())
            },
        ),
    );
    register_attribute(
        unsafe { MM_INO },
        SysfsAttribute::readonly("overcommit_ratio", || String::from("50\n")),
    );
}

pub fn get_transparent_hugepage() -> u32 {
    TRANSPARENT_HUGEPAGE.load(Ordering::Relaxed)
}
pub fn get_overcommit_memory() -> u32 {
    OVERCOMMIT_MEMORY.load(Ordering::Relaxed)
}
