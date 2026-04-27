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

mod mm;

pub use mm::{get_overcommit_memory, get_transparent_hugepage, init_mm_subsystem};

use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;

static mut KERNEL_INO: u64 = 400;

pub fn init_kernel_subsystem() {
    unsafe {
        KERNEL_INO = 400;
    }
    register_attribute(
        unsafe { KERNEL_INO },
        SysfsAttribute::readonly("uevent", || alloc::string::String::new()),
    );
    register_attribute(
        unsafe { KERNEL_INO },
        SysfsAttribute::readonly("fscaps", || alloc::string::String::from("1\n")),
    );
    register_attribute(
        unsafe { KERNEL_INO },
        SysfsAttribute::readonly("profiling", || alloc::string::String::from("0\n")),
    );
    register_kobject("security", KobjectType::Subsystem, unsafe { KERNEL_INO });
    register_kobject("debug", KobjectType::Subsystem, unsafe { KERNEL_INO });
    register_kobject("config", KobjectType::Subsystem, unsafe { KERNEL_INO });
    mm::init_mm_subsystem();
}

pub fn get_kernel_ino() -> u64 {
    unsafe { KERNEL_INO }
}

pub fn register_kernel_param(
    name: &str,
    show: fn() -> alloc::string::String,
    store: Option<fn(&str) -> Result<(), i32>>,
) -> u64 {
    let ino = crate::fs::sysfs::kobject::register_attribute(
        unsafe { KERNEL_INO },
        match store {
            Some(s) => SysfsAttribute::readwrite(name, show, s),
            None => SysfsAttribute::readonly(name, show),
        },
    );
    ino
}
