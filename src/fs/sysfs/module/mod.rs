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

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::fs::sysfs::kobject::{register_kobject, KobjectType, register_attribute};
use crate::fs::sysfs::types::SysfsAttribute;

static mut MODULE_INO: u64 = 500;

pub fn init_module_subsystem() {
    unsafe {
        MODULE_INO = 500;
    }
    for module in crate::modules::list_modules() {
        register_module(&module.name, module.size, module.refcount);
    }
}

pub fn get_module_ino() -> u64 {
    unsafe { MODULE_INO }
}

pub fn register_module(name: &str, size: usize, refcount: u32) -> u64 {
    let parent = get_module_ino();
    let ino = register_kobject(name, KobjectType::Module, parent);
    register_attribute(ino, SysfsAttribute::readonly("coresize", move || format!("{}\n", size)));
    register_attribute(ino, SysfsAttribute::readonly("refcnt", move || format!("{}\n", refcount)));
    register_attribute(ino, SysfsAttribute::readonly("taint", || String::from("\n")));
    let params_ino = register_kobject("parameters", KobjectType::Subsystem, ino);
    register_attribute(ino, SysfsAttribute::readonly("srcversion", || String::from("NONOS\n")));
    register_attribute(ino, SysfsAttribute::readonly("initstate", || String::from("live\n")));
    ino
}

pub fn unregister_module(name: &str) {
    crate::fs::sysfs::kobject::unregister_kobject(find_module_ino(name).unwrap_or(0));
}

fn find_module_ino(name: &str) -> Option<u64> {
    crate::fs::sysfs::kobject::get_entry(get_module_ino())
        .and_then(|_| None)
}

pub fn list_modules() -> Vec<String> {
    crate::modules::list_modules().iter().map(|m| m.name.clone()).collect()
}

pub fn get_module_info(name: &str) -> Option<ModuleInfo> {
    crate::modules::get_module(name).map(|m| ModuleInfo { name: m.name.clone(), size: m.size, refcount: m.refcount })
}

pub struct ModuleInfo { pub name: String, pub size: usize, pub refcount: u32 }
