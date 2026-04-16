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
use crate::fs::sysfs::kobject::{register_kobject, KobjectType, register_attribute, get_kobject_entries};
use crate::fs::sysfs::types::SysfsAttribute;

static mut MODULE_INO: u64 = 500;

pub struct ModuleInfo {
    pub name: String,
    pub size: usize,
    pub refcount: u32,
}

pub fn init_module_subsystem() {
    unsafe { MODULE_INO = 500; }
    for name in crate::modules::list_modules() {
        if let Ok(info) = crate::modules::get_module_info(&name) {
            register_module_entry(&info.name, info.memory_size, 1);
        }
    }
}

pub fn get_module_ino() -> u64 {
    unsafe { MODULE_INO }
}

pub fn register_module_entry(name: &str, size: usize, refcount: u32) -> u64 {
    let parent = get_module_ino();
    let ino = register_kobject(name, KobjectType::Module, parent);
    register_attribute(ino, SysfsAttribute::readonly("coresize", move || format!("{}\n", size)));
    register_attribute(ino, SysfsAttribute::readonly("refcnt", move || format!("{}\n", refcount)));
    register_attribute(ino, SysfsAttribute::readonly("taint", || String::from("\n")));
    let _ = register_kobject("parameters", KobjectType::Subsystem, ino);
    register_attribute(ino, SysfsAttribute::readonly("srcversion", || String::from("NONOS\n")));
    register_attribute(ino, SysfsAttribute::readonly("initstate", || String::from("live\n")));
    ino
}

pub fn unregister_module(name: &str) {
    if let Some(ino) = find_module_ino(name) {
        crate::fs::sysfs::kobject::unregister_kobject(ino);
    }
}

fn find_module_ino(name: &str) -> Option<u64> {
    let parent = get_module_ino();
    for entry in get_kobject_entries(parent) {
        if entry.name == name {
            return Some(entry.ino);
        }
    }
    None
}

pub fn list_modules() -> Vec<String> {
    crate::modules::list_modules()
}

pub fn get_module_info(name: &str) -> Option<ModuleInfo> {
    crate::modules::get_module_info(name).ok().map(|m| ModuleInfo {
        name: m.name.clone(),
        size: m.memory_size,
        refcount: 1,
    })
}
