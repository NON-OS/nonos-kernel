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

use super::register_root_device;
use crate::fs::sysfs::kobject::{register_attribute, register_kobject, KobjectType};
use crate::fs::sysfs::types::SysfsAttribute;
use alloc::format;
use alloc::string::String;

static mut SYSTEM_INO: u64 = 0;
static mut CPU_INO: u64 = 0;
static mut NODE_INO: u64 = 0;

pub fn init_system_devices() {
    unsafe {
        SYSTEM_INO = register_root_device("system");
        CPU_INO = register_kobject("cpu", KobjectType::Subsystem, SYSTEM_INO);
        NODE_INO = register_kobject("node", KobjectType::Subsystem, SYSTEM_INO);
    }
    for cpu in 0..crate::smp::cpu_count() {
        register_cpu(cpu);
    }
    register_node(0);
}

fn register_cpu(cpu: usize) {
    let parent = unsafe { CPU_INO };
    let name = format!("cpu{}", cpu);
    let ino = register_kobject(&name, KobjectType::Device, parent);
    register_cpu_device(cpu, ino);
    register_attribute(ino, SysfsAttribute::readonly("online", || String::from("1\n")));
    register_attribute(
        ino,
        SysfsAttribute::readonly("topology/core_id", move || format!("{}\n", cpu)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("topology/physical_package_id", || String::from("0\n")),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("topology/thread_siblings_list", move || format!("{}\n", cpu)),
    );
    register_attribute(
        ino,
        SysfsAttribute::readonly("topology/core_siblings_list", || {
            let count = crate::smp::cpu_count();
            format!("0-{}\n", count.saturating_sub(1))
        }),
    );
}

fn register_node(node: u32) {
    let parent = unsafe { NODE_INO };
    let name = format!("node{}", node);
    let ino = register_kobject(&name, KobjectType::Device, parent);
    register_node_device(node, ino);
    register_attribute(
        ino,
        SysfsAttribute::readonly("cpulist", || {
            let count = crate::smp::cpu_count();
            format!("0-{}\n", count.saturating_sub(1))
        }),
    );
    register_attribute(ino, SysfsAttribute::readonly("meminfo", || read_node_meminfo()));
}

fn read_node_meminfo() -> String {
    let stats = crate::memory::get_memory_stats();
    format!(
        "Node 0 MemTotal:    {:>12} kB\nNode 0 MemFree:     {:>12} kB\n",
        stats.total_bytes / 1024,
        stats.free_bytes / 1024
    )
}

static CPU_DEVICES: spin::Mutex<alloc::collections::BTreeMap<usize, u64>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());
static NODE_DEVICES: spin::Mutex<alloc::collections::BTreeMap<u32, u64>> =
    spin::Mutex::new(alloc::collections::BTreeMap::new());

pub fn get_cpu_device(cpu: usize) -> u64 {
    CPU_DEVICES.lock().get(&cpu).copied().unwrap_or(unsafe { CPU_INO })
}

pub fn get_node_device(node: u32) -> u64 {
    NODE_DEVICES.lock().get(&node).copied().unwrap_or(unsafe { NODE_INO })
}

pub fn register_cpu_device(cpu: usize, ino: u64) {
    CPU_DEVICES.lock().insert(cpu, ino);
}

pub fn register_node_device(node: u32, ino: u64) {
    NODE_DEVICES.lock().insert(node, ino);
}
