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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use super::types::{SysfsEntry, SysfsAttribute};

static NEXT_INO: AtomicU64 = AtomicU64::new(10000);
static KOBJECTS: Mutex<BTreeMap<u64, Kobject>> = Mutex::new(BTreeMap::new());
static ATTRIBUTES: Mutex<BTreeMap<u64, SysfsAttribute>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KobjectType { Device, Driver, Class, Bus, Module, Subsystem }

#[derive(Debug, Clone)]
pub struct Kobject {
    pub ino: u64,
    pub name: String,
    pub ktype: KobjectType,
    pub parent: u64,
    pub children: Vec<u64>,
}

pub fn register_kobject(name: &str, ktype: KobjectType, parent: u64) -> u64 {
    let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
    let kobj = Kobject { ino, name: String::from(name), ktype, parent, children: Vec::new() };
    let mut kobjects = KOBJECTS.lock();
    kobjects.insert(ino, kobj);
    if let Some(p) = kobjects.get_mut(&parent) {
        p.children.push(ino);
    }
    ino
}

pub fn unregister_kobject(ino: u64) {
    let mut kobjects = KOBJECTS.lock();
    if let Some(kobj) = kobjects.remove(&ino) {
        if let Some(p) = kobjects.get_mut(&kobj.parent) {
            p.children.retain(|&c| c != ino);
        }
    }
}

pub fn get_kobject_entries(parent_ino: u64) -> Vec<SysfsEntry> {
    let kobjects = KOBJECTS.lock();
    kobjects.values()
        .filter(|k| k.parent == parent_ino)
        .map(|k| SysfsEntry::directory(&k.name, k.ino))
        .collect()
}

pub fn get_attribute(ino: u64) -> Option<SysfsAttribute> {
    ATTRIBUTES.lock().get(&ino).cloned()
}

pub fn get_entry(ino: u64) -> Option<SysfsEntry> {
    KOBJECTS.lock().get(&ino).map(|k| SysfsEntry::directory(&k.name, k.ino))
}

pub fn register_attribute(parent: u64, attr: SysfsAttribute) -> u64 {
    let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
    ATTRIBUTES.lock().insert(ino, attr);
    ino
}
