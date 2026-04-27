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

use super::types::{SysfsAttribute, SysfsEntry};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static NEXT_INO: AtomicU64 = AtomicU64::new(10000);
static KOBJECTS: Mutex<BTreeMap<u64, Kobject>> = Mutex::new(BTreeMap::new());
static ATTRIBUTES: Mutex<BTreeMap<u64, SysfsAttribute>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KobjectType {
    Device,
    Driver,
    Class,
    Bus,
    Module,
    Subsystem,
}

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
    kobjects
        .values()
        .filter(|k| k.parent == parent_ino)
        .map(|k| SysfsEntry::directory(&k.name, k.ino))
        .collect()
}

pub fn get_attribute(ino: u64) -> Option<alloc::string::String> {
    ATTRIBUTES.lock().get(&ino).map(|attr| (attr.show)())
}

pub fn store_attribute(ino: u64, data: &str) -> Result<(), i32> {
    let attrs = ATTRIBUTES.lock();
    let attr = attrs.get(&ino).ok_or(-2)?;
    match &attr.store {
        Some(store_fn) => store_fn(data),
        None => Err(-1),
    }
}

pub fn get_entry(ino: u64) -> Option<SysfsEntry> {
    KOBJECTS.lock().get(&ino).map(|k| SysfsEntry::directory(&k.name, k.ino))
}

static ATTR_TO_PARENT: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

pub fn register_attribute(parent: u64, attr: SysfsAttribute) -> u64 {
    let ino = NEXT_INO.fetch_add(1, Ordering::SeqCst);
    ATTRIBUTES.lock().insert(ino, attr);
    ATTR_TO_PARENT.lock().insert(ino, parent);
    let mut kobjects = KOBJECTS.lock();
    if let Some(p) = kobjects.get_mut(&parent) {
        p.children.push(ino);
    }
    ino
}

pub struct AttributeInfo {
    pub ino: u64,
    pub name: alloc::string::String,
    pub mode: u32,
    pub writable: bool,
}

pub fn get_attributes_for_kobject(parent: u64) -> Vec<AttributeInfo> {
    let attr_to_parent = ATTR_TO_PARENT.lock();
    let attrs = ATTRIBUTES.lock();
    attrs
        .iter()
        .filter(|(ino, _)| attr_to_parent.get(*ino) == Some(&parent))
        .map(|(ino, attr)| AttributeInfo {
            ino: *ino,
            name: attr.name.clone(),
            mode: attr.mode,
            writable: attr.is_writable(),
        })
        .collect()
}
