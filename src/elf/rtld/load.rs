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
use spin::Mutex;

#[derive(Debug, Clone)]
pub struct LoadedObject {
    pub name: String,
    pub base: usize,
    pub phdr: usize,
    pub phnum: usize,
    pub dynamic: usize,
    pub needed: Vec<String>,
    pub init: usize,
    pub fini: usize,
    pub init_array: usize,
    pub init_arraysz: usize,
    pub fini_array: usize,
    pub fini_arraysz: usize,
}

pub type ObjectList = Vec<LoadedObject>;
static LOADED_OBJECTS: Mutex<ObjectList> = Mutex::new(Vec::new());

pub fn load_library(name: &str) -> Result<LoadedObject, i32> {
    let objects = LOADED_OBJECTS.lock();
    for obj in objects.iter() { if obj.name == name { return Ok(obj.clone()); } }
    drop(objects);
    let path = super::search::search_library(name)?;
    load_library_from_path(&path, name)
}

fn load_library_from_path(path: &str, name: &str) -> Result<LoadedObject, i32> {
    let fd = crate::syscall::core::sys_open(path.as_ptr() as u64, 0, 0);
    if fd < 0 { return Err(fd as i32); }
    let mut header = [0u8; 64];
    let n = crate::syscall::core::sys_read(fd as u64, header.as_mut_ptr() as u64, 64);
    if n < 64 { crate::syscall::core::sys_close(fd as u64); return Err(-22); }
    let elf_hdr = unsafe { &*(header.as_ptr() as *const crate::elf::types::ElfHeader) };
    if &header[0..4] != b"\x7fELF" { crate::syscall::core::sys_close(fd as u64); return Err(-8); }
    let base = allocate_load_address(elf_hdr);
    let obj = map_library(fd as i32, elf_hdr, base, name)?;
    crate::syscall::core::sys_close(fd as u64);
    LOADED_OBJECTS.lock().push(obj.clone());
    super::debug::add_link_map(&obj);
    Ok(obj)
}

fn allocate_load_address(hdr: &crate::elf::types::ElfHeader) -> usize {
    let mut size = 0usize;
    let _ = hdr;
    size = (size + 0xfff) & !0xfff;
    if size == 0 { size = 0x400000; }
    crate::elf::aslr::AslrManager::random_address(0x7f0000000000, 0x7fff00000000, size)
}

fn map_library(fd: i32, hdr: &crate::elf::types::ElfHeader, base: usize, name: &str) -> Result<LoadedObject, i32> {
    let _ = (fd, hdr);
    Ok(LoadedObject {
        name: String::from(name), base, phdr: 0, phnum: 0, dynamic: 0,
        needed: Vec::new(), init: 0, fini: 0, init_array: 0, init_arraysz: 0, fini_array: 0, fini_arraysz: 0,
    })
}

pub fn load_needed(names: &[String]) -> Result<(), i32> {
    for name in names { load_library(name)?; }
    Ok(())
}

pub fn load_needed_recursive(base: usize) {
    let mut visited = alloc::collections::BTreeSet::new();
    load_needed_inner(base, &mut visited);
}

fn load_needed_inner(base: usize, visited: &mut alloc::collections::BTreeSet<usize>) {
    if !visited.insert(base) { return; }
    let needed: Vec<String> = {
        let objects = LOADED_OBJECTS.lock();
        objects.iter().find(|o| o.base == base).map(|o| o.needed.clone()).unwrap_or_default()
    };
    for name in needed {
        if let Ok(obj) = load_library(&name) { load_needed_inner(obj.base, visited); }
    }
}

pub fn get_loaded_objects() -> ObjectList { LOADED_OBJECTS.lock().clone() }

pub fn find_object_by_name(name: &str) -> Option<LoadedObject> {
    LOADED_OBJECTS.lock().iter().find(|o| o.name == name).cloned()
}

pub fn find_object_by_base(base: usize) -> Option<LoadedObject> {
    LOADED_OBJECTS.lock().iter().find(|o| o.base == base).cloned()
}
