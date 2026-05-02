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

use crate::syscall::numbers::SyscallNumber;

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
    for obj in objects.iter() {
        if obj.name == name {
            return Ok(obj.clone());
        }
    }
    drop(objects);
    let path = super::search::search_library(name)?;
    load_library_from_path(&path, name)
}

fn load_library_from_path(path: &str, name: &str) -> Result<LoadedObject, i32> {
    let fd = super::syscall::call(
        SyscallNumber::Open,
        [path.as_ptr() as u64, 0, 0, 0, 0, 0],
    );
    if fd < 0 {
        return Err(fd as i32);
    }
    let mut header = [0u8; 64];
    let n = super::syscall::call(
        SyscallNumber::Read,
        [fd as u64, header.as_mut_ptr() as u64, 64, 0, 0, 0],
    );
    if n < 64 {
        let _ = super::syscall::call(SyscallNumber::Close, [fd as u64, 0, 0, 0, 0, 0]);
        return Err(-22);
    }
    let elf_hdr = unsafe { &*(header.as_ptr() as *const crate::elf::types::ElfHeader) };
    if &header[0..4] != b"\x7fELF" {
        let _ = super::syscall::call(SyscallNumber::Close, [fd as u64, 0, 0, 0, 0, 0]);
        return Err(-8);
    }
    let base = allocate_load_address(elf_hdr);
    let obj = map_library(fd as i32, elf_hdr, base, name)?;
    let _ = super::syscall::call(SyscallNumber::Close, [fd as u64, 0, 0, 0, 0, 0]);
    LOADED_OBJECTS.lock().push(obj.clone());
    super::debug::add_link_map(&obj);
    Ok(obj)
}

fn allocate_load_address(hdr: &crate::elf::types::ElfHeader) -> usize {
    let phnum = hdr.e_phnum as usize;
    let phoff = hdr.e_phoff as usize;
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;
    for i in 0..phnum {
        let phdr_off = phoff + i * 56;
        let p_type = unsafe { *((hdr as *const _ as usize + phdr_off) as *const u32) };
        if p_type != 1 {
            continue;
        }
        let p_vaddr =
            unsafe { *((hdr as *const _ as usize + phdr_off + 16) as *const u64) } as usize;
        let p_memsz =
            unsafe { *((hdr as *const _ as usize + phdr_off + 40) as *const u64) } as usize;
        min_vaddr = min_vaddr.min(p_vaddr);
        max_vaddr = max_vaddr.max(p_vaddr + p_memsz);
    }
    let size = if max_vaddr > min_vaddr { max_vaddr - min_vaddr } else { 0x400000 };
    let size = (size + 0xfff) & !0xfff;
    crate::elf::aslr::AslrManager::random_address(0x7f0000000000, 0x7fff00000000, size)
}

fn map_library(
    fd: i32,
    hdr: &crate::elf::types::ElfHeader,
    base: usize,
    name: &str,
) -> Result<LoadedObject, i32> {
    let phnum = hdr.e_phnum as usize;
    let phentsize = hdr.e_phentsize as usize;
    let phoff = hdr.e_phoff;
    let mut phdrs = alloc::vec![0u8; phnum * phentsize];
    let _ = super::syscall::call(
        SyscallNumber::Lseek,
        [fd as u64, phoff as u64, 0, 0, 0, 0],
    );
    let n = super::syscall::call(
        SyscallNumber::Read,
        [fd as u64, phdrs.as_mut_ptr() as u64, phdrs.len() as u64, 0, 0, 0],
    );
    if (n as usize) < phdrs.len() {
        return Err(-5);
    }
    let mut obj = LoadedObject {
        name: String::from(name),
        base,
        phdr: 0,
        phnum,
        dynamic: 0,
        needed: Vec::new(),
        init: 0,
        fini: 0,
        init_array: 0,
        init_arraysz: 0,
        fini_array: 0,
        fini_arraysz: 0,
    };
    for i in 0..phnum {
        let phdr = &phdrs[i * phentsize..];
        let p_type = u32::from_le_bytes([phdr[0], phdr[1], phdr[2], phdr[3]]);
        let p_offset = u64::from_le_bytes([
            phdr[8], phdr[9], phdr[10], phdr[11], phdr[12], phdr[13], phdr[14], phdr[15],
        ]);
        let p_vaddr = u64::from_le_bytes([
            phdr[16], phdr[17], phdr[18], phdr[19], phdr[20], phdr[21], phdr[22], phdr[23],
        ]);
        let p_filesz = u64::from_le_bytes([
            phdr[32], phdr[33], phdr[34], phdr[35], phdr[36], phdr[37], phdr[38], phdr[39],
        ]);
        let p_memsz = u64::from_le_bytes([
            phdr[40], phdr[41], phdr[42], phdr[43], phdr[44], phdr[45], phdr[46], phdr[47],
        ]);
        match p_type {
            1 => {
                let addr = base + p_vaddr as usize;
                let pages = (p_memsz as usize + 0xfff) / 0x1000;
                crate::syscall::microkernel::sys_mmap(addr as u64, pages * 0x1000, 7, 0x22);
                let _ = super::syscall::call(
                    SyscallNumber::Lseek,
                    [fd as u64, p_offset, 0, 0, 0, 0],
                );
                let _ = super::syscall::call(
                    SyscallNumber::Read,
                    [fd as u64, addr as u64, p_filesz, 0, 0, 0],
                );
                if p_memsz > p_filesz {
                    let bss_start = addr + p_filesz as usize;
                    let bss_size = (p_memsz - p_filesz) as usize;
                    unsafe {
                        core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
                    }
                }
            }
            2 => obj.dynamic = base + p_vaddr as usize,
            6 => obj.phdr = base + p_vaddr as usize,
            _ => {}
        }
    }
    if obj.dynamic != 0 {
        parse_dynamic(&mut obj);
    }
    Ok(obj)
}

fn parse_dynamic(obj: &mut LoadedObject) {
    let mut ptr = obj.dynamic;
    loop {
        let tag = unsafe { *(ptr as *const i64) };
        let val = unsafe { *((ptr + 8) as *const u64) };
        match tag {
            0 => break,
            1 => {
                let strtab = get_strtab(obj.dynamic, obj.base);
                if strtab != 0 {
                    let s =
                        unsafe { core::ffi::CStr::from_ptr((strtab + val as usize) as *const i8) };
                    if let Ok(name) = s.to_str() {
                        obj.needed.push(String::from(name));
                    }
                }
            }
            12 => obj.init = obj.base + val as usize,
            13 => obj.fini = obj.base + val as usize,
            25 => obj.init_array = obj.base + val as usize,
            27 => obj.init_arraysz = val as usize,
            26 => obj.fini_array = obj.base + val as usize,
            28 => obj.fini_arraysz = val as usize,
            _ => {}
        }
        ptr += 16;
    }
}

fn get_strtab(dynamic: usize, base: usize) -> usize {
    let mut ptr = dynamic;
    loop {
        let tag = unsafe { *(ptr as *const i64) };
        let val = unsafe { *((ptr + 8) as *const u64) };
        if tag == 0 {
            break;
        }
        if tag == 5 {
            return base + val as usize;
        }
        ptr += 16;
    }
    0
}

pub fn load_needed(names: &[String]) -> Result<(), i32> {
    for name in names {
        load_library(name)?;
    }
    Ok(())
}

pub fn load_needed_recursive(base: usize) {
    let mut visited = alloc::collections::BTreeSet::new();
    load_needed_inner(base, &mut visited);
}

fn load_needed_inner(base: usize, visited: &mut alloc::collections::BTreeSet<usize>) {
    if !visited.insert(base) {
        return;
    }
    let needed: Vec<String> = {
        let objects = LOADED_OBJECTS.lock();
        objects.iter().find(|o| o.base == base).map(|o| o.needed.clone()).unwrap_or_default()
    };
    for name in needed {
        if let Ok(obj) = load_library(&name) {
            load_needed_inner(obj.base, visited);
        }
    }
}

pub fn get_loaded_objects() -> ObjectList {
    LOADED_OBJECTS.lock().clone()
}

pub fn find_object_by_name(name: &str) -> Option<LoadedObject> {
    LOADED_OBJECTS.lock().iter().find(|o| o.name == name).cloned()
}

pub fn find_object_by_base(base: usize) -> Option<LoadedObject> {
    LOADED_OBJECTS.lock().iter().find(|o| o.base == base).cloned()
}
