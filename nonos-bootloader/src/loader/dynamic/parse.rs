// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::types::{dyn_tag, DynamicInfo, Elf64Dyn};
use crate::log::logger::log_debug;

pub fn parse_dynamic_section(
    data: &[u8],
    dyn_offset: usize,
    dyn_size: usize,
) -> LoaderResult<DynamicInfo> {
    let entry_size = core::mem::size_of::<Elf64Dyn>();

    if dyn_offset + dyn_size > data.len() {
        return Err(LoaderError::SegmentOutOfBounds);
    }

    if dyn_size < entry_size {
        return Err(LoaderError::InvalidDynamic);
    }

    let entry_count = dyn_size / entry_size;
    let mut info = DynamicInfo::default();

    for i in 0..entry_count {
        let offset = dyn_offset + i * entry_size;
        let dyn_entry = unsafe { &*(data.as_ptr().add(offset) as *const Elf64Dyn) };

        if dyn_entry.d_tag == dyn_tag::DT_NULL {
            break;
        }

        parse_dynamic_entry(dyn_entry, &mut info);
    }

    log_debug("dynamic", "Parsed dynamic section");

    Ok(info)
}

pub fn parse_dynamic_entry(entry: &Elf64Dyn, info: &mut DynamicInfo) {
    match entry.d_tag {
        dyn_tag::DT_RELA => info.rela_addr = Some(entry.d_val),
        dyn_tag::DT_RELASZ => info.rela_size = entry.d_val as usize,
        dyn_tag::DT_RELAENT => info.rela_ent = entry.d_val as usize,
        dyn_tag::DT_REL => info.rel_addr = Some(entry.d_val),
        dyn_tag::DT_RELSZ => info.rel_size = entry.d_val as usize,
        dyn_tag::DT_RELENT => info.rel_ent = entry.d_val as usize,
        dyn_tag::DT_JMPREL => info.jmprel_addr = Some(entry.d_val),
        dyn_tag::DT_PLTRELSZ => info.jmprel_size = entry.d_val as usize,
        dyn_tag::DT_PLTREL => info.pltrel_type = entry.d_val as i64,
        dyn_tag::DT_SYMTAB => info.symtab_addr = Some(entry.d_val),
        dyn_tag::DT_SYMENT => info.syment = entry.d_val as usize,
        dyn_tag::DT_STRTAB => info.strtab_addr = Some(entry.d_val),
        dyn_tag::DT_STRSZ => info.strsz = entry.d_val as usize,
        dyn_tag::DT_HASH => info.hash_addr = Some(entry.d_val),
        dyn_tag::DT_GNU_HASH => info.gnu_hash_addr = Some(entry.d_val),
        dyn_tag::DT_INIT => info.init_addr = Some(entry.d_val),
        dyn_tag::DT_FINI => info.fini_addr = Some(entry.d_val),
        dyn_tag::DT_INIT_ARRAY => info.init_array_addr = Some(entry.d_val),
        dyn_tag::DT_INIT_ARRAYSZ => info.init_array_size = entry.d_val as usize,
        dyn_tag::DT_FINI_ARRAY => info.fini_array_addr = Some(entry.d_val),
        dyn_tag::DT_FINI_ARRAYSZ => info.fini_array_size = entry.d_val as usize,
        dyn_tag::DT_PLTGOT => info.pltgot_addr = Some(entry.d_val),
        dyn_tag::DT_FLAGS_1 => info.flags_1 = entry.d_val,
        _ => {}
    }
}

pub unsafe fn parse_dynamic_at_address(
    base_addr: u64,
    dyn_vaddr: u64,
    dyn_size: usize,
) -> LoaderResult<DynamicInfo> {
    let entry_size = core::mem::size_of::<Elf64Dyn>();

    if dyn_size < entry_size {
        return Err(LoaderError::InvalidDynamic);
    }

    let dyn_ptr = (base_addr + dyn_vaddr) as *const Elf64Dyn;
    let entry_count = dyn_size / entry_size;
    let mut info = DynamicInfo::default();

    for i in 0..entry_count {
        let dyn_entry = &*dyn_ptr.add(i);

        if dyn_entry.d_tag == dyn_tag::DT_NULL {
            break;
        }

        parse_dynamic_entry(dyn_entry, &mut info);
    }

    adjust_dynamic_addresses(&mut info, base_addr);

    Ok(info)
}

fn adjust_dynamic_addresses(info: &mut DynamicInfo, base: u64) {
    if let Some(addr) = info.rela_addr {
        info.rela_addr = Some(addr + base);
    }
    if let Some(addr) = info.rel_addr {
        info.rel_addr = Some(addr + base);
    }
    if let Some(addr) = info.jmprel_addr {
        info.jmprel_addr = Some(addr + base);
    }
    if let Some(addr) = info.symtab_addr {
        info.symtab_addr = Some(addr + base);
    }
    if let Some(addr) = info.strtab_addr {
        info.strtab_addr = Some(addr + base);
    }
    if let Some(addr) = info.hash_addr {
        info.hash_addr = Some(addr + base);
    }
    if let Some(addr) = info.gnu_hash_addr {
        info.gnu_hash_addr = Some(addr + base);
    }
    if let Some(addr) = info.init_addr {
        info.init_addr = Some(addr + base);
    }
    if let Some(addr) = info.fini_addr {
        info.fini_addr = Some(addr + base);
    }
    if let Some(addr) = info.init_array_addr {
        info.init_array_addr = Some(addr + base);
    }
    if let Some(addr) = info.fini_array_addr {
        info.fini_array_addr = Some(addr + base);
    }
    if let Some(addr) = info.pltgot_addr {
        info.pltgot_addr = Some(addr + base);
    }
}
