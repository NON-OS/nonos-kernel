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

use super::commands::{BpfMapCreate, BpfMapElem, BpfProgLoad};
use super::map::BpfMap;
use super::program::BpfProgram;
use super::types::{BpfCmd, BpfMapType, BpfProgType};
use crate::syscall::dispatch::util::errno;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user, read_user_value};
use alloc::vec;

pub fn handle_bpf(cmd: u32, attr_ptr: u64, size: u32) -> SyscallResult {
    let bpf_cmd = match BpfCmd::from_u32(cmd) {
        Some(c) => c,
        None => return errno(22),
    };
    if attr_ptr == 0 || size == 0 {
        return errno(22);
    }
    match bpf_cmd {
        BpfCmd::MapCreate => handle_map_create(attr_ptr),
        BpfCmd::MapLookupElem => handle_map_lookup(attr_ptr),
        BpfCmd::MapUpdateElem => handle_map_update(attr_ptr),
        BpfCmd::MapDeleteElem => handle_map_delete(attr_ptr),
        BpfCmd::MapGetNextKey => handle_map_get_next_key(attr_ptr),
        BpfCmd::ProgLoad => handle_prog_load(attr_ptr),
        BpfCmd::ProgAttach => handle_prog_attach(attr_ptr),
        BpfCmd::ProgDetach => handle_prog_detach(attr_ptr),
        _ => errno(22),
    }
}

fn handle_map_create(attr_ptr: u64) -> SyscallResult {
    let attr: BpfMapCreate = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let map_type = BpfMapType::from_u32(attr.map_type).unwrap_or(BpfMapType::Unspec);
    match BpfMap::create(map_type, attr.key_size, attr.value_size, attr.max_entries) {
        Ok(fd) => {
            SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true }
        }
        Err(e) => errno(e),
    }
}

fn handle_map_lookup(attr_ptr: u64) -> SyscallResult {
    let attr: BpfMapElem = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let maps = super::map::MAPS.lock();
    let map = match maps.get(&(attr.map_fd as i32)) {
        Some(m) => m,
        None => return errno(9),
    };
    let mut key = vec![0u8; map.key_size as usize];
    if copy_from_user(attr.key, &mut key).is_err() {
        return errno(14);
    }
    drop(maps);
    match BpfMap::lookup(attr.map_fd as i32, &key) {
        Ok(value) => {
            if copy_to_user(attr.value_or_next_key, &value).is_err() {
                return errno(14);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        Err(e) => errno(e),
    }
}

fn handle_map_update(attr_ptr: u64) -> SyscallResult {
    let attr: BpfMapElem = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let maps = super::map::MAPS.lock();
    let map = match maps.get(&(attr.map_fd as i32)) {
        Some(m) => m,
        None => return errno(9),
    };
    let (ks, vs) = (map.key_size as usize, map.value_size as usize);
    drop(maps);
    let (mut key, mut value) = (vec![0u8; ks], vec![0u8; vs]);
    if copy_from_user(attr.key, &mut key).is_err() {
        return errno(14);
    }
    if copy_from_user(attr.value_or_next_key, &mut value).is_err() {
        return errno(14);
    }
    match BpfMap::update(attr.map_fd as i32, &key, &value, attr.flags) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => errno(e),
    }
}

fn handle_map_delete(attr_ptr: u64) -> SyscallResult {
    let attr: BpfMapElem = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let maps = super::map::MAPS.lock();
    let map = match maps.get(&(attr.map_fd as i32)) {
        Some(m) => m,
        None => return errno(9),
    };
    let mut key = vec![0u8; map.key_size as usize];
    drop(maps);
    if copy_from_user(attr.key, &mut key).is_err() {
        return errno(14);
    }
    match BpfMap::delete(attr.map_fd as i32, &key) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(e) => errno(e),
    }
}

fn handle_map_get_next_key(attr_ptr: u64) -> SyscallResult {
    let attr: BpfMapElem = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let maps = super::map::MAPS.lock();
    let map = match maps.get(&(attr.map_fd as i32)) {
        Some(m) => m,
        None => return errno(9),
    };
    let ks = map.key_size as usize;
    drop(maps);
    let key = if attr.key != 0 {
        let mut k = vec![0u8; ks];
        if copy_from_user(attr.key, &mut k).is_err() {
            return errno(14);
        }
        Some(k)
    } else {
        None
    };
    match BpfMap::get_next_key(attr.map_fd as i32, key.as_deref()) {
        Ok(next) => {
            if copy_to_user(attr.value_or_next_key, &next).is_err() {
                return errno(14);
            }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        Err(e) => errno(e),
    }
}

fn handle_prog_load(attr_ptr: u64) -> SyscallResult {
    let attr: BpfProgLoad = match read_user_value(attr_ptr) {
        Ok(a) => a,
        Err(_) => return errno(14),
    };
    let prog_type = BpfProgType::from_u32(attr.prog_type).unwrap_or(BpfProgType::Unspec);
    let mut insns = vec![0u64; attr.insn_cnt as usize];
    if copy_from_user(attr.insns, unsafe {
        core::slice::from_raw_parts_mut(insns.as_mut_ptr() as *mut u8, insns.len() * 8)
    })
    .is_err()
    {
        return errno(14);
    }
    match BpfProgram::load(prog_type, insns, attr.prog_name) {
        Ok(fd) => {
            SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true }
        }
        Err(e) => errno(e),
    }
}

fn handle_prog_attach(_attr_ptr: u64) -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
fn handle_prog_detach(_attr_ptr: u64) -> SyscallResult {
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
