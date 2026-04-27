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
use spin::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfFdType {
    Program,
    Map,
    Link,
    BtfObj,
}

static BPF_FD_TYPES: Mutex<BTreeMap<i32, BpfFdType>> = Mutex::new(BTreeMap::new());

pub fn register_fd(fd: i32, fd_type: BpfFdType) {
    BPF_FD_TYPES.lock().insert(fd, fd_type);
}

pub fn get_fd_type(fd: i32) -> Option<BpfFdType> {
    BPF_FD_TYPES.lock().get(&fd).copied()
}

pub fn is_bpf_fd(fd: i32) -> bool {
    BPF_FD_TYPES.lock().contains_key(&fd)
}

pub fn is_program_fd(fd: i32) -> bool {
    BPF_FD_TYPES.lock().get(&fd) == Some(&BpfFdType::Program)
}

pub fn is_map_fd(fd: i32) -> bool {
    BPF_FD_TYPES.lock().get(&fd) == Some(&BpfFdType::Map)
}

pub fn unregister_fd(fd: i32) {
    BPF_FD_TYPES.lock().remove(&fd);
}

pub fn get_all_program_fds() -> alloc::vec::Vec<i32> {
    BPF_FD_TYPES
        .lock()
        .iter()
        .filter(|(_, &t)| t == BpfFdType::Program)
        .map(|(&fd, _)| fd)
        .collect()
}

pub fn get_all_map_fds() -> alloc::vec::Vec<i32> {
    BPF_FD_TYPES.lock().iter().filter(|(_, &t)| t == BpfFdType::Map).map(|(&fd, _)| fd).collect()
}

pub fn bpf_fd_count() -> usize {
    BPF_FD_TYPES.lock().len()
}

pub fn close_bpf_fd(fd: i32) -> Result<(), i32> {
    let fd_type = BPF_FD_TYPES.lock().remove(&fd).ok_or(9)?;
    match fd_type {
        BpfFdType::Program => super::program::BpfProgram::close(fd),
        BpfFdType::Map => super::map::BpfMap::close(fd),
        _ => Ok(()),
    }
}
