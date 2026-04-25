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

use super::types::NamespaceType;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

static NEXT_NS_FD: AtomicI32 = AtomicI32::new(500);
static NS_FD_MAP: Mutex<BTreeMap<i32, (u64, NamespaceType)>> = Mutex::new(BTreeMap::new());

pub fn open_namespace_fd(ns_id: u64, ns_type: NamespaceType) -> i32 {
    let fd = NEXT_NS_FD.fetch_add(1, Ordering::SeqCst);
    NS_FD_MAP.lock().insert(fd, (ns_id, ns_type));
    fd
}

pub fn lookup_namespace_fd(fd: i32) -> Option<(u64, NamespaceType)> {
    NS_FD_MAP.lock().get(&fd).copied()
}

pub fn close_namespace_fd(fd: i32) -> Result<(), i32> {
    NS_FD_MAP.lock().remove(&fd).map(|_| ()).ok_or(9)
}

pub fn is_namespace_fd(fd: i32) -> bool {
    NS_FD_MAP.lock().contains_key(&fd)
}

pub fn get_all_namespace_fds() -> alloc::vec::Vec<(i32, u64, NamespaceType)> {
    NS_FD_MAP.lock().iter().map(|(&fd, &(ns_id, ns_type))| (fd, ns_id, ns_type)).collect()
}

pub fn namespace_fd_count() -> usize {
    NS_FD_MAP.lock().len()
}

pub fn get_namespace_type_for_fd(fd: i32) -> Option<NamespaceType> {
    NS_FD_MAP.lock().get(&fd).map(|(_, ns_type)| *ns_type)
}

pub fn get_namespace_id_for_fd(fd: i32) -> Option<u64> {
    NS_FD_MAP.lock().get(&fd).map(|(ns_id, _)| *ns_id)
}
