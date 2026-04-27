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

use super::socket::UnixSocket;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;

static BOUND_SOCKETS: Mutex<BTreeMap<String, Arc<UnixSocket>>> = Mutex::new(BTreeMap::new());
static ABSTRACT_SOCKETS: Mutex<BTreeMap<String, Arc<UnixSocket>>> = Mutex::new(BTreeMap::new());

pub struct UnixListener {
    pub socket: Arc<UnixSocket>,
    pub backlog: usize,
}

impl UnixListener {
    pub fn new(socket: Arc<UnixSocket>, backlog: usize) -> Self {
        socket.listening.store(true, core::sync::atomic::Ordering::SeqCst);
        Self { socket, backlog }
    }

    pub fn accept(&self) -> Result<Arc<UnixSocket>, i32> {
        self.socket.backlog.lock().pop_front().ok_or(-11)
    }
}

static SOCKET_PTRS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

pub fn register_bound_socket(path: &str, ptr: u64) -> Result<(), i32> {
    if is_path_bound(path) {
        return Err(-98);
    }
    SOCKET_PTRS.lock().insert(String::from(path), ptr);
    Ok(())
}

pub fn get_socket_ptr(path: &str) -> Option<u64> {
    SOCKET_PTRS.lock().get(path).copied()
}

pub fn bind_unix(socket: &Arc<UnixSocket>, path: &str) -> Result<(), i32> {
    let mut sockets =
        if path.starts_with('\0') { ABSTRACT_SOCKETS.lock() } else { BOUND_SOCKETS.lock() };
    if sockets.contains_key(path) {
        return Err(-98);
    }
    sockets.insert(String::from(path), socket.clone());
    *socket.bound_path.lock() = Some(String::from(path));
    Ok(())
}

pub fn listen_unix(socket: &Arc<UnixSocket>, backlog: i32) -> Result<(), i32> {
    if socket.bound_path.lock().is_none() {
        return Err(-22);
    }
    socket.listening.store(true, core::sync::atomic::Ordering::SeqCst);
    let max_backlog = if backlog <= 0 { 128 } else { backlog.min(4096) as usize };
    socket.set_backlog_limit(max_backlog);
    Ok(())
}

pub fn lookup_bound_socket(path: &str) -> Result<Arc<UnixSocket>, i32> {
    let sockets =
        if path.starts_with('\0') { ABSTRACT_SOCKETS.lock() } else { BOUND_SOCKETS.lock() };
    sockets.get(path).cloned().ok_or(-2)
}

pub fn unregister_bound_socket(path: &str) {
    if path.starts_with('\0') {
        ABSTRACT_SOCKETS.lock().remove(path);
    } else {
        BOUND_SOCKETS.lock().remove(path);
    }
}

pub fn is_path_bound(path: &str) -> bool {
    let sockets =
        if path.starts_with('\0') { ABSTRACT_SOCKETS.lock() } else { BOUND_SOCKETS.lock() };
    sockets.contains_key(path)
}
