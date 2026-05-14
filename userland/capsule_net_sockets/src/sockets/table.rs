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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use super::types::{Family, Kind, LocalAddr4, RemoteAddr4, SocketKey};

pub const TABLE_CAP: usize = 256;

#[derive(Clone, Copy, Debug)]
pub struct Socket {
    pub key: SocketKey,
    pub family: Family,
    pub kind: Kind,
    pub local: Option<LocalAddr4>,
    pub remote: Option<RemoteAddr4>,
    pub bound: bool,
    pub listening: bool,
}

pub struct Table {
    inner: Mutex<[Option<Socket>; TABLE_CAP]>,
    next_handle: AtomicU32,
}

impl Table {
    pub const fn new() -> Self {
        Self { inner: Mutex::new([None; TABLE_CAP]), next_handle: AtomicU32::new(1) }
    }

    pub fn open(&self, pid: u32, family: Family, kind: Kind) -> Option<SocketKey> {
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let key = SocketKey { pid, handle };
        let mut g = self.inner.lock();
        for slot in g.iter_mut() {
            if slot.is_none() {
                *slot = Some(Socket {
                    key,
                    family,
                    kind,
                    local: None,
                    remote: None,
                    bound: false,
                    listening: false,
                });
                return Some(key);
            }
        }
        None
    }

    pub fn close(&self, key: SocketKey) -> bool {
        let mut g = self.inner.lock();
        for slot in g.iter_mut() {
            if slot.as_ref().map(|s| s.key.handle == key.handle && s.key.pid == key.pid)
                == Some(true)
            {
                *slot = None;
                return true;
            }
        }
        false
    }

    pub fn close_all_for_pid(&self, pid: u32) -> usize {
        let mut g = self.inner.lock();
        let mut n = 0;
        for slot in g.iter_mut() {
            if slot.as_ref().map(|s| s.key.pid == pid).unwrap_or(false) {
                *slot = None;
                n += 1;
            }
        }
        n
    }

    pub fn with<F, R>(&self, key: SocketKey, f: F) -> Option<R>
    where
        F: FnOnce(&mut Socket) -> R,
    {
        let mut g = self.inner.lock();
        for slot in g.iter_mut() {
            if let Some(s) = slot {
                if s.key.handle == key.handle && s.key.pid == key.pid {
                    return Some(f(s));
                }
            }
        }
        None
    }
}

pub static SOCKETS: Table = Table::new();
