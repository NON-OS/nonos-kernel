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

use super::types::BpfMapType;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

pub static NEXT_MAP_FD: AtomicI32 = AtomicI32::new(200);
pub static MAPS: Mutex<BTreeMap<i32, BpfMap>> = Mutex::new(BTreeMap::new());

pub struct BpfMap {
    pub fd: i32,
    pub map_type: BpfMapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl BpfMap {
    pub fn create(
        map_type: BpfMapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Result<i32, i32> {
        if key_size == 0 || key_size > 4096 || value_size > 65536 || max_entries == 0 {
            return Err(22);
        }
        let fd = NEXT_MAP_FD.fetch_add(1, Ordering::SeqCst);
        let map = BpfMap { fd, map_type, key_size, value_size, max_entries, data: BTreeMap::new() };
        MAPS.lock().insert(fd, map);
        Ok(fd)
    }

    pub fn lookup(fd: i32, key: &[u8]) -> Result<Vec<u8>, i32> {
        let maps = MAPS.lock();
        let map = maps.get(&fd).ok_or(9)?;
        map.data.get(key).cloned().ok_or(2)
    }

    pub fn update(fd: i32, key: &[u8], value: &[u8], _flags: u64) -> Result<(), i32> {
        let mut maps = MAPS.lock();
        let map = maps.get_mut(&fd).ok_or(9)?;
        if key.len() != map.key_size as usize || value.len() != map.value_size as usize {
            return Err(22);
        }
        if map.data.len() >= map.max_entries as usize && !map.data.contains_key(key) {
            return Err(28);
        }
        map.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    pub fn delete(fd: i32, key: &[u8]) -> Result<(), i32> {
        let mut maps = MAPS.lock();
        let map = maps.get_mut(&fd).ok_or(9)?;
        map.data.remove(key).map(|_| ()).ok_or(2)
    }

    pub fn get_next_key(fd: i32, key: Option<&[u8]>) -> Result<Vec<u8>, i32> {
        let maps = MAPS.lock();
        let map = maps.get(&fd).ok_or(9)?;
        match key {
            None => map.data.keys().next().cloned().ok_or(2),
            Some(k) => {
                let mut iter = map.data.keys();
                while let Some(current) = iter.next() {
                    if current.as_slice() == k {
                        return iter.next().cloned().ok_or(2);
                    }
                }
                Err(2)
            }
        }
    }

    pub fn close(fd: i32) -> Result<(), i32> {
        MAPS.lock().remove(&fd).map(|_| ()).ok_or(9)
    }
}
