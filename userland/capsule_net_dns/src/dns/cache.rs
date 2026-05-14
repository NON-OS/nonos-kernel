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

//! Small fixed-capacity DNS cache. Indexed by FNV-1a hash of the
//! lowercased query name; collisions evict the older entry. The
//! capsule walks the table once per tick to drop expired records,
//! so the structure stays unsynchronised on the lookup path.

use core::sync::atomic::{AtomicU32, Ordering};

pub const ENTRY_CAP: usize = 128;
pub const NAME_BYTES: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct CacheEntry {
    pub name_hash: u64,
    pub name: [u8; NAME_BYTES],
    pub name_len: u8,
    pub ipv4: [u8; 4],
    pub expires_ms: u64,
}

pub struct Cache {
    entries: [Option<CacheEntry>; ENTRY_CAP],
    epoch: AtomicU32,
}

impl Cache {
    pub const fn new() -> Self {
        Self { entries: [None; ENTRY_CAP], epoch: AtomicU32::new(0) }
    }

    pub fn lookup(&self, name: &str, now_ms: u64) -> Option<[u8; 4]> {
        let h = hash(name);
        for slot in self.entries.iter() {
            if let Some(e) = slot {
                if e.name_hash == h && now_ms < e.expires_ms {
                    return Some(e.ipv4);
                }
            }
        }
        None
    }

    pub fn insert(&mut self, name: &str, ipv4: [u8; 4], ttl_ms: u64, now_ms: u64) {
        let h = hash(name);
        let bytes = name.as_bytes();
        let name_len = bytes.len().min(NAME_BYTES);
        let mut name_buf = [0u8; NAME_BYTES];
        name_buf[..name_len].copy_from_slice(&bytes[..name_len]);
        let entry = CacheEntry {
            name_hash: h,
            name: name_buf,
            name_len: name_len as u8,
            ipv4,
            expires_ms: now_ms.saturating_add(ttl_ms),
        };
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| e.as_ref().map(|x| x.name_hash == h).unwrap_or(false))
        {
            *slot = Some(entry);
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some(entry);
            return;
        }
        let idx = (self.epoch.fetch_add(1, Ordering::Relaxed) as usize) % ENTRY_CAP;
        self.entries[idx] = Some(entry);
    }

    pub fn tick(&mut self, now_ms: u64) {
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if now_ms >= e.expires_ms {
                    *slot = None;
                }
            }
        }
    }
}

// FNV-1a 64-bit. Case-insensitive on ASCII.
pub fn hash(name: &str) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in name.bytes() {
        let c = if (b'A'..=b'Z').contains(&b) { b + 32 } else { b };
        h ^= c as u64;
        h = h.wrapping_mul(0x100_0000_01B3);
    }
    h
}
